from binaryninja import *


class RunInBackground(BackgroundTaskThread):
    def __init__(self, msg, func, *args, **kwargs):
            BackgroundTaskThread.__init__(self, msg, True)
            self.func = func
            self.args = args
            self.kwargs = kwargs

    def run(self):
        self.func(self, *self.args, **self.kwargs)


def check_rtti_magic(view, magic):
    if view.address_size == 4:
        return magic == 0
    if view.address_size == 8:
        return magic == 1
    return False

def get_rtti_address(view, offset):
    if view.address_size == 4:
        return offset
    if view.address_size == 8:
        return view.start + offset
    return None

def read_pointer(view, reader):
    if view.address_size == 4:
        return reader.read32le()
    if view.address_size == 8:
        return reader.read64le()
    return None

def read_rtti_pointer(view, reader):
    offset = reader.read32le()
    if view.address_size == 8:
        offset = view.start + offset
    return offset

def check_offset(view, offset):
    return view.start <= offset < view.end

def read_cstring(reader):
    buf = bytearray()
    while True:
        b = reader.read8()
        if b is None or b == 0:
            return str(buf)
        else:
            buf.append(b)

class RTTICompleteObjectLocator:
    def read(self, view, reader, offset):
        reader.seek(offset)
        magic = reader.read32le()
        if not check_rtti_magic(view, magic):
            return False
        unk0 = read_rtti_pointer(view, reader)
        cd_offset = read_rtti_pointer(view, reader)
        type_desc_offset = read_rtti_pointer(view, reader)
        class_desc_offset = read_rtti_pointer(view, reader)
        if not check_offset(view, type_desc_offset):
            log.log_error('Bad Type Descriptor @ 0x{0:X}'.format(type_desc_offset))
            return False
        if not check_offset(view, class_desc_offset):
            log.log_error('Bad Class Descriptor @ 0x{0:X}'.format(class_desc_offset))
            return False
        self.type_descriptor = RTTITypeDescriptor()
        if not self.type_descriptor.read(view, reader, type_desc_offset):
            return False
        return True

class RTTITypeDescriptor:
    def read(self, view, reader, offset):
        reader.seek(offset)
        self.vtable_addr = read_pointer(view, reader)
        if not check_offset(view, self.vtable_addr):
            return False
        read_pointer(view, reader)
        self.decorated_name = read_cstring(reader)
        if not self.decorated_name.startswith('.?'):
            return False
        # Currently binja doesn't demangle the vtable name
        self.name = self.decorated_name[1:]
        return True

class RTTIClassHierarchyDescriptor:
    def __init__(self):
        pass

class RTTIBaseClassArray:
    def __init__(self):
        pass

class RTTIBaseClassDescriptor:
    def __init__(self):
        pass

class PMD:
    def __init__(self):
        pass


def scan_for_rtti(thread, view, start, end):
    reader = BinaryReader(view)
    void_ptr_type, _ = view.parse_type_string("void*")
    for i in range(start, end, view.address_size):
        reader.seek(i)
        pCompleteObject = read_pointer(view, reader)
        if start < pCompleteObject < end:
            rtti = RTTICompleteObjectLocator()
            if rtti.read(view, reader, pCompleteObject):
                vtable_addr = i + view.address_size

                thread.progress = 'Found vftable @ 0x{0:X}'.format(vtable_addr)
                log.log_info('0x{0:x} @ {1}'.format(vtable_addr, rtti.type_descriptor.name))

                view.define_user_symbol(Symbol(SymbolType.DataSymbol, vtable_addr, 'vtable_' + rtti.type_descriptor.name))

                for j in range(32):
                    func_ptr_addr = vtable_addr + (j * view.address_size)
                    reader.seek(func_ptr_addr)
                    func_addr = read_pointer(view, reader)

                    if not view.is_offset_executable(func_addr):
                        break

                    if view.get_function_at(func_ptr_addr) is None:
                        if j and view.get_code_refs(func_ptr_addr, view.address_size):
                            break

                    view.define_user_data_var(func_ptr_addr, void_ptr_type)
                    view.create_user_function(func_addr)


def scan_for_rtti_command(view):
    if '.rdata' in view.sections:
        rdata = view.sections['.rdata']
        task = RunInBackground('Scanning for RTTI', scan_for_rtti, view, rdata.start, rdata.end)
        task.start()
    else:
        log.log_error('Could not find .rdata section')


PluginCommand.register(
    'Scan for RTTI',
    'Scans for MSVC RTTI',
    lambda view: scan_for_rtti_command(view),
    lambda view: view.arch.name in [ 'x86', 'x86_64' ]
)
