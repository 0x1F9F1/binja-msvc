from binaryninja import log, demangle
from utils import read_pointer, read_cstring


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


def read_rtti_pointer(view, reader):
    offset = reader.read32le()
    if view.address_size == 8:
        offset = view.start + offset
    return offset


def check_offset(view, offset):
    return view.start <= offset < view.end


def get_vtable_name(view, name):
    if name[:3] in [ '?AU', '?AV' ]:
        demangle_type, demangle_name = demangle.demangle_ms(view.arch, '??_7{0}6B@'.format(name[3:]))

        if demangle_type is not None:
            return '::'.join(demangle_name)

    return 'vtable_{0}'.format(name)


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
        self.name = get_vtable_name(view, self.decorated_name[1:])
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
