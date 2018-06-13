from binaryninja import Symbol, Type, log, demangle
from binaryninja.enums import SymbolType
from utils import BinjaStruct, read_cstring, check_offset


def check_rtti_signature(view, magic):
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
    raise NotImplementedError()


def get_vtable_name(view, name):
    if name[:3] in [ '?AU', '?AV' ]:
        # demangle_ms doesn't support flags (UNDNAME_32_BIT_DECODE | UNDNAME_NAME_ONLY | UNDNAME_NO_ARGUMENTS | UNDNAME_NO_MS_KEYWORDS)
        demangle_type, demangle_name = demangle.demangle_ms(view.arch, '??_7{0}6B@'.format(name[3:]))

        if demangle_type is not None:
            return '::'.join(demangle_name)

    return 'vtable_{0}'.format(name)


def create_vtable(view, vtable_name, vtable_address, max_funcs = 64):
    pointer_t = BinjaStruct.Pointer(view)

    funcs = list()

    for i in range(max_funcs):
        func_pointer_address = vtable_address + (i * view.address_size)
        func_address, _ = pointer_t.read(view, func_pointer_address)

        if func_address is None:
            break

        if not view.is_offset_executable(func_address):
            break

        func = view.get_function_at(func_pointer_address)

        if func is None:
            if i and view.get_code_refs(func_pointer_address, view.address_size):
                break

        funcs.append(func_address)

    if funcs:
        view.define_user_symbol(Symbol(SymbolType.DataSymbol, vtable_address, vtable_name))
        view.define_user_data_var(vtable_address, Type.array(Type.pointer(view.arch, Type.void(), const = True), len(funcs)))

    return funcs


RTTICompleteObjectLocator32_t = BinjaStruct('<IIIII', names = ('signature', 'offset', 'cdOffset', 'pTypeDescriptor', 'pClassDescriptor'))
RTTICompleteObjectLocator64_t = BinjaStruct('<IIIIII', names = ('signature', 'offset', 'cdOffset', 'pTypeDescriptor', 'pClassDescriptor', 'pSelf'))

def read_object_locator(view, address):
    if view.address_size == 4:
        RTTICompleteObjectLocator_t = RTTICompleteObjectLocator32_t
    elif view.address_size == 8:
        RTTICompleteObjectLocator_t = RTTICompleteObjectLocator64_t
    else:
        raise NotImplementedError()

    object_locator, _ = RTTICompleteObjectLocator_t.read(view, address)

    if object_locator is None:
        return None

    if not check_rtti_signature(view, object_locator['signature']):
        return None

    cd_address = get_rtti_address(view, object_locator['cdOffset'])

    if not check_offset(view, cd_address):
        return None

    type_address = get_rtti_address(view, object_locator['pTypeDescriptor'])

    if not check_offset(view, type_address):
        return None

    class_address = get_rtti_address(view, object_locator['pClassDescriptor'])

    if not check_offset(view, class_address):
        return None

    if 'pSelf' in object_locator:
        self_address = get_rtti_address(view, object_locator['pSelf'])

        if self_address != address:
            return None

    return cd_address, type_address, class_address


RTTITypeDescriptor32_t = BinjaStruct('<II', names = ('vTable', 'UndecoratedName'))
RTTITypeDescriptor64_t = BinjaStruct('<QQ', names = ('vTable', 'UndecoratedName'))

def read_type_descriptor(view, address):
    if view.address_size == 4:
        RTTITypeDescriptor_t = RTTITypeDescriptor32_t
    elif view.address_size == 8:
        RTTITypeDescriptor_t = RTTITypeDescriptor64_t
    else:
        raise NotImplementedError()

    type_descriptor, decorated_name_address = RTTITypeDescriptor_t.read(view, address)

    if not check_offset(view, type_descriptor['vTable']):
        return None

    if type_descriptor is None:
        return None

    decorated_name, _ = read_cstring(view, decorated_name_address)

    if not decorated_name.startswith('.?'):
        return None

    return decorated_name,


def scan_for_rtti(thread, view, start, end):
    pointer_t = BinjaStruct.Pointer(view)

    funcs = set()

    for i in range(start, end, view.address_size):
        if thread.cancelled:
            break

        locator_address, _ = pointer_t.read(view, i)

        if locator_address is None:
            continue

        if not check_offset(view, locator_address):
            continue

        object_locator = read_object_locator(view, locator_address)

        if object_locator is None:
            continue

        cd_address, type_address, class_address = object_locator

        type_descriptor = read_type_descriptor(view, type_address)

        if type_descriptor is None:
            continue

        decorated_name, = type_descriptor

        vtable_address = i + view.address_size
        vtable_name = get_vtable_name(view, decorated_name[1:])

        thread.progress = 'Found {0} @ 0x{1:X}'.format(vtable_name, vtable_address)

        funcs |= set(create_vtable(view, vtable_name, vtable_address))


    log.log_info('Found {0} Functions'.format(len(funcs)))
    thread.progress = 'Creating {0} Functions'.format(len(funcs))

    if not thread.cancelled:
        for func in funcs:
            view.create_user_function(func)
