from binaryninja import Symbol, Type, log, demangle
from binaryninja.enums import SymbolType
from .utils import BinjaStruct, read_cstring, check_address, update_percentage


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


def fix_rtti_offset(view, container, name):
    container[name] = get_rtti_address(view, container[name])


def get_vtable_name(view, name):
    try:
        if name[:3] in [ b'?AU', b'?AV' ]:
            # demangle_ms doesn't support flags (UNDNAME_32_BIT_DECODE | UNDNAME_NAME_ONLY | UNDNAME_NO_ARGUMENTS | UNDNAME_NO_MS_KEYWORDS)
            demangle_type, demangle_name = demangle.demangle_ms(view.arch, '??_7{0}6B@'.format(name[3:].decode('ascii')))

            if demangle_type is not None:
                return demangle.get_qualified_name(demangle_name)
    except:
        pass

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
            if i and len(list(view.get_code_refs(func_pointer_address, view.address_size))) > 0:
                break

        funcs.append(func_address)

    if funcs:
        if vtable_name is not None:
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

    object_locator, address = RTTICompleteObjectLocator_t.read(view, address)

    if object_locator is not None:
        fix_rtti_offset(view, object_locator, 'cdOffset')
        fix_rtti_offset(view, object_locator, 'pTypeDescriptor')
        fix_rtti_offset(view, object_locator, 'pClassDescriptor')

        if 'pSelf' in object_locator:
            fix_rtti_offset(view, object_locator, 'pSelf')

    return object_locator, address


RTTITypeDescriptor32_t = BinjaStruct('<II', names = ('vTable', 'UndecoratedName'))
RTTITypeDescriptor64_t = BinjaStruct('<QQ', names = ('vTable', 'UndecoratedName'))

def read_type_descriptor(view, address):
    if view.address_size == 4:
        RTTITypeDescriptor_t = RTTITypeDescriptor32_t
    elif view.address_size == 8:
        RTTITypeDescriptor_t = RTTITypeDescriptor64_t
    else:
        raise NotImplementedError()

    type_descriptor, address = RTTITypeDescriptor_t.read(view, address)

    if type_descriptor is not None:
        decorated_name, address = read_cstring(view, address)

        type_descriptor['DecoratedName'] = decorated_name

    return type_descriptor, address


def scan_for_rtti(thread, view, start, end):
    pointer_t = BinjaStruct.Pointer(view)

    count = 0
    funcs = set()

    for i in range(start, end, view.address_size):
        update_percentage(thread, start, end, i, 'Scanning for RTTI - Found {0} vtables'.format(count))

        if thread.cancelled:
            break

        locator_address, _ = pointer_t.read(view, i)

        if locator_address is None:
            continue

        if not check_address(view, locator_address):
            continue

        object_locator, _ = read_object_locator(view, locator_address)

        if object_locator is None:
            continue

        if not check_rtti_signature(view, object_locator['signature']):
            continue

        if 'pSelf' in object_locator:
            if object_locator['pSelf'] != locator_address:
                continue

        type_address = object_locator['pTypeDescriptor']

        if not check_address(view, type_address):
            continue

        type_descriptor, _ = read_type_descriptor(view, type_address)

        if type_descriptor is None:
            continue

        if not check_address(view, type_descriptor['vTable']):
            continue

        decorated_name = type_descriptor['DecoratedName']

        vtable_address = i + view.address_size

        if decorated_name.startswith(b'.?'):
            vtable_name = get_vtable_name(view, decorated_name[1:])
        else:
            vtable_name = 'vtable_{0:X}'.format(vtable_address)

        count += 1
        funcs |= set(create_vtable(view, vtable_name, vtable_address))

    if not thread.cancelled:
        thread.progress = 'Creating {0} Function'.format(len(funcs))
        log.log_info('Found {0} functions'.format(len(funcs)))

        for func in funcs:
            view.create_user_function(func)
