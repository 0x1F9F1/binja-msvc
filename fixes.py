from binaryninja import log
from binaryninja.demangle import demangle_ms
from binaryninja.enums import TypeClass, NamedTypeReferenceClass
from binaryninja.types import Type, NamedTypeReference, Symbol

from .rtti import create_vtable

# from binaryninja.binaryview import *
# from binaryninja.architecture import *
# from binaryninja.demangle import *
# from binaryninja.enums import *

def get_proper_cc(func):
    function_type = func.function_type
    params = function_type.parameters
    cc_name = function_type.calling_convention.name
    if cc_name == 'fastcall':
        if (len(params) == 1) and ((params[0].location is None) or (params[0].location.name == 'ecx')):
            return 'thiscall'
    elif cc_name == 'stdcall':
        if (len(params) > 0) and (params[0].location is not None) and (params[0].location.name == 'ecx'):
            if (len(params) > 1) and (params[1].location is not None) and (params[1].location.name == 'edx'):
                return 'fastcall'
            return 'thiscall'

    return None

def fix_x86_conventions(thread, view):
    count = 0

    for func in view.functions:
        if thread.cancelled:
            break
        if func.arch.name != 'x86':
            return
        cc = get_proper_cc(func)
        if cc is not None:
            func.calling_convention = func.arch.calling_conventions[cc]
            thread.progress = 'Fixed {0}'.format(func.name)
            count += 1

    log.log_info('Fixed {0} functions\'s'.format(count))

def process_msvc_func(func):
    arch = func.arch
    plat = func.platform

    sym_type, sym_parts = demangle_ms(arch, func.symbol.raw_name)

    if (sym_type is None) or (sym_type.type_class != TypeClass.FunctionTypeClass):
        return

    if isinstance(sym_parts, str):
        return

    params = [v.type for v in sym_type.parameters if v.type.type_class != TypeClass.VoidTypeClass]
    return_type = sym_type.return_value

    tokens_before = [str(v) for v in sym_type.get_tokens_before_name()]

    is_member = ('public:' in tokens_before) or ('protected:' in tokens_before) or ('private:' in tokens_before)
    is_static = 'static' in tokens_before

    convention = plat.default_calling_convention

    if '__cdecl' in tokens_before:
        convention = plat.cdecl_calling_convention
    elif '__stdcall' in tokens_before:
        convention = plat.stdcall_calling_convention
    elif '__fastcall' in tokens_before:
        convention = plat.fastcall_calling_convention
    elif '__thiscall' in tokens_before:
        convention = arch.calling_conventions['thiscall']

    if len(sym_parts) >= 2 and is_member and not is_static:
        if 'static' not in tokens_before:
            type_name = '::'.join(sym_parts[:-1])
            this_type = Type.pointer(arch, Type.named_type(NamedTypeReference(NamedTypeReferenceClass.StructNamedTypeClass, name = type_name)))
            params.insert(0, this_type)

    func.function_type = Type.function(return_type, params, convention, sym_type.has_variable_arguments)

def fix_mangled_symbols(thread, view):
    for func in view.functions:
        if thread.cancelled:
            break
        process_msvc_func(func)

    for sym in view.symbols.values():
        if thread.cancelled:
            break
        if not isinstance(sym, Symbol):
            continue

        # Create vtables
        if '`vftable\'' in sym.full_name:
            create_vtable(view, None, sym.address)

        # Create strings
        if sym.raw_name.startswith('??_C@_'):
            view.undefine_user_symbol(sym)
            ascii_string = view.get_ascii_string_at(sym.address)

            if (ascii_string is not None) and (ascii_string.start == sym.address):
                view.define_user_data_var(sym.address, Type.array(Type.char(), ascii_string.length))
