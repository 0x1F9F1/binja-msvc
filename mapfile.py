import re

from binaryninja.types import Symbol, Type
from binaryninja.demangle import demangle_ms
from binaryninja.enums import SymbolType

from .fixes import fix_mangled_symbols

MAP_LINE_REGEX = re.compile(r'([0-9a-zA-Z?@_]+)\s+([0-9a-fA-F]{8,16})')
IDC_NAME_REGEX = re.compile(r'set_name\t\(0X([0-9A-F]+),\t"(.+)"\);')

def parse_map_file(lines):
    result = []

    for line in lines:
        find = MAP_LINE_REGEX.search(line)

        if find is None:
            continue

        name = find[1]

        try:
            int(name, 16)
            continue
        except:
            pass

        addr = int(find[2], 16)

        result.append((name, addr))

    return result

def parse_idc_file(lines):
    result = []

    for line in lines:
        find = IDC_NAME_REGEX.search(line)

        if find is None:
            continue

        addr = int(find[1], 16)
        name = find[2]

        result.append((name, addr))

    return result

def load_symbols(thread, view, symbols):
    arch = view.arch

    for name, addr in symbols:
        if not view.is_valid_offset(addr):
            continue

        current_sym = view.get_symbol_at(addr)

        if current_sym is not None:
            if not current_sym.auto:
                continue

            if current_sym.type not in [ SymbolType.DataSymbol, SymbolType.FunctionSymbol ]:
                continue

            view.undefine_user_symbol(current_sym)

        sym_type, sym_parts = demangle_ms(arch, name)

        if sym_type is None:
            sym_type = Type.void()

        if isinstance(sym_parts, str):
            sym_parts = [sym_parts]

        sym_name = '::'.join(sym_parts)

        if '`vftable\'' in sym_name:
            sym_type = Type.void()

        if view.is_offset_executable(addr):
            view.create_user_function(addr)
            view.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, sym_name, raw_name = name))
        else:
             view.define_data_var(addr, sym_type)
             view.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, sym_name, raw_name = name))

    fix_mangled_symbols(thread, view)

def load_map_file(thread, view, filename):
    lines = open(filename, 'r').readlines()
    load_symbols(thread, view, parse_map_file(lines))

def load_idc_file(thread, view, filename):
    lines = open(filename, 'r', errors='replace').readlines()
    load_symbols(thread, view, parse_idc_file(lines))
