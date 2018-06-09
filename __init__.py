from binaryninja import PluginCommand, BinaryReader, Symbol, SymbolType, log
from .pefile import *

from rtti import RTTICompleteObjectLocator
from utils import RunInBackground, read_pointer


def read_pe_header(view, reader):
    seg = view.get_segment_at(view.start)
    reader.seek(seg.start)
    return pefile.PE(data = reader.read(seg.length))


def scan_for_rtti(thread, view, start, end):
    reader = BinaryReader(view)
    void_ptr_type, _ = view.parse_type_string("void*")

    funcs = set()

    for i in range(start, end, view.address_size):
        if thread.cancelled:
            break
        reader.seek(i)
        pCompleteObject = read_pointer(view, reader)
        if start < pCompleteObject < end:
            rtti = RTTICompleteObjectLocator()
            if rtti.read(view, reader, pCompleteObject):
                vtable_addr = i + view.address_size
                vtable_name = rtti.type_descriptor.name

                thread.progress = 'Found {0} @ 0x{1:X}'.format(vtable_name, vtable_addr)

                view.define_user_symbol(Symbol(SymbolType.DataSymbol, vtable_addr, vtable_name))

                for j in range(64):
                    func_ptr_addr = vtable_addr + (j * view.address_size)
                    reader.seek(func_ptr_addr)
                    func_addr = read_pointer(view, reader)

                    if not view.is_offset_executable(func_addr):
                        break

                    if view.get_function_at(func_ptr_addr) is None:
                        if j and view.get_code_refs(func_ptr_addr, view.address_size):
                            break

                    view.define_user_data_var(func_ptr_addr, void_ptr_type)
                    funcs.add(func_addr)

    log.log_info('Found {0} Functions'.format(len(funcs)))
    thread.progress = 'Creating {0} Functions'.format(len(funcs))

    if not thread.cancelled:
        for func in funcs:
            view.create_user_function(func)


# https://msdn.microsoft.com/en-us/library/ft9x1kdx.aspx
def parse_unwind_info(thread, view):
    base_address = view.start
    reader = BinaryReader(view)

    pe = read_pe_header(view, reader)

    unwind_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    unwind_entrys = base_address + unwind_directory.VirtualAddress

    funcs = set()

    for addr in range(unwind_entrys, unwind_entrys + unwind_directory.Size, 12):
        if thread.cancelled:
            break
        reader.seek(addr)
        start_rva = reader.read32le()
        end_rva = reader.read32le()
        info_rva = reader.read32le()
        if (not start_rva) or (not end_rva) or (not info_rva):
            break
        start_addr = base_address + start_rva
        end_addr = base_address + end_rva
        if not view.is_offset_executable(start_addr):
            break
        thread.progress = 'Found unwind info @ 0x{0:X}'.format(start_addr)
        funcs.add(start_addr)

    log.log_info('Found {0} Functions'.format(len(funcs)))
    thread.progress = 'Creating {0} Functions'.format(len(funcs))

    if not thread.cancelled:
        for func in funcs:
            view.create_user_function(func)


def is_broken_thiscall(func):
    function_type = func.function_type
    if function_type.calling_convention == func.arch.calling_conventions['fastcall']:
        return True
    if function_type.calling_convention == func.arch.calling_conventions['stdcall']:
        params = function_type.parameters
        if params:
            this_ptr = params[0]
            if this_ptr.location is not None:
                if this_ptr.location.name == 'ecx':
                    return True
    return False


def fix_thiscalls(thread, view):
    for func in view.functions:
        if func.arch.name != 'x86':
            return
        if is_broken_thiscall(func):
            func.calling_convention = func.arch.calling_conventions['thiscall']
            thread.progress = 'Fixed {0}'.format(func.name)



def command_scan_for_rtti(view):
    if '.rdata' in view.sections:
        rdata = view.sections['.rdata']
        task = RunInBackground('Scanning for RTTI', scan_for_rtti, view, rdata.start, rdata.end)
        task.start()
    else:
        log.log_error('Could not find .rdata section')


def command_parse_unwind_info(view):
    rdata = view.sections['.rdata']
    task = RunInBackground('Parsing Unwind Info', parse_unwind_info, view)
    task.start()


def command_fix_thiscalls(view):
    task = RunInBackground('Fixing thiscall\'s', fix_thiscalls, view)
    task.start()


def check_view_platform(view, *platforms):
    platform = view.platform
    if platform is None:
        return False
    return platform.name in platforms


PluginCommand.register(
    'Scan for RTTI',
    'Scans for MSVC RTTI',
    lambda view: command_scan_for_rtti(view),
    lambda view: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)

PluginCommand.register(
    'Parse exception handlers',
    'Create functions based on exception handlers',
    lambda view: command_parse_unwind_info(view),
    lambda view: check_view_platform(view, 'windows-x86_64')
)

PluginCommand.register(
    'Fix thiscall\'s',
    'Convert appropriate stdcall\'s and fastcall\'s into thiscall\'s',
    lambda view: command_fix_thiscalls(view),
    lambda view: check_view_platform(view, 'windows-x86')
)
