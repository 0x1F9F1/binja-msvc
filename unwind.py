from binaryninja import log
from utils import BinjaStruct, read_pe_header

# https://msdn.microsoft.com/en-us/library/ft9x1kdx.aspx

RUNTIME_FUNCTION_t = BinjaStruct('<III', names = ('BeginAddress', 'EndAddress', 'UnwindData'))

def read_runtime_function(view, address):
    runtime_function, _ = RUNTIME_FUNCTION_t.read(view, address, 4)

    if runtime_function is None:
        return None

    start_address = view.start + runtime_function['BeginAddress']
    end_address   = view.start + runtime_function['EndAddress']
    info_address  = view.start + runtime_function['UnwindData']

    return start_address, end_address, info_address


UNWIND_INFO_t = BinjaStruct('<BBBB', names = ('VersionAndFlags', 'SizeOfProlog', 'CountOfCodes', 'FrameRegisterAndOffset'))
UNWIND_CODE_t = BinjaStruct('<BB', names = ('CodeOffset', 'UnwindOpAndInfo'))

def read_unwind_info(view, address):
    unwind_info, codes_address = UNWIND_INFO_t.read(view, address)

    if unwind_info is None:
        return None

    if (unwind_info['VersionAndFlags'] & 0x7) != 1:
        return None

    unwind_info['UnwindCodes'], extra_address = UNWIND_CODE_t.read_array(view, codes_address, unwind_info['CountOfCodes'], 2)

    if (unwind_info['VersionAndFlags'] >> 3) & 0x4: # UNW_FLAG_CHAININFO
        unwind_info['FunctionEntry']  = read_runtime_function(view, extra_address)

    return unwind_info


def parse_unwind_info(thread, view):
    base_address = view.start

    pe = read_pe_header(view)

    unwind_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    unwind_entrys = base_address + unwind_directory.VirtualAddress

    funcs = set()

    log.log_info('Exception Data @ 0x{0:X} => 0x{1:X}'.format(unwind_entrys, unwind_entrys + unwind_directory.Size))

    for runtime_address in range(unwind_entrys, unwind_entrys + unwind_directory.Size, 12):
        if thread.cancelled:
            break

        runtime_function = read_runtime_function(view, runtime_address)

        if runtime_function is None:
            continue

        start_address, end_address, info_address = runtime_function

        if not view.is_offset_executable(start_address):
            continue
        if view.get_functions_containing(start_address):
            continue
        # if view.get_functions_containing(end_address - 1):
        #     continue

        unwind_info = read_unwind_info(view, info_address)

        if unwind_info is None:
            continue

        if 'FunctionEntry' in unwind_info:
            continue

        funcs.add(start_address)

    if not thread.cancelled:
        thread.progress = 'Found {0} Function'.format(len(funcs))
        log.log_info('Found {0} functions'.format(len(funcs)))

        for func in funcs:
            view.create_user_function(func)
