from binaryninja import log
from utils import BinjaStruct, read_pe_header, split_bits, update_percentage

# https://msdn.microsoft.com/en-us/library/ft9x1kdx.aspx

RUNTIME_FUNCTION_t = BinjaStruct('<III', names = ('BeginAddress', 'EndAddress', 'UnwindData'))

def read_runtime_function(view, address):
    runtime_function, address = RUNTIME_FUNCTION_t.read(view, address, 4)

    if runtime_function is not None:
        runtime_function['BeginAddress'] += view.start
        runtime_function['EndAddress'] += view.start
        runtime_function['UnwindData'] += view.start

    return runtime_function, address


UNWIND_INFO_t = BinjaStruct('<BBBB', names = ('VersionAndFlags', 'SizeOfProlog', 'CountOfCodes', 'FrameRegisterAndOffset'))

UNW_FLAG_NHANDLER = 0x0
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_FHANDLER = 0x3
UNW_FLAG_CHAININFO = 0x4

def read_unwind_info(view, address):
    unwind_info, address = UNWIND_INFO_t.read(view, address)

    if unwind_info is not None:
        split_bits(unwind_info, 'VersionAndFlags', [
            ('Version', 0, 3),
            ('Flags',   3, 5)
        ])

        split_bits(unwind_info, 'FrameRegisterAndOffset', [
            ('FrameRegister', 0, 4),
            ('FrameOffset',   4, 4)
        ])

        if unwind_info['Version'] == 1:
            unwind_codes = [ ]

            for i in range(unwind_info['CountOfCodes']):
                unwind_code, address = read_unwind_code(view, address)
                unwind_codes.append(unwind_code)

            unwind_info['UnwindCodes'] = unwind_codes

            if unwind_info['Flags'] & UNW_FLAG_CHAININFO:
                unwind_info['FunctionEntry'], address  = read_runtime_function(view, address)

    return unwind_info, address


UNWIND_CODE_t = BinjaStruct('<BB', names = ('CodeOffset', 'UnwindOpAndInfo'))

def read_unwind_code(view, address):
    unwind_code, address = UNWIND_CODE_t.read(view, address)

    if unwind_code is not None:
        split_bits(unwind_code, 'UnwindOpAndInfo', [
            ('UnwindOp', 0, 4),
            ('OpInfo',   4, 4)
        ])

    return unwind_code, address


def parse_unwind_info(thread, view):
    base_address = view.start

    pe = read_pe_header(view)

    unwind_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    unwind_entrys = base_address + unwind_directory.VirtualAddress
    unwind_entrys_end = unwind_entrys + unwind_directory.Size

    funcs = set()

    log.log_info('Exception Data @ 0x{0:X} => 0x{1:X}'.format(unwind_entrys, unwind_entrys_end))

    for runtime_address in range(unwind_entrys, unwind_entrys_end, 12):
        if thread.cancelled:
            break

        update_percentage(thread, unwind_entrys, unwind_entrys_end, runtime_address, 'Parsing Unwind Info - Found {0} functions'.format(len(funcs)))

        runtime_function, _ = read_runtime_function(view, runtime_address)

        if runtime_function is None:
            continue

        start_address = runtime_function['BeginAddress']

        if not view.is_offset_executable(start_address):
            continue
        if view.get_functions_containing(start_address):
            continue

        info_address = runtime_function['UnwindData']
        unwind_info, _ = read_unwind_info(view, info_address)

        if unwind_info is None:
            continue

        if 'FunctionEntry' in unwind_info:
            continue

        funcs.add(start_address)

    if not thread.cancelled:
        thread.progress = 'Creating {0} Function'.format(len(funcs))
        log.log_info('Found {0} functions'.format(len(funcs)))

        for func in funcs:
            view.create_user_function(func)
