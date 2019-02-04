from binaryninja import PluginCommand, log
from utils import RunInBackground
from rtti import scan_for_rtti, create_vtable
from unwind import parse_unwind_info
from fixes import fix_x86_conventions
from tls import label_tls


def command_scan_for_rtti(view):
    if '.rdata' in view.sections:
        rdata = view.sections['.rdata']
        task = RunInBackground('Scanning for RTTI', scan_for_rtti, view, rdata.start, rdata.end)
        task.start()
    else:
        log.log_error('Could not find .rdata section')


def command_create_vtable(view, address):
    vtable_name = 'vtable_{0:X}'.format(address)

    funcs = create_vtable(view, vtable_name, address)

    for func in funcs:
        view.create_user_function(func)


def command_parse_unwind_info(view):
    task = RunInBackground('Parsing Unwind Info', parse_unwind_info, view)
    task.start()


def command_fix_x86_conventions(view):
    task = RunInBackground('Fixing calling conventions\'s', fix_x86_conventions, view)
    task.start()


def command_label_tls(view):
    label_tls(view)


def check_view_platform(view, *platforms):
    platform = view.platform
    if platform is None:
        return False
    return platform.name in platforms


PluginCommand.register(
    'Windows\\Scan for RTTI',
    'Scans for MSVC RTTI',
    lambda view: command_scan_for_rtti(view),
    lambda view: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)

PluginCommand.register_for_address(
    'Windows\\Create vftable',
    'Creates a vftable at the current address',
    lambda view, address: command_create_vtable(view, address),
    lambda view, address: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)

PluginCommand.register(
    'Windows\\Parse exception handlers',
    'Create functions based on exception handlers',
    lambda view: command_parse_unwind_info(view),
    lambda view: check_view_platform(view, 'windows-x86_64')
)

PluginCommand.register(
    'Windows\\Fix thiscall\'s',
    'Convert appropriate stdcall\'s and fastcall\'s into thiscall\'s',
    lambda view: command_fix_x86_conventions(view),
    lambda view: check_view_platform(view, 'windows-x86')
)

PluginCommand.register(
    'Windows\\Label TLS',
    'Labels TLS Structures',
    lambda view: command_label_tls(view),
    lambda view: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)
