from binaryninja import PluginCommand, log, interaction

from .utils import RunInBackground
from .rtti import scan_for_rtti, create_vtable
from .unwind import parse_unwind_info
from .fixes import fix_x86_conventions, fix_mangled_symbols
from .tls import label_tls
from .mapfile import load_map_file, load_idc_file

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
    task = RunInBackground('Fixing calling conventions', fix_x86_conventions, view)
    task.start()

def command_mangled_symbols(view):
    task = RunInBackground('Fixing mangled symbols', fix_mangled_symbols, view)
    task.start()

def command_label_tls(view):
    label_tls(view)

def command_load_mapfile(view):
    filename = interaction.get_open_filename_input('Map File', '*.map')

    if filename is not None:
        task = RunInBackground('Loading map file', load_map_file, view, filename)
        task.start()

def command_load_idcfile(view):
    filename = interaction.get_open_filename_input('IDC File', '*.idc')

    if filename is not None:
        task = RunInBackground('Loading idc file', load_idc_file, view, filename)
        task.start()

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
    'Windows\\Fix mangled symbols',
    'Fix types of mangled symbols',
    lambda view: command_mangled_symbols(view),
    lambda view: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)

PluginCommand.register(
    'Windows\\Label TLS',
    'Labels TLS Structures',
    lambda view: command_label_tls(view),
    lambda view: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)

PluginCommand.register(
    'Windows\\Load Map File',
    'Loads symbols from a map file',
    lambda view: command_load_mapfile(view),
    lambda view: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)

PluginCommand.register(
    'Windows\\Load IDC File',
    'Loads symbols from a idc file',
    lambda view: command_load_idcfile(view),
    lambda view: check_view_platform(view, 'windows-x86', 'windows-x86_64')
)
