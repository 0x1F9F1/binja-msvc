from binaryninja import PluginCommand, log
from utils import RunInBackground
from rtti import scan_for_rtti
from unwind import parse_unwind_info
from fixes import fix_thiscalls


def command_scan_for_rtti(view):
    if '.rdata' in view.sections:
        rdata = view.sections['.rdata']
        task = RunInBackground('Scanning for RTTI', scan_for_rtti, view, rdata.start, rdata.end)
        task.start()
    else:
        log.log_error('Could not find .rdata section')


def command_parse_unwind_info(view):
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
