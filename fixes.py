from binaryninja import log

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
