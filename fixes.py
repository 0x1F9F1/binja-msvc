from binaryninja import log


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
    count = 0

    for func in view.functions:
        if thread.cancelled:
            break
        if func.arch.name != 'x86':
            return
        if is_broken_thiscall(func):
            func.calling_convention = func.arch.calling_conventions['thiscall']
            thread.progress = 'Fixed {0}'.format(func.name)
            count += 1

    log.log_info('Fixed {0} thiscall\'s'.format(count))
