from __future__ import absolute_import
import sys

'''
A small module for keeping a database of ordinal to symbol
mappings for DLLs which frequently get linked without symbolic
infoz.
'''

ords = {

}

PY3 = sys.version_info > (3,)

if PY3:
    def formatOrdString(ord_val):
        return 'ord{}'.format(ord_val).encode()
else:
    def formatOrdString(ord_val):
        return b'ord%d' % ord_val


def ordLookup(libname, ord_val, make_name=False):
    '''
    Lookup a name for the given ordinal if it's in our
    database.
    '''
    names = ords.get(libname.lower())
    if names is None:
        if make_name is True:
            return formatOrdString(ord_val)
        return None
    name = names.get(ord_val)
    if name is None:
        return formatOrdString(ord_val)
    return name
