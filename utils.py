from binaryninja import BackgroundTaskThread
from binaryninja.enums import Endianness
import struct
from .pefile import *


class RunInBackground(BackgroundTaskThread):
    def __init__(self, msg, func, *args, **kwargs):
            BackgroundTaskThread.__init__(self, msg, True)
            self.func = func
            self.args = args
            self.kwargs = kwargs

    def run(self):
        self.func(self, *self.args, **self.kwargs)


def read_cstring(view, address):
    buf = bytearray()

    while True:
        data = view.read(address, 1)
        address += 1

        if not data:
            break

        value = ord(data)

        if not value:
            break

        buf.append(value)

    return str(buf), address


def align_up(value, align):
    remainder = value % align
    if remainder:
        value += (align - remainder)
    return value


def check_offset(view, offset):
    return view.start <= offset < view.end


def read_pe_header(view):
    seg = view.get_segment_at(view.start)
    return pefile.PE(data = view.read(seg.start, seg.length))


def get_endian_format(endian):
    if endian == Endianness.LittleEndian:
        return '<'
    elif endian == Endianness.BigEndian:
        return '>'
    raise NotImplementedError()


def get_bool_format(width):
    if width == 1:
        return '?'
    return get_int_format(width, False)


_int_formats = {
    1: ['B', 'b'],
    2: ['H', 'h'],
    4: ['I', 'i'],
    8: ['Q', 'q']
}

def get_int_format(width, signed):
    if width in _int_formats:
        return _int_formats[width][bool(signed)]
    raise NotImplementedError()


_float_formats = {
    4: 'f',
    8: 'd'
}

def get_float_format(width):
    if width in _float_formats:
        return _float_formats[width]
    raise NotImplementedError()


def get_pointer_format(width):
    return get_int_format(width, False)


class BinjaStruct(object):
    def __init__(self, fmt, names = None, single = False):
        self._struct = struct.Struct(fmt)
        self._names = names
        self._single = single

    @classmethod
    def Pointer(cls, view):
        return BinjaStruct('{0}{1}'.format(get_endian_format(view.endianness), get_pointer_format(view.address_size)), single = True)

    @property
    def struct(self):
        return self._struct

    @property
    def names(self):
        return self._names

    @property
    def single(self):
        return self._single

    @property
    def size(self):
        return self.struct.size

    def read(self, view, address, align = 1):
        address = align_up(address, align)
        data = view.read(address, self.size)

        result = None

        if len(data) == self.size:
            result = self.struct.unpack(data)

            if self.names is not None:
                if len(self.names) == len(result):
                    result = dict(zip(self.names, result))
                else:
                    result = None
            elif self.single:
                if len(result) == 1:
                    result = result[0]
                else:
                    result = None

        return result, address + self.size

    def read_array(self, view, address, count, align = 1):
        results = [ ]

        for i in range(count):
            value, address = self.read(view, address, align)
            results.append(value)

        return results, address
