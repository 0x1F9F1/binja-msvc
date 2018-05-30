from binaryninja import BackgroundTaskThread


class RunInBackground(BackgroundTaskThread):
    def __init__(self, msg, func, *args, **kwargs):
            BackgroundTaskThread.__init__(self, msg, True)
            self.func = func
            self.args = args
            self.kwargs = kwargs

    def run(self):
        self.func(self, *self.args, **self.kwargs)


def read_pointer(view, reader):
    if view.address_size == 4:
        return reader.read32le()
    if view.address_size == 8:
        return reader.read64le()
    return None


def read_cstring(reader):
    buf = bytearray()
    while True:
        b = reader.read8()
        if b is None or b == 0:
            return str(buf)
        else:
            buf.append(b)
