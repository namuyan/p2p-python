import msgpack


def dump(obj, fp, default=None):
    msgpack.pack(obj, fp, use_bin_type=True, default=default)


def dumps(obj, default=None):
    return msgpack.packb(obj, use_bin_type=True, default=default)


def load(fp, object_hook=None):
    return msgpack.unpack(fp, object_hook=object_hook, encoding='utf8')


def loads(b, object_hook=None):
    return msgpack.unpackb(b, object_hook=object_hook, encoding='utf8')


def stream_unpacker(fp, object_hook=None):
    return msgpack.Unpacker(fp, object_hook=object_hook, encoding='utf8')


__all__ = [
    "dump",
    "dumps",
    "load",
    "loads",
    "stream_unpacker",
]
