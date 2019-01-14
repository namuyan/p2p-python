import msgpack


def default(obj):
    if isinstance(obj, dict):
        for k in obj.keys():
            if isinstance(k, str) or isinstance(k, int) or isinstance(k, bytes):
                continue
            else:
                raise TypeError('msgpack dict key don\'t allow {}'.format(type(k)))
    return obj


def dump(obj, fp):
    msgpack.pack(obj, fp, use_bin_type=True, default=default)


def dumps(obj):
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
