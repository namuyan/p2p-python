import msgpack


def only_key_check(obj):
    if isinstance(obj, dict):
        for k in obj.keys():
            if isinstance(k, str) or isinstance(k, int) or isinstance(k, bytes):
                continue
            else:
                raise TypeError('msgpack dict key don\'t allow {}'.format(type(k)))
    return obj


def dump(obj, fp, default=only_key_check):
    msgpack.pack(obj, fp, use_bin_type=True, default=default)


def dumps(obj, default=only_key_check):
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
