import p2p_python.msgpack as msgpack
from threading import Lock
from queue import Queue, Empty, Full
import atexit
from logging import getLogger
import os

# For AES
from Cryptodome.Cipher import AES
from Cryptodome import Random
from base64 import b64encode, b64decode

log = getLogger('p2p-python')


class QueueStream:
    def __init__(self):
        self.ques = list()  # [(que, name), ..]
        self.empty = Empty
        self.lock = Lock()

    def put(self, obj):
        for q, name in self.ques.copy():
            try:
                q.put_nowait(obj)
            except Full:
                with self.lock:
                    self.ques.remove((q, name))

    def get(self, channel, timeout=None):
        # caution: Don't forget remove! memory leak risk.
        while True:
            for q, ch in self.ques.copy():
                if channel == ch:
                    return q.get(timeout=timeout)
            else:
                que = Queue(maxsize=3000)
                with self.lock:
                    self.ques.append((que, channel))

    def remove(self, channel):
        for q, ch in self.ques.copy():
            if ch == channel:
                with self.lock:
                    self.ques.remove((q, ch))
                return True
        return False


class EventIgnition:
    def __init__(self):
        self.event = dict()

    def addevent(self, cmd, f):
        self.event[cmd] = f

    def removevent(self, cmd):
        if cmd in self.event:
            del self.event[cmd]

    def __contains__(self, item):
        return item in self.event

    def work(self, cmd, data):
        if cmd in self.event:
            return self.event[cmd](data)
        else:
            raise KeyError('Not found cmd "{}"'.format(cmd))


class AESCipher:
    @staticmethod
    def create_key():
        return b64encode(os.urandom(AES.block_size)).decode()

    @staticmethod
    def is_aes_key(key):
        try:
            return len(b64decode(key.encode())) == AES.block_size
        except:
            return False

    @staticmethod
    def encrypt(key, raw):
        assert type(raw) == bytes, "input data is bytes"
        key = b64decode(key.encode())
        raw = AESCipher._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    @staticmethod
    def decrypt(key, enc):
        assert type(enc) == bytes, 'Encrypt data is bytes'
        key = b64decode(key.encode())
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw = AESCipher._unpad(cipher.decrypt(enc[AES.block_size:]))
        if len(raw) == 0:
            raise ValueError("AES decryption error, not correct key.")
        return raw

    @staticmethod
    def _pad(s):
        pad = AES.block_size - len(s) % AES.block_size
        add = AES.block_size - len(s) % AES.block_size
        return s + add * pad.to_bytes(1, 'big')

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class JsonDataBase(dict):
    def __init__(self, path, remove_limit=3):
        super().__init__()
        self.remove_limit = remove_limit
        self.path = path
        self.load()
        atexit.register(self.save)

    def save(self):
        with open(self.path, mode='bw') as fp:
            msgpack.dump(dict(self), fp)
        log.info("JsonDataBase saved to {}".format(os.path.split(self.path)[1]))

    def load(self):
        try:
            with open(self.path, mode='br') as fp:
                data = msgpack.load(fp)
                if not isinstance(data, dict):
                    for k, v in data.items:
                        self[k] = v
        except Exception:
            with open(self.path, mode='bw') as fp:
                msgpack.dump(dict(self), fp)
        log.info("JsonDataBase load from {}".format(os.path.split(self.path)[1]))

    def remove(self, host_port):
        if host_port in self and len(self) >= self.remove_limit:
            del self[host_port]
            return True
        return False


def version2int(v):
    return sum([pow(1000, i) * int(d) for i, d in enumerate(reversed(v.split('.')))])


__all__ = [
    "QueueStream",
    "EventIgnition",
    "AESCipher",
    "JsonDataBase",
    "version2int"
]
