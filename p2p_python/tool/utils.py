from threading import Lock
from queue import Queue, Empty, Full
import time
import bjson
import atexit
import logging
import os

# For AES
from Cryptodome.Cipher import AES
from Cryptodome import Random
from base64 import b64encode, b64decode


class StackDict:
    def __init__(self, limit=500):
        self.uuid2data = dict()
        self.lock = Lock()
        self.limit = limit

    def get(self, uuid):
        return self.uuid2data[uuid][0]

    def put(self, uuid, item):
        with self.lock:
            self.uuid2data[uuid] = (item, time.time())
            if len(self.uuid2data) > self.limit:
                self.__refresh()

    def include(self, uuid):
        return uuid in self.uuid2data

    def remove(self, uuid):
        with self.lock:
            if uuid in self.uuid2data:
                del self.uuid2data[uuid]

    def __refresh(self):
        limit = self.limit * 3 // 4
        for k, v in sorted(self.uuid2data.items(), key=lambda x: x[1][1]):
            del self.uuid2data[k]
            if len(self.uuid2data) < limit:
                break
        logging.debug("StackDict refresh now.")

    def get_data_list(self):
        return list(self.uuid2data.values())


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
            bjson.dump(dict(self), fp=fp)
        logging.info("JsonDataBase saved to {}".format(os.path.split(self.path)[1]))

    def load(self):
        try:
            with open(self.path, mode='br') as fp:
                data = bjson.load(fp=fp)
                if not isinstance(data, dict):
                    for k, v in data.items:
                        self[k] = v
        except Exception:
            with open(self.path, mode='bw') as fp:
                bjson.dump(dict(self), fp=fp)
        logging.info("JsonDataBase load from {}".format(os.path.split(self.path)[1]))

    def remove(self, host_port):
        if host_port in self and len(self) >= self.remove_limit:
            del self[host_port]
            return True
        return False


def version2int(v):
    return sum([pow(1000, i) * int(d) for i, d in enumerate(reversed(v.split('.')))])


__all__ = [
    "StackDict",
    "QueueStream",
    "EventIgnition",
    "AESCipher",
    "JsonDataBase",
    "version2int"
]
