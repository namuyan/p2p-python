import p2p_python.msgpack as msgpack
from threading import Lock
from queue import Queue, Empty, Full
from time import time
from logging import getLogger
import os

# For AES
from Cryptodome.Cipher import AES
from Cryptodome import Random
from base64 import b64encode, b64decode

log = getLogger('p2p-python')


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
        except Exception as e:
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


class Peers:
    def __init__(self, path):
        """recode all node, don't remove"""
        self._peer = dict()  # {(host, port): header,..}
        self.path = path
        self.cleanup()

    def get(self, host_port):
        return self._peer.get(tuple(host_port))

    def remove(self, host_port):
        del self._peer[tuple(host_port)]

    def __contains__(self, item):
        return tuple(item) in self._peer

    def __len__(self):
        return len(self._peer)

    def keys(self):
        yield from self._peer.keys()

    def copy(self):
        return self._peer.copy()

    def add(self, host_port, data):
        self._peer[tuple(host_port)] = data
        self._save(host_port, data)

    def _save(self, host_port, data):
        with open(self.path, mode='ba') as fp:
            msgpack.dump((host_port, data), fp)

    def cleanup(self):
        time_limit = int(time() - 3600 * 24 * 30)
        try:
            with open(self.path, mode='br') as fp:
                for k, v in msgpack.stream_unpacker(fp):
                    # if time_limit < v['last_seen']:
                    #    self._peer[tuple(k)] = v
                    self._peer[tuple(k)] = v
        except Exception:
            pass
        with open(self.path, mode='bw') as fp:
            for k, v in self._peer.items():
                msgpack.dump((k, v), fp)


__all__ = [
    "EventIgnition",
    "AESCipher",
    "Peers",
]
