from p2p_python.serializer import stream_unpacker, dump
from logging import getLogger
from time import time
import os

# For AES
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome import Random
from base64 import b64encode, b64decode

log = getLogger(__name__)


class EventIgnition:

    def __init__(self):
        self.event = dict()

    def addevent(self, cmd, f, post_f=None):
        self.event[cmd] = (f, post_f)

    def removevent(self, cmd):
        if cmd in self.event:
            del self.event[cmd]

    def __contains__(self, item):
        return item in self.event

    def work(self, cmd, data):
        if cmd in self.event:
            f, post_f = self.event[cmd]
            r = f(data)
            if post_f:
                return post_f(r)
            else:
                return r
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
        raw = pad(raw, AES.block_size)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    @staticmethod
    def decrypt(key, enc):
        assert type(enc) == bytes, 'Encrypt data is bytes'
        key = b64decode(key.encode())
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw = cipher.decrypt(enc[AES.block_size:])
        raw = unpad(raw, AES.block_size)
        if len(raw) == 0:
            raise ValueError("AES decryption error, not correct key.")
        return raw


class PeerData(object):

    def __init__(self, path):
        """recode all node, don't remove"""
        self._peer = dict()  # {(host, port): header,..}
        self.path = path
        self.cleanup()

    def get(self, host_port):
        return self._peer.get(tuple(host_port))

    def remove(self, host_port):
        host_port = tuple(host_port)
        if host_port in self._peer:
            del self._peer[tuple(host_port)]
            return True
        return False

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
        with open(self.path, mode='ba') as fp:
            dump((host_port, data), fp)

    def cleanup(self):
        time_limit = int(time() - 3600*24*30)
        try:
            with open(self.path, mode='br') as fp:
                for k, v in stream_unpacker(fp):
                    # if time_limit < v['last_seen']:
                    #    self._peer[tuple(k)] = v
                    self._peer[tuple(k)] = v
        except Exception:
            pass
        with open(self.path, mode='bw') as fp:
            for k, v in self._peer.items():
                dump((k, v), fp)


__all__ = [
    "EventIgnition",
    "AESCipher",
    "PeerData",
]
