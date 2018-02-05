#!/user/env python3
# -*- coding: utf-8 -*-

from ..utils import str2byte
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import zlib
import os


class AESCipher:
    @staticmethod
    def create_key():
        return b64encode(os.urandom(32)).decode()

    @staticmethod
    def is_aes_key(key):
        try:
            return len(b64decode(key.encode())) == 32
        except:
            return False

    @staticmethod
    def encrypt(key, raw, z=True):
        assert type(raw) == bytes, "input data is bytes"
        if z:
            raw = zlib.compress(raw)
        key = b64decode(str2byte(key))
        raw = AESCipher._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    @staticmethod
    def decrypt(key, enc, z=True):
        assert type(enc) == bytes, 'Encrypt data is bytes'
        key = b64decode(str2byte(key))
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw = AESCipher._unpad(cipher.decrypt(enc[AES.block_size:]))
        if len(raw) == 0:
            raise Exception("not correct pwd")
        elif z:
            return zlib.decompress(raw)
        else:
            return raw

    @staticmethod
    def _pad(s):
        pad = 32 - len(s) % 32
        add = 32 - len(s) % 32
        return s + add * pad.to_bytes(1, 'big')

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
