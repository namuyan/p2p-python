#!/user/env python3
# -*- coding: utf-8 -*-

from ..utils import str2byte
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode, b64encode


class EncryptRSA:
    @staticmethod
    def create_keypair(b=3072):
        rsa = RSA.generate(b, Random.new().read)
        private_pem = rsa.exportKey(format='PEM')
        public_pem = rsa.publickey().exportKey()
        return private_pem.decode(), public_pem.decode()

    @staticmethod
    def encrypt(public_pem, message):
        cipher = PKCS1_OAEP.new(RSA.importKey(str2byte(public_pem)))
        return b64encode(cipher.encrypt(message)).decode()

    @staticmethod
    def decrypt(private_pem, enc):
        msg = b64decode(str2byte(enc))
        cipher = PKCS1_OAEP.new(RSA.importKey(str2byte(private_pem)))
        return cipher.decrypt(msg)