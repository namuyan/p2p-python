#!/user/env python3
# -*- coding: utf-8 -*-

from ..utils import str2byte
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class SignRSA:
    @staticmethod
    def create_keypair(b=3072):
        rsa = RSA.generate(b, Random.new().read)
        private_pem = rsa.exportKey(format='PEM')
        public_pem = rsa.publickey().exportKey()
        return private_pem.decode(), public_pem.decode()

    @staticmethod
    def sign(private_pem, message, pwd=None):
        key = RSA.importKey(str2byte(private_pem), passphrase=pwd)  # , passphrase='hogehoge')
        h = SHA256.new(message)
        return pkcs1_15.new(key).sign(h)

    @staticmethod
    def verify(public_pem, message, signature, pwd=None):
        key = RSA.importKey(str2byte(public_pem), passphrase=pwd)
        h = SHA256.new(message)
        # Note: When failed verification, raised ValueError
        pkcs1_15.new(key).verify(h, signature)
