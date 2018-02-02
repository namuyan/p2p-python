#!/user/env python3
# -*- coding: utf-8 -*-

from ..utils import str2byte
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


class SignECDSA:
    SECP256R1 = 'secp256r1'
    PRIME256V1 = 'prime256v1'

    @staticmethod
    def create_keypair(curve=SECP256R1):
        key = ECC.generate(curve=curve)  # prime256v1, secp256r1
        private_pem = key.export_key(format='PEM')
        public_pem = key.public_key().export_key(format='PEM')
        return private_pem.decode(), public_pem.decode()

    @staticmethod
    def sign(private_pem, message):
        assert type(message) == bytes, 'message should be bytes'
        key = ECC.import_key(str2byte(private_pem))
        h = SHA256.new(message)
        signer = DSS.new(key, 'fips-186-3')
        return signer.sign(h)

    @staticmethod
    def verify(public_pem, message, sign):
        key = ECC.import_key(str2byte(public_pem))
        h = SHA256.new(message)
        verifier = DSS.new(key, 'fips-186-3')
        # Note: When failed verification, raised ValueError
        verifier.verify(h, sign)
