"""
tools

note: don't import from other libs to escape dependency problem
"""
from typing import List, Tuple, Dict, NamedTuple, Any, Union, Callable
from ipaddress import ip_address, IPv4Address, IPv6Address
from concurrent.futures import ThreadPoolExecutor
from Cryptodome.Cipher import AES
from Cryptodome.Cipher._mode_gcm import GcmMode
from ecdsa.keys import VerifyingKey
from ecdsa.curves import SECP256k1
from binascii import a2b_hex
from socket import AddressFamily
from threading import Lock
from enum import IntEnum
import json
import os


# general types
_Address = Tuple[Any, ...]
_Host = Union[IPv4Address, IPv6Address]
_Dict = Dict[str, Any]
_ResponseFuc = Callable[[bytes, bytes], None]

# shared key's curve
CURVE = SECP256k1

# debug print socket receive/send message all
PRINT_SOCK_MSG = bool(os.getenv("PRINT_SOCK_MSG"))

# 20 thread pooled for general usage (not for loop work)
executor = ThreadPoolExecutor(20, thread_name_prefix="Ex")


class InnerCmd(IntEnum):
    """don't overwrite this cmd id"""
    # peer control cmd
    REQUEST_PEER_INFO = 0xfa  # 250

    # connection relay cmd
    REQUEST_MEDIATOR = 0xfb  # 251
    REQUEST_ASK_SRUDP = 0xfc  # 252

    # general response cmd
    RESPONSE_PROCESSING = 0xfd  # 253
    RESPONSE_SUCCESS = 0xfe  # 254
    RESPONSE_FAILED = 0xff  # 255


# cmd response
_PROCESSING = InnerCmd.RESPONSE_PROCESSING.to_bytes(1, "big")
_SUCCESS = InnerCmd.RESPONSE_SUCCESS.to_bytes(1, "big")
_FAILED = InnerCmd.RESPONSE_FAILED.to_bytes(1, "big")


class FormalAddr(NamedTuple):
    host: _Host
    port: int

    def __repr__(self) -> str:
        return self.to_string()

    @classmethod
    def from_bytes(cls, b: bytes) -> 'FormalAddr':
        port = int.from_bytes(b[:4], "big")
        host = ip_address(b[4:])
        return FormalAddr(host, port)

    @classmethod
    def from_address(cls, addr: _Address) -> 'FormalAddr':
        host = ip_address(addr[0])
        port = int(addr[1])
        return FormalAddr(host, port)

    @classmethod
    def from_string(cls, s: str) -> 'FormalAddr':
        """
        ipv4: 145.2.134.5:80
        ipv6: [2001:db8::1]:80
        """
        host_str, port_str = s.rsplit(":", 1)
        return FormalAddr(ip_address(host_str.lstrip("[").rstrip("]")), int(port_str))

    def to_bytes(self) -> bytes:
        host_bytes = self.host.packed
        port_bytes = self.port.to_bytes(4, "big")
        return port_bytes + host_bytes

    def to_address(self) -> _Address:
        if self.host.version == 4:
            return str(self.host), self.port
        elif self.host.version == 6:
            return str(self.host), self.port, 0, 0
        else:
            raise NotImplementedError(f"not found ip ver {self.host.version}")

    def to_string(self) -> str:
        if self.host.version == 4:
            return f"{self.host}:{self.port}"
        elif self.host.version == 6:
            return f"[{self.host}]:{self.port}"
        else:
            raise NotImplementedError(f"not found ip ver {self.host.version}")


class PeerInfo(NamedTuple):
    """peer's public info"""
    addresses: List[FormalAddr]  # listen address
    public_key: VerifyingKey
    tcp_server: bool
    srudp_bound: bool

    def to_bytes(self) -> bytes:
        return json.dumps({
            "addresses": [addr.to_string() for addr in self.addresses],
            "public_key": self.public_key.to_string().hex(),
            "tcp_server": self.tcp_server,
            "srudp_bound": self.srudp_bound,
        }).encode()

    @classmethod
    def from_bytes(cls, b: bytes) -> 'PeerInfo':
        obj: _Dict = json.loads(b.decode())
        addresses = [FormalAddr.from_string(addr) for addr in obj["addresses"]]
        pubkey_bytes = a2b_hex(obj["public_key"])
        public_key = VerifyingKey.from_string(pubkey_bytes, curve=CURVE)
        return PeerInfo(
            addresses,
            public_key,
            bool(obj["tcp_server"]),
            bool(obj["srudp_bound"]),
        )

    def __eq__(self, other: object) -> bool:
        """only check public key"""
        assert isinstance(other, PeerInfo)
        return self.public_key == other.public_key  # type: ignore


def uniq_id_generator() -> Callable[[], int]:
    """uniq Sock's id generator"""
    lock = Lock()
    base_uuid = 0

    def _get_uuid() -> int:
        nonlocal base_uuid
        with lock:
            base_uuid += 1
            return base_uuid
    return _get_uuid


def time2string(ntime: float) -> str:
    if ntime < 120.0:  # 2m
        return str(round(ntime, 1)) + "s"
    elif ntime < 7200.0:  # 2h
        return str(round(ntime/60.0, 1)) + "m"
    elif ntime < 172800.0:  # 2d
        return str(round(ntime/3600.0, 1)) + "h"
    else:
        return str(round(ntime/86400.0, 1)) + "d"


def encrypt(key: bytes, data: bytes) -> bytes:
    """encrypt by AES-GCM (more secure than CBC mode)"""
    cipher: GcmMode = AES.new(key, AES.MODE_GCM)  # type: ignore
    # warning: Don't reuse nonce
    enc, tag = cipher.encrypt_and_digest(data)
    # output length = 16bytes + 16bytes + N(=data)bytes
    return cipher.nonce + tag + enc


def decrypt(key: bytes, data: bytes) -> bytes:
    """decrypt by AES-GCM (more secure than CBC mode)"""
    cipher: GcmMode = AES.new(key, AES.MODE_GCM, nonce=data[:16])  # type: ignore
    # ValueError raised when verify failed
    return cipher.decrypt_and_verify(data[32:], data[16:32])


__all__ = [
    "_Address",
    "_Host",
    "_Dict",
    "_ResponseFuc",
    "CURVE",
    "PRINT_SOCK_MSG",
    "executor",
    "InnerCmd",
    "_PROCESSING",
    "_SUCCESS",
    "_FAILED",
    "FormalAddr",
    "PeerInfo",
    "uniq_id_generator",
    "time2string",
    "encrypt",
    "decrypt",
]
