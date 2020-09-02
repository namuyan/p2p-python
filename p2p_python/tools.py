"""
tools

note: don't import from other libs to escape dependency problem
"""
from typing import TYPE_CHECKING, Optional, List, Tuple, Dict, NamedTuple, Any, Union, Callable
from ipaddress import ip_address, IPv4Address, IPv6Address
from concurrent.futures import ThreadPoolExecutor
from Cryptodome.Cipher import AES
from Cryptodome.Cipher._mode_gcm import GcmMode
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.curves import SECP256k1
from binascii import a2b_hex
from socket import AddressFamily
from threading import Lock
from enum import IntEnum
from io import BytesIO
from hashlib import sha256
import json
import os

if TYPE_CHECKING:
    from p2p_python.peer2peer import Peer2Peer
    from p2p_python.sockpool import Sock

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
    REQUEST_ASK_NEERS = 0xf9  # 249
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


# cmd base class
class CmdThreadBase(object):
    cmd: IntEnum

    @staticmethod
    def encode(*args: Any) -> bytes:
        """serialize any items, escape supertype error by 'type: ignore'"""
        raise NotImplementedError("CmdThreadBase.encode()")

    @staticmethod
    def decode(io: BytesIO) -> Any:
        """deserialize received binary"""
        raise NotImplementedError("CmdThreadBase.decode()")

    @staticmethod
    def thread(res_fnc: _ResponseFuc, body: bytes, sock: 'Sock', p2p: 'Peer2Peer') -> Optional[bytes]:
        """execute this when receive request, finish in 20s or timeout and return bytes or None"""
        raise NotImplementedError("CmdThreadBase thread()")


class FormalAddr(NamedTuple):
    host: _Host
    port: int

    def __repr__(self) -> str:
        return self.to_string()

    @classmethod
    def from_bytes(cls, io: BytesIO) -> 'FormalAddr':
        """[port int 4b][host_len 4b][host 4-16b]"""
        port = int.from_bytes(io.read(4), "big")
        host_len = int.from_bytes(io.read(4), "big")
        host = ip_address(io.read(host_len))
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

    def to_bytes(self, io: BytesIO) -> memoryview:
        io.write(self.port.to_bytes(4, "big"))
        host_bytes = self.host.packed
        io.write(len(host_bytes).to_bytes(4, "big"))
        io.write(host_bytes)
        return io.getbuffer()

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

    def to_bytes(self, io: BytesIO) -> memoryview:
        data = json.dumps({
            "addresses": [addr.to_string() for addr in self.addresses],
            "public_key": self.public_key.to_string().hex(),
            "tcp_server": self.tcp_server,
            "srudp_bound": self.srudp_bound,
        }).encode()
        io.write(len(data).to_bytes(4, "big"))
        io.write(data)
        return io.getbuffer()

    @classmethod
    def from_bytes(cls, io: BytesIO) -> 'PeerInfo':
        length = int.from_bytes(io.read(4), "big")
        obj: _Dict = json.loads(io.read(length))
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


def get_shared_key(sk: SigningKey, pk: VerifyingKey, nonce: bytes = b"") -> bytes:
    """calculate shared point and hashed by sha256"""
    shared_point = sk.privkey.secret_multiplier * pk.pubkey.point
    return sha256(int(shared_point.x()).to_bytes(32, 'big') + nonce).digest()


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
    "CmdThreadBase",
    "FormalAddr",
    "PeerInfo",
    "uniq_id_generator",
    "time2string",
    "encrypt",
    "decrypt",
    "get_shared_key",
]
