from p2p_python.tools import *
from p2p_python.sockpool import Sock, SockControl
from typing import TYPE_CHECKING, Tuple, List, Optional, Union, NamedTuple, Any
from ecdsa.keys import VerifyingKey
from threading import Thread, Lock
from time import time
import socket as s
import logging


log = logging.getLogger(__name__)
get_uuid = uniq_id_generator()


class Peer(object):
    def __init__(self, info: PeerInfo) -> None:
        self.id = get_uuid()
        self.info = info
        self.socks: List[Sock] = list()
        # self.neers: List[PeerInfo] = list()
        # self.warn = 0
        # self.point = 0
        self.score = 100  # 0~100
        self.time = time()
        self.lock = Lock()

    def __repr__(self) -> str:
        stable = len([sock.stable.is_set() for sock in self.socks])
        public_key = self.get_validated_key()
        if public_key is None:
            pubkey_hex = "invalidate"
        else:
            pubkey_hex = public_key.to_string().hex()
            pubkey_hex = pubkey_hex[:6] + ".." + pubkey_hex[-6:]
        uptime = time2string(time() - self.time)
        return f"<Peer{self.id} {stable}/{len(self.socks)} {pubkey_hex} {uptime}>"

    def get_connect_address(self, family: s.AddressFamily) -> Optional[FormalAddr]:
        """get connection address format"""
        family_ver = 4 if family == s.AF_INET else 6
        with self.lock:
            for addr in self.info.addresses:
                if addr.host.version == family_ver:
                    return addr
        return None

    def get_validated_key(self) -> Optional[VerifyingKey]:
        """get public key from validation success sock"""
        with self.lock:
            for sock in self.socks:
                if sock.flags & SockControl.VALIDATED \
                        and sock.others_key is not None:
                    return sock.others_key
        return None

    def get_sock(self, family: s.AddressFamily, is_srudp: bool) -> Optional[Sock]:
        """find an already connected sock"""
        with self.lock:
            for sock in self.socks:
                if sock.sock.family == family and sock.is_srudp() is is_srudp:
                    return sock
        return None

    def wait_stable(self) -> bool:
        """wait for peer's sock is stable"""
        with self.lock:
            socks = self.socks.copy()
        for sock in socks:
            if sock.stable.is_set():
                return True
        for sock in socks:
            if sock.stable.wait(20.0):
                return True
        return False

    def close(self) -> None:
        for sock in self.socks:
            sock.close()
        self.socks.clear()


__all__ = [
    "Peer",
]
