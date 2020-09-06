"""
stabilize p2p network tool (optional)

don't import this from outside
"""
from p2p_python.tools import *
from p2p_python.peer import Peer
from p2p_python.peercontrol import AskNeersCmd
from typing import TYPE_CHECKING, List, Dict, Set, NamedTuple
from random import random
from enum import Enum
from io import BytesIO
from time import time
import socket as s
import logging


log = logging.getLogger(__name__)


if TYPE_CHECKING:
    from p2p_python.peer2peer import Peer2Peer


class Layer(Enum):
    """
    peer's position 0~4 layer

    1. CENTER: peer is myself
    2. FIRST: connected peer
    3. SECOND: known peer by connected peer
    4. THIRD: only know the existence
    5. FORTH: unknown peer
    """
    CENTER = 0  # peer is myself
    FIRST = -1  # connected peer
    SECOND = -2  # known peer by connected peer
    THIRD = -3  # only know the existence
    FORTH = -4  # unknown peer


class MetaInfo(NamedTuple):
    peer: Peer
    neers: List[PeerInfo]
    time: float

    def __hash__(self) -> int:
        return hash(self.peer)

    def __eq__(self, other: object) -> bool:
        assert isinstance(other, MetaInfo)
        return self.peer == other.peer


class Stabilizer(object):
    """
    stabilize network connection

    * fewer duplicate connection is better
    * high-layer is better
    """
    def __init__(self, p2p: 'Peer2Peer', max_conn: int = 30):
        self.p2p = p2p
        self.max_conn = max_conn

        # params
        self.neers_infos: Set[MetaInfo] = set()
        self.known_infos: Set[PeerInfo] = set()
        self.duplicate_cnt: Dict[PeerInfo, int] = dict()

    def update_params(self) -> None:
        """get neers info from peers and update"""
        now = time()
        success = 0
        self.neers_infos.clear()
        for peer in self.p2p.peers.copy():
            try:
                assert peer.wait_stable(), ("wait stable but timeout", peer)
                response, _sock = self.p2p.throw_command(peer, InnerCmd.REQUEST_ASK_NEERS, b"")
                neers = AskNeersCmd.decode(BytesIO(response))
                self.neers_infos.add(MetaInfo(peer, neers, time()))
                self.known_infos.add(peer.info)
                self.known_infos.update(neers)
                success += 1
            except AssertionError as e:
                log.debug(e)
            except ConnectionError:
                pass
            except OSError:  # socket is closed
                pass

        # check duplicate
        all_neer_list = list()
        for meta in self.neers_infos:
            all_neer_list.extend(meta.neers)
        for info in self.known_infos:
            self.duplicate_cnt[info] = all_neer_list.count(info)
        log.debug(f"update Stabilizer success={success} {time()-now:.3g}s")

    def increase_connection(self, inc_num: int, family: s.AddressFamily) -> None:
        """add new connection from known peer list"""
        assert 0 < inc_num

        # find stable connection number
        lack = self.max_conn - len(self.p2p.peers)

        # enough connection have
        if lack < 1:
            return

        # order by good
        good_list = sorted(
            filter(lambda _info: _info.tcp_server or _info.srudp_bound, self.known_infos),
            key=lambda _info: (self.get_layer(_info).value, self.duplicate_cnt.get(_info, 0), random()),
        )
        log.debug(f"stabilizer find good list len={len(good_list)}")

        # add new connection number
        add = min(lack, inc_num)

        # try to connect
        peer: Peer = None
        layer: Layer = None
        for info in good_list:
            if add == 0:
                break
            layer = self.get_layer(info)
            # skip myself
            if layer == Layer.CENTER:
                continue
            # skip already connected
            if layer == Layer.FIRST:
                continue

            try:
                if info.tcp_server and 0 < len(info.addresses):
                    addr = info.get_address(4 if family == s.AF_INET else 6)
                    if addr is None:
                        continue
                    peer = self.p2p.add_peer_by_address(addr.host, addr.port, info.public_key)
                    peer.wait_stable()

                elif info.srudp_bound:
                    for meta in self.neers_infos:
                        if info in meta.neers:
                            mediator = meta.peer
                            break
                    else:
                        continue
                    peer = self.p2p.add_peer_by_mediator(mediator, info.public_key, family)
                    peer.wait_stable()

                else:
                    continue
            except ConnectionError as e:
                log.debug(f"failed connect to {layer} {peer} by {info}, error is {e}")
            except Exception:
                log.debug(f"unexpected {layer} {peer} {info}", exc_info=True)

            # connect success
            log.info(f"success add new connection {peer}")
            add -= 1

    def decrease_connection(self, dec_num: int) -> None:
        """remove low-scored connection"""
        assert 0 < dec_num

        # how many connection remove
        remove = min(len(self.p2p.peers), dec_num)

        # order by bad
        bad_list = sorted(
            self.neers_infos,
            key=lambda _meta: self.duplicate_cnt.get(_meta.peer.info, 0),
            reverse=True)

        # remove bad peer
        for _index, meta in zip(range(remove), bad_list):
            self.p2p.close_peer(meta.peer, b"stabilizer repute you low-scored")

    def score(self) -> int:
        """calc my score (need improvement if lower than zero)"""
        score = len(self.p2p.peers)
        for meta in self.neers_infos:
            score -= self.duplicate_cnt.get(meta.peer.info, 0)
        return score

    def is_stable(self) -> bool:
        return self.max_conn // 2 < len(self.p2p.peers)

    def get_layer(self, info: PeerInfo) -> Layer:
        """get layer of the peer"""
        if info == self.p2p.my_info:
            return Layer.CENTER
        for meta in self.neers_infos:
            if meta.peer.info == info:
                return Layer.FIRST
        for meta in self.neers_infos:
            if info in meta.neers:
                return Layer.SECOND
        if info in self.known_infos:
            return Layer.THIRD
        return Layer.FORTH

    def write_down(self, path: str) -> None:
        """write down all known peer info"""
        io = BytesIO()
        for info in self.known_infos:
            info.to_bytes(io)
        open(path, mode="wb").write(io.getbuffer())

    def read_back(self, path: str) -> None:
        """read back all peer info"""
        data = open(path, mode="rb").read()
        io = BytesIO(data)
        while io.tell() < len(io.getbuffer()):
            self.known_infos.add(PeerInfo.from_bytes(io))


__all__ = [
    "Layer",
    "Stabilizer",
]
