"""
stabilize p2p network tool (optional)

don't import this from outside
"""
from p2p_python.tools import *
from p2p_python.peer import Peer
from typing import TYPE_CHECKING, List, Dict, Set, NamedTuple
from threading import Thread, Event
from random import random
from pathlib import Path
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


class Stabilizer(Thread):
    """
    stabilize network connection

    * fewer duplicate connection is better
    * high-layer is better
    """
    def __init__(self, p2p: 'Peer2Peer', max_conn: int = 30, path: Path = None):
        super().__init__(name="Stabilizer")
        self.p2p = p2p
        self.max_conn = max_conn
        self._counter = 0
        self.path = path  # peers' info backup file path

        # params
        self.neers_infos: Set[MetaInfo] = set()
        self.known_infos: Set[PeerInfo] = set()
        self.failed_infos: Set[PeerInfo] = set()
        self.duplicate_cnt: Dict[PeerInfo, int] = dict()

        # flags
        self.closing = Event()
        self.closing.clear()
        self.closed = Event()
        self.closed.set()

        # check
        if path:
            assert path.parent.is_dir(), ("backup file parent path is dir", path)

        # init
        if path and path.is_file():
            self.read_back(path)

    def run(self) -> None:
        """auto update params and stabilize connection"""
        assert self.closed.is_set()
        assert not self.closing.is_set()
        self.closed.clear()

        while True:
            try:
                # wait..
                if self.closing.wait(60.0 if self.is_stable() else 5.0):
                    log.debug("closing is set [closing now]")
                    break

                # update
                self.update_params(1 if self.is_stable() else None)

                # improve
                score = self.score()
                if self.is_stable():
                    if score < 0:
                        self.decrease_connection(1)
                        log.info(f"decrease connection score={score}")
                else:
                    self.increase_connection(1, s.AF_INET)
                    log.info(f"increase connection score={score}")

            except (ConnectionError, PenaltyError) as e:
                log.debug(f"stabiliser failed: {e}")
            except Exception:
                log.error("unexpected stabiliser error", exc_info=True)
        # closed
        self.closed.set()
        if self.path:
            self.write_down(self.path)
        log.debug("succes to close")

    def close(self) -> None:
        self.closing.set()
        self.closed.wait()

    def update_params(self, update_num: int = None) -> None:
        """get neers info from peers and update"""
        if update_num is None:
            update_num = len(self.p2p.peers)

        now = time()
        success = 0
        while 0 < update_num:
            peer = self.p2p.peers[self._counter % len(self.p2p.peers)]
            try:
                self.p2p.update_peer_info(peer)
                self.neers_infos.add(MetaInfo(peer, peer.neers, time()))
                self.known_infos.add(peer.info)
                self.known_infos.update(peer.neers)
                success += 1
            except AssertionError as e:
                log.debug(e)
            except ConnectionError:
                pass
            except OSError:  # socket is closed
                pass
            finally:
                self._counter += 1
                update_num -= 1

        # remove unknown meta
        for meta in self.neers_infos.copy():
            if meta.peer not in self.p2p.peers:
                self.neers_infos.remove(meta)

        # update bloom filter
        self.p2p.update_bloom_filter()

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
                self.failed_infos.add(info)
            except Exception:
                log.debug(f"unexpected {layer} {peer} {info}", exc_info=True)
                self.failed_infos.add(info)

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

    def write_down(self, path: Path) -> None:
        """write down all known peer info"""
        log.debug(f"backup initial peer connection len={len(self.known_infos)}")
        io = BytesIO()
        for info in self.known_infos:
            info.to_bytes(io)
        open(path, mode="wb").write(io.getbuffer())

    def read_back(self, path: Path) -> None:
        """read back all peer info"""
        try:
            data = open(path, mode="rb").read()
            io = BytesIO(data)
            while io.tell() < len(io.getbuffer()):
                self.known_infos.add(PeerInfo.from_bytes(io))
            log.debug(f"recover initial peer connection len={len(self.known_infos)}")

        except Exception:
            self.known_infos.clear()
            log.warning("failed restore from backup file", exc_info=True)


__all__ = [
    "Layer",
    "Stabilizer",
]
