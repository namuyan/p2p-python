from p2p_python.peer2peer import *
from p2p_python.tools import *
from p2p_python.stabiliser import Stabilizer
from typing import Dict
from ipaddress import ip_address
import socket as s
import logging
import random


log = logging.getLogger(__name__)


def test_stabiliser() -> None:
    """
    stabilize p2p network
    """
    num = 20
    assert 5 < num
    localhost = ip_address("127.0.0.1")
    p2ps = list()
    stabilisers = list()
    start = random.randint(10000, 30000)
    for port in range(start, start + num):
        p2p = Peer2Peer(dict(), [FormalAddr(localhost, port)], tcp_server=True)
        p2p.add_server_sock(localhost, port, s.AF_INET)
        p2ps.append(p2p)
        stabilisers.append(Stabilizer(p2p, max_conn=6))
    log.info("p2ps len=%d", len(p2ps))

    key2name: Dict[bytes, str] = {
        p2p.my_info.public_key.to_string("compressed"): "P{:0>2}".format(index)
        for index, p2p in enumerate(p2ps)}
    for pk, name in key2name.items():
        log.info("show pubkey %s=%s", name, pk.hex())

    # connect
    root_p2p = p2ps[0]
    for dest_p2p in p2ps[1:]:
        port = dest_p2p.my_info.addresses[0][1]
        peer = root_p2p.add_peer_by_address(localhost, port, dest_p2p.my_info.public_key)
        assert peer.wait_stable(), peer
    log.info("connected to root %s", root_p2p)

    # before
    before_score = sum([stab.score() for stab in stabilisers])

    # stabilize
    for cnt in range(10):
        for stab in stabilisers:
            stab.update_params()
            score = stab.score()
            if stab.is_stable():
                if score < 0:
                    stab.decrease_connection(1)
                    log.info("decrease -> score=%d %s", score, stab.p2p)
            else:
                stab.increase_connection(1, s.AF_INET)
                log.info("increase -> score=%d %s", score, stab.p2p)
        log.info("finish cycle %d", cnt)

    # last update
    for stab in stabilisers:
        stab.update_params()

    # status
    log.info("show connection status")
    after_score = 0
    for stab, p2p in zip(stabilisers, p2ps):
        after_score += stab.score()
        log.info("peer=%s peer_len=%d score=%d peers=%s",
                 key2name.get(p2p.my_info.public_key.to_string("compressed")),
                 len(p2p.peers),
                 stab.score(),
                 list(map(lambda _peer: key2name.get(_peer.info.public_key.to_string("compressed")), p2p.peers)))

    # compare
    log.info("compare score %d -> %d", before_score, after_score)
    assert before_score < after_score, ("no network improvement", before_score, after_score)

    # close
    log.info("close")
    for p2p in p2ps:
        p2p.close()


def test_surdp_stabilize() -> None:
    """
    stabilized by srudp

    only one server and other clients
    """
    num = 20
    assert 5 < num
    localhost = ip_address("127.0.0.1")
    p2ps = list()
    stabilisers = list()
    start = random.randint(10000, 30000)
    for port in range(start, start + num):
        if port == start:
            p2p = Peer2Peer(dict(), [FormalAddr(localhost, port)], tcp_server=True)
            p2p.add_server_sock(localhost, port, s.AF_INET)
        else:
            p2p = Peer2Peer(dict(), [FormalAddr(localhost, port)], srudp_bound=True)
        p2ps.append(p2p)
        stabilisers.append(Stabilizer(p2p, max_conn=6))
    log.info("p2ps len=%d", len(p2ps))

    key2name: Dict[bytes, str] = {
        p2p.my_info.public_key.to_string("compressed"): "P{:0>2}".format(index)
        for index, p2p in enumerate(p2ps)}
    for pk, name in key2name.items():
        log.info("show pubkey %s=%s", name, pk.hex())

    # connect by tcp
    root_p2p = p2ps[0]
    root_port = root_p2p.my_info.addresses[0][1]
    for dest_p2p in p2ps[1:]:
        peer = dest_p2p.add_peer_by_address(localhost, root_port, root_p2p.my_info.public_key)
        assert peer.wait_stable(), peer
    log.info("connected to root")

    # before
    before_score = sum([stab.score() for stab in stabilisers])

    # stabilize by srudp
    for cnt in range(10):
        for stab in stabilisers:
            stab.update_params()
            score = stab.score()
            if stab.is_stable():
                if score < 0:
                    stab.decrease_connection(1)
                    log.info("decrease -> score=%d %s", score, stab.p2p)
            else:
                stab.increase_connection(1, s.AF_INET)
                log.info("increase -> score=%d %s", score, stab.p2p)
        log.info("finish cycle %d", cnt)

    # last update
    for stab in stabilisers:
        stab.update_params()

    # status
    log.info("show connection status")
    after_score = 0
    for stab, p2p in zip(stabilisers, p2ps):
        after_score += stab.score()
        log.info("peer=%s peer_len=%d score=%d peers=%s",
                 key2name.get(p2p.my_info.public_key.to_string("compressed")),
                 len(p2p.peers),
                 stab.score(),
                 list(map(lambda _peer: key2name.get(_peer.info.public_key.to_string("compressed")), p2p.peers)))

    # compare
    log.info("compare score %d -> %d", before_score, after_score)
    assert before_score < after_score, ("no network improvement", before_score, after_score)

    # close
    log.info("close")
    for p2p in p2ps:
        p2p.close()
