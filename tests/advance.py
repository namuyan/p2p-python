from p2p_python.peer2peer import *
from p2p_python.tools import *
from p2p_python.traceroute import traceroute_network
from ipaddress import ip_address
import socket as s
import logging
import random


log = logging.getLogger(__name__)


def test_traceroute() -> None:
    """
    trace p2p network route

    1. setup A, B, C and D
    2. connect A-B-C-D-A-.. looped
    3. trace route of A to B and A to C
    """
    port_a = random.randint(10000, 30000)
    port_b = port_a + 1
    port_c = port_b + 1
    port_d = port_c + 1
    localhost = ip_address("127.0.0.1")
    log.info("STEP1 init A=%d, B=%d, C=%d D=%d", port_a, port_b, port_c,port_d)

    p2p_a = Peer2Peer(dict(), [FormalAddr(localhost, port_a)], tcp_server=True)
    p2p_b = Peer2Peer(dict(), [FormalAddr(localhost, port_b)], tcp_server=True)
    p2p_c = Peer2Peer(dict(), [FormalAddr(localhost, port_c)], tcp_server=True)
    p2p_d = Peer2Peer(dict(), [FormalAddr(localhost, port_d)], tcp_server=True)
    log.info("STEP2 p2p")

    key2name = {
        p2p_a.my_info.public_key.to_string("compressed"): "A",
        p2p_b.my_info.public_key.to_string("compressed"): "B",
        p2p_c.my_info.public_key.to_string("compressed"): "C",
        p2p_d.my_info.public_key.to_string("compressed"): "D",
    }
    for pk, name in key2name.items():
        log.info("show pubkey %s=%s", name, pk.hex())

    # setup server
    p2p_a.add_server_sock(localhost, port_a, s.AF_INET)
    p2p_b.add_server_sock(localhost, port_b, s.AF_INET)
    p2p_c.add_server_sock(localhost, port_c, s.AF_INET)
    p2p_d.add_server_sock(localhost, port_d, s.AF_INET)
    log.info("STEP3 server A=%s, B=%s, C=%s D=%s",
             p2p_a.pool.socks[0], p2p_b.pool.socks[0], p2p_c.pool.socks[0], p2p_d.pool.socks[0])

    # connect
    log.info("try to connect A-B-C-D-A")
    peer_a_b = p2p_a.add_peer_by_address(localhost, port_b, p2p_b.my_info.public_key)
    peer_b_c = p2p_b.add_peer_by_address(localhost, port_c, p2p_c.my_info.public_key)
    peer_c_d = p2p_c.add_peer_by_address(localhost, port_d, p2p_d.my_info.public_key)
    peer_d_a = p2p_d.add_peer_by_address(localhost, port_a, p2p_a.my_info.public_key)
    assert peer_a_b.wait_stable(), (peer_a_b, p2p_a, p2p_b)
    assert peer_b_c.wait_stable(), (peer_b_c, p2p_b, p2p_c)
    assert peer_c_d.wait_stable(), (peer_c_d, p2p_c, p2p_d)
    assert peer_d_a.wait_stable(), (peer_d_a, p2p_d, p2p_a)

    # trace route
    log.info("trace route A to B")
    route_a_b = traceroute_network(p2p_a, p2p_b.my_info.public_key)
    for i, key in enumerate(route_a_b):
        log.info("traced result %d -> %s", i, key2name.get(key.to_string("compressed")))

    log.info("trace route A to C")
    route_a_c = traceroute_network(p2p_a, p2p_c.my_info.public_key)
    for i, key in enumerate(route_a_c):
        log.info("traced result %d -> %s", i, key2name.get(key.to_string("compressed")))

    log.info("trace route A to A")
    route_a_a = traceroute_network(p2p_a, p2p_a.my_info.public_key)
    for i, key in enumerate(route_a_a):
        log.info("traced result %d -> %s", i, key2name.get(key.to_string("compressed")))

    # close
    log.info("close")
    p2p_a.close()
    p2p_b.close()
    p2p_c.close()
    p2p_d.close()
