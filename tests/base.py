from p2p_python.sockpool import *
from p2p_python.peer2peer import *
from p2p_python.tools import *
from ipaddress import ip_address
from socket import socket
import socket as s
from time import sleep, time
from enum import IntEnum
import logging
import random

"""
use nosetests
====

formatter
----
https://docs.python.org/ja/3/library/logging.html#logrecord-attributes
`export NOSE_LOGFORMAT=[%(levelname)-6s %(created)d %(threadName)-10s] %(filename)s.%(funcName)s: %(message)s`
"""

log = logging.getLogger(__name__)


def printer1(body: bytes, sock: Sock) -> None:
    log.info("print: %s `%s`", sock, body.decode(errors="ignore"))


def printer2(_fnc: _ResponseFuc, body: bytes, sock: Sock, _p2p: Peer2Peer) -> bytes:
    log.info("print: %s `%s`", sock, body.decode(errors="ignore"))
    return b"nice word"


class TestCmd(IntEnum):
    PRINTER = 0x00


def test_sock() -> None:
    """
    1. setup pool_a and pool_b.
    2. pool_a is server and pool_b is client.
    3. connect, encrypt, validate and measure delay.
    """
    port = random.randint(10000, 30000)
    log.info("step 1 port=%d", port)
    pool_a = SockPool()
    pool_a.start()
    log.info("pool_a %s", pool_a)

    # setup server
    raw_sock = socket()
    raw_sock.bind(("127.0.0.1", port))
    raw_sock.listen(5)
    raw_sock.setblocking(False)
    pool_a.add_sock(Sock(raw_sock, printer1, SockType.SERVER, None, pool_a.secret_key))

    log.info("step 2")

    pool_b = SockPool()
    pool_b.start()

    # setup client
    raw_sock = socket()
    raw_sock.connect(("127.0.0.1", port))
    raw_sock.setblocking(False)
    pool_b.add_sock(Sock(raw_sock, printer1, SockType.OUTBOUND, None, pool_b.secret_key))

    # wait connection established
    while len(pool_a.socks) != 2:
        sleep(0.2)
    log.debug(pool_a.socks)

    log.info("step 3")

    # encryption
    client = pool_a.socks[1]
    log.info("sock_a %s", client)
    count = 10
    while client.establish_encryption(True).wait(3.0) is False:
        if client.flags & SockControl.ENCRYPTED:
            break
        else:
            log.warning("retry.. %d %s", time(), client)
        count -= 1
        assert 0 < count
    log.info("success encryption %s", client)

    log.info("step 4")

    # send data (check callback)
    # warning: this cause problem for check recover work
    client.sendall(b"hello world")

    # validation the other
    log.info("sock_a %s", client)
    count = 10
    while client.validate_the_other(True).wait(3.0) is False:
        if client.flags & SockControl.VALIDATED:
            break
        else:
            log.warning("retry.. %d %s", time(), client)
        count -= 1
        assert 0 < count
    log.info("success validation %s", client)
    assert client.flags & SockControl.VALIDATED

    assert client.others_key == pool_b.secret_key.get_verifying_key()
    log.debug("pubkey is %s", client.others_key.to_string("compressed").hex())

    log.info("step 5")

    # measure delay time
    count = 10
    while client.measure_delay_time(True).wait(3.0) is False:
        if client.stable.is_set():
            break
        else:
            log.warning("retry.. %d %s", time(), client)
        count -= 1
        assert 0 < count
    log.info("success measure delay %f", client.delay)
    assert client.stable.wait(20.0)

    log.info("step 6")

    pool_a.close()
    pool_b.close()


def test_peer2peer() -> None:
    """
    1. setup p2p_a and p2p_b
    2. p2p_a is server and p2p_b is client
    3. p2p_a connect p2p_b by TCP
    4. send cmd and receive msg
    """
    localhost = ip_address("127.0.0.1")
    port = random.randint(10000, 30000)

    log.info("step 1 port=%d", port)
    p2p_a = Peer2Peer(dict(), [FormalAddr(localhost, port)], tcp_server=True)
    p2p_b = Peer2Peer({TestCmd.PRINTER: printer2}, [])

    log.info("step 2")

    # server
    p2p_a.add_server_sock(localhost, port, s.AF_INET)

    log.info("step 3")

    # client
    peer_b = p2p_b.add_peer_by_address(localhost, port, p2p_a.my_info.public_key)
    log.info("peer_b %s", peer_b)
    log.info("peer_b sock %s", peer_b.socks)

    # wait
    count = 10
    now = time()
    while 0 == len(p2p_a.peers):
        assert 0 < count, ("timeout", p2p_a)
        sleep(0.5)
        count -= 1
    log.info("step 4 %f wait", time() - now)

    # connect
    assert 0 < len(p2p_a.peers)
    log.info("p2p_a  pk %s", p2p_a.my_info.public_key.to_string().hex())
    log.info("peer_a pk %s", p2p_a.peers[0].info.public_key.to_string().hex())
    log.info("p2p_b  pk %s", p2p_b.my_info.public_key.to_string().hex())
    log.info("peer_b pk %s", peer_b.info.public_key.to_string().hex())
    peer_a = p2p_a.get_peer_by_pubkey(p2p_b.my_info.public_key)
    assert peer_a is not None

    # execute cmd
    res, _sock = p2p_a.throw_command(peer_a, TestCmd.PRINTER, b"hello world")
    assert res == b"nice word"

    log.info("step 5")

    # close
    p2p_a.close()
    p2p_b.close()


def test_relay_connect() -> None:
    """
    1. setup A, B, C and connect A with B and B with C.
    2. A connects to C via B by srudp.
    3. request PEER_INFO cmd
    """
    port_a = random.randint(10000, 30000)
    port_b = random.randint(10000, 30000)
    port_c = random.randint(10000, 30000)
    localhost = ip_address("127.0.0.1")
    log.info("STEP1 init A=%d, B=%d, C=%d", port_a, port_b, port_c)

    p2p_a = Peer2Peer(dict(), [FormalAddr(localhost, port_a)], tcp_server=True, srudp_bound=True)
    p2p_b = Peer2Peer(dict(), [FormalAddr(localhost, port_b)], tcp_server=True, srudp_bound=True)
    p2p_c = Peer2Peer(dict(), [FormalAddr(localhost, port_c)], tcp_server=True, srudp_bound=True)
    log.info("STEP2 p2p A=%s, B=%s, C=%s", p2p_a, p2p_b, p2p_c)

    # setup server
    p2p_a.add_server_sock(localhost, port_a, s.AF_INET)
    p2p_b.add_server_sock(localhost, port_b, s.AF_INET)
    p2p_c.add_server_sock(localhost, port_c, s.AF_INET)
    log.info("STEP3 server A=%s, B=%s, C=%s", p2p_a.pool.socks[0], p2p_b.pool.socks[0], p2p_c.pool.socks[0])

    # connect A-B and B-C
    log.info("try to connect A-B and B-C")
    peer_a_b = p2p_a.add_peer_by_address(localhost, port_b, p2p_b.my_info.public_key)
    peer_b_c = p2p_b.add_peer_by_address(localhost, port_c, p2p_c.my_info.public_key)
    assert peer_a_b.wait_stable(), (peer_a_b, p2p_a, p2p_b)
    assert peer_b_c.wait_stable(), (peer_b_c, p2p_b, p2p_c)
    log.info("STEP4 connect A-B=%s, B-C=%s", peer_a_b, peer_b_c)

    # connect A-C (srudp)
    log.info("try to connect A-C")
    peer_a_c = p2p_a.add_peer_by_mediator(peer_a_b, p2p_c.my_info.public_key, s.AF_INET)
    assert peer_a_c.wait_stable(), (peer_a_c, p2p_a, p2p_c)
    log.info("STEP5 connect A-C=%s", peer_a_c)

    # send
    response, sock = p2p_a.throw_command(peer_a_c, InnerCmd.REQUEST_PEER_INFO, b"{}")
    log.info("response %s", response)
    log.info("sock %s", sock)

    # add new sock A-B as second (srudp)
    sock = p2p_a.add_client_sock(peer_a_b, s.AF_INET, True)
    assert len(peer_a_b.socks) == 2, peer_a_b.socks
    assert sock.stable.wait(20.0), sock
    log.info("srudp %s", sock)

    # close
    log.info("STEP6 close")
    p2p_a.close()
    p2p_b.close()
    p2p_c.close()
