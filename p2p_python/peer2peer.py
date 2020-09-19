from p2p_python.sockpool import *
from p2p_python.peer import *
from p2p_python.tools import *
from p2p_python.bloomfilter import BloomFilter
from p2p_python.traceroute import *
from p2p_python.peercontrol import *
from p2p_python.connectionrelay import *
from concurrent.futures import Future, TimeoutError
from threading import Lock
from typing import List, Tuple, Set, Dict, Optional, Callable
from Cryptodome.Random import get_random_bytes
from expiringdict import ExpiringDict
from ecdsa.keys import VerifyingKey
from time import time
from random import choice
from enum import IntEnum
from io import BytesIO
from srudp import SecureReliableSocket
from socket import socket
import socket as s
import logging
import random


log = logging.getLogger(__name__)


CommandFnc = Callable[[_ResponseFuc, bytes, Sock, 'Peer2Peer'], Optional[bytes]]
BAN_THRESHOLD = 100


def callback_generator(
        cmd: int,
        uuid: int,
        res_fnc: _ResponseFuc,
        result_fut: 'Future[bytes]',
) -> Callable[['Future[Optional[bytes]]'], None]:
    """"""
    def callback(fut: 'Future[Optional[bytes]]') -> None:
        status = "INCOMPLETE"
        try:
            result = fut.result()

            # success: already responded in the thread
            if result is None:
                if not result_fut.done():
                    error = f"future returned None, but don't send result yet cmd={cmd} uuid={uuid}"
                    res_fnc(_FAILED, error.encode())
                else:
                    status = "FINISHED"

        except PenaltyError as e:
            # penalty
            status = "PENALTY"
            res_fnc(_PENALTY, e.point.to_bytes(1, "big") + e.reason.encode())
        except Exception as e:
            # failed
            status = "FAIL"
            res_fnc(_FAILED, str(e).encode())
        else:
            # success
            assert isinstance(result, bytes)
            status = "SUCCESS"
            res_fnc(_SUCCESS, result)
        finally:
            log.debug(f"finished the {cmd} with {status} uuid={uuid}")

    # note: add by `fut.add_done_callback(callback)`
    return callback


def response_generator(
        sock: Sock,
        uuid_bytes: bytes,
        uuid_int: int,
        result_fut: 'Future[bytes]'
) -> _ResponseFuc:
    """"""
    def response_fnc(status: bytes, msg: bytes) -> None:
        assert len(status) == 1
        if result_fut.done():
            log.warning(f"already responded result by {sock} uuid={uuid_int}")
        else:
            response = status + uuid_bytes + msg
            result_fut.set_result(response)
            if 0 < sock.fileno():
                sock.sendall(response)
            else:
                log.debug("ignore response because socket is closed")

    return response_fnc


class Peer2Peer(object):
    def __init__(
            self,
            commands: Dict[int, CommandFnc],
            addresses: List[FormalAddr],
            secret: bytes = None,
            tcp_server: bool = False,
            srudp_bound: bool = False,
    ) -> None:
        self.peers: List[Peer] = list()
        self.commands = commands.copy()
        self.results: Dict[int, 'Future[bytes]'] = ExpiringDict(600, 600.0)
        self.works: Dict[int, 'Future[bytes]'] = ExpiringDict(600, 600.0)
        self.pool = SockPool(self._callback_accept, self._callback_close, secret)
        unexpected_addr = [addr for addr in addresses if not isinstance(addr, FormalAddr)]
        assert 0 == len(unexpected_addr), ("addresses is wrong", unexpected_addr)
        self.my_info = PeerInfo(
            addresses, self.pool.secret_key.verifying_key, tcp_server, srudp_bound)
        self.my_bloom = BloomFilter()
        self.ban_host: Set[_Host] = set()
        self.lock = Lock()
        self.update_time = time()
        self.create_time = time()
        # flags
        self.closed = False
        # init
        duplicated_cmds = set(commands) & set(InnerCmd)
        assert len(duplicated_cmds) == 0, ("duplicated cmds not allowed", duplicated_cmds)
        self.commands.update({
            InnerCmd.REQUEST_TRACEROUTE: TracerouteCmd.thread,
            InnerCmd.REQUEST_ASK_NEERS: AskNeersCmd.thread,
            InnerCmd.REQUEST_PEER_INFO: PeerInfoCmd.thread,
            InnerCmd.REQUEST_MEDIATOR: MediatorCmd.thread,
            InnerCmd.REQUEST_ASK_SRUDP: AskSrudpCmd.thread,
        })
        self.pool.start()

    def __repr__(self) -> str:
        pubkey_hex = self.my_info.public_key.to_string().hex()
        uptime = time2string(time() - self.create_time)
        return f"<P2P {pubkey_hex[:6]}..{pubkey_hex[-6:]} peer={len(self.peers)} uptime={uptime}>"

    def get_random_peer(self) -> Optional[Peer]:
        limit = 5
        while 0 < limit:
            limit -= 1
            with self.lock:
                peers = self.peers.copy()
            if len(peers) == 0:
                return None
            else:
                peer = choice(peers)
                if peer.wait_stable():
                    return peer
                else:
                    continue
        return None

    def get_peer_by_sock(self, sock: Sock) -> Optional[Peer]:
        with self.lock:
            for peer in self.peers:
                for _sock in peer.socks:
                    if sock is _sock:
                        return peer
        return None

    def get_peer_by_pubkey(self, public_key: VerifyingKey) -> Optional[Peer]:
        with self.lock:
            for peer in self.peers:
                peer_pubkey = peer.get_validated_key()
                if peer_pubkey and peer_pubkey == public_key:
                    return peer
        return None

    def add_server_sock(self, host: _Host, port: int, family: s.AddressFamily) -> None:
        """add new server TCP sock and ipv4 or ipv6"""
        address: _Address
        if host.version == 4:
            address = str(host), port
        else:
            address = str(host), port, 0, 0
        sock = socket(family, s.SOCK_STREAM)
        sock.bind(address)
        sock.listen(10)
        sock.settimeout(0.0)
        server = Sock(sock, self._callback_recv, SockType.SERVER, None, self.pool.secret_key)
        self.pool.add_sock(server)

    def add_client_sock(self, peer: Peer, family: s.AddressFamily, is_srudp: bool) -> Sock:
        """add new sock to peer and ipv4 or ipv6"""
        connected = peer.get_sock(family, is_srudp)
        assert connected is None, f"already connected {connected} {family} {peer}"
        address = peer.get_connect_address(family)
        assert address is not None, f"can't get new destination {family} {peer}"
        others_key = peer.get_validated_key()
        assert others_key is not None, f"not found validated sock in peer {peer}"

        if is_srudp:
            # check socket family
            assert 0 < len(self.my_info.addresses), self.my_info
            my_address = self.my_info.addresses[0]

            # request srudp connect
            new_addr = FormalAddr(my_address.host, random.randint(1024, 65535))
            body = AskSrudpCmd.encode(self.my_info, new_addr)
            response, _sock = self.throw_command(peer, InnerCmd.REQUEST_ASK_SRUDP, body)
            dest_info, dest_addr = AskSrudpCmd.decode(BytesIO(response))

            # check
            assert dest_addr.host.version == my_address.host.version, (dest_addr, my_address)

            # connect
            sock = SecureReliableSocket(family)
            sock.connect(new_addr)

        else:
            # connect
            sock = socket(family, s.SOCK_STREAM)
            sock.connect(address.to_address())

        # add pool
        sock.settimeout(0.0)
        client = Sock(sock, self._callback_recv, SockType.OUTBOUND, others_key, self.pool.secret_key)
        self.pool.add_sock(client)
        peer.socks.append(client)

        # note: sock's flag will be updated by INBOUND
        # note: wait for sock stabled by `client.stable.wait(20.0)`
        return client

    def add_peer_by_mediator(self, mediator: Peer, dest_pubkey: VerifyingKey, family: s.AddressFamily) -> Peer:
        """connect via intermediate node by srudp"""
        # check already known pubkey
        dest_peer = self.get_peer_by_pubkey(dest_pubkey)
        assert dest_peer is None, "already connected"

        # get my address
        assert 0 < len(self.my_info.addresses), ("we have no address", self.my_info)
        family_ver = 4 if family == s.AF_INET else 6
        for my_address in self.my_info.addresses:
            if my_address.host.version == family_ver:
                # select random port number by issuer
                issuer_addr = FormalAddr(my_address.host, random.randint(1024, 65535))
                break
        else:
            raise AssertionError(f"request family is {family_ver} but not found in my_info")

        # request intermediate work
        body = MediatorCmd.encode(self.my_info, issuer_addr, dest_pubkey)
        response, _sock = self.throw_command(mediator, InnerCmd.REQUEST_MEDIATOR, body)
        dest_info, dest_addr = MediatorCmd.decode(BytesIO(response))

        # check
        assert my_address.host.is_loopback is dest_addr.host.is_loopback, \
            ("contamination of local with global not allowed", my_address, dest_addr)
        assert my_address.host.version == dest_addr.host.version, (my_address, dest_addr)

        # try to connect
        raw_sock = SecureReliableSocket(s.AF_INET if family_ver == 4 else s.AF_INET6)
        raw_sock.connect(dest_addr.to_address())

        # create sock
        raw_sock.settimeout(0.0)
        sock = Sock(raw_sock, self._callback_recv, SockType.OUTBOUND, dest_pubkey, self.pool.secret_key)
        self.pool.add_sock(sock)

        # create peer
        dest_peer = Peer(dest_info)
        dest_peer.socks.append(sock)

        # success
        self.peers.append(dest_peer)
        if sock.stable.wait(20.0) is False:
            log.warning(f"wait for {sock} of {dest_peer} stabled but timeout")
        return dest_peer

    def add_peer_by_address(self, host: _Host, port: int, public_key: VerifyingKey) -> Peer:
        """connect to direct address by TCP"""
        # check known address (instead use add_client_sock)
        address = FormalAddr(host, port)
        for peer in self.peers:
            assert address not in peer.info.addresses, (address, peer.info.addresses)

        # connect
        raw_sock = socket(s.AF_INET if address.host.version == 4 else s.AF_INET6)
        raw_sock.connect(address.to_address())

        # sock
        raw_sock.settimeout(0.0)
        sock = Sock(raw_sock, self._callback_recv, SockType.OUTBOUND, public_key, self.pool.secret_key)
        self.pool.add_sock(sock)

        # peer (dummy info)
        peer = Peer(PeerInfo(list(), public_key, False, False))
        peer.socks.append(sock)
        self.peers.append(peer)

        # wait to be stabled
        if sock.stable.wait(20.0) is False:
            log.warning(f"timeout on waiting for {sock} of {peer}")

        # update peer info
        response, _sock = self.throw_command(peer, InnerCmd.REQUEST_PEER_INFO, b"")
        peer.info = PeerInfo.from_bytes(BytesIO(response))

        # success
        return peer

    def update_peer_info(self, peer: Peer) -> None:
        """update peer's neers and bloom filter"""
        assert peer.wait_stable(), ("wait stable but timeout", peer)
        response, _sock = self.throw_command(peer, InnerCmd.REQUEST_ASK_NEERS, b"")
        neers, bloom = AskNeersCmd.decode(BytesIO(response))
        peer.neers = neers
        # from peer's point of view, it's Layer 0,1,2,
        # but from node's point of view, it's Layer1,2,3
        peer.bloom = bloom
        peer.update_time = time()

    def update_bloom_filter(self) -> None:
        """update what pubkey is neer (layer 0, 1 and 2)"""
        bloom = BloomFilter()
        bloom.add(self.my_info.public_key)  # layer 0
        for peer in self.peers:
            bloom.add(peer.info.public_key)  # layer 1
            for info in peer.neers:
                bloom.add(info.public_key)  # layer 2
        self.my_bloom = bloom
        self.update_time = time()

    def close_peer(self, peer: Peer, reason: bytes) -> None:
        """graceful peer close"""
        if peer in self.peers:
            self.peers.remove(peer)

        # remove socks from pool
        for sock in peer.socks:
            self.pool.close_sock(sock, reason)
        peer.close()

    def throw_command(
            self,
            peer: Peer,
            cmd: IntEnum,
            body: bytes,
            timeout: float = 20.0,
            retry: int = 2,
            responsible: Sock = None,
            penalty: int = None,
    ) -> Tuple[bytes, Sock]:
        assert peer in self.peers, ("not found peer", peer)
        socks = peer.socks.copy()
        assert 0 < len(socks), f"no socket in the {peer}"
        assert 1.0 < timeout and 0 < retry, (timeout, retry)
        assert (responsible is None) is (penalty is None), (responsible, penalty)
        timeout /= retry

        # encode send params
        uuid_bytes = get_random_bytes(7)
        uuid_int = int.from_bytes(uuid_bytes, 'big')
        msg = cmd.to_bytes(1, 'big') + uuid_bytes + body

        # setup future
        future: 'Future[bytes]' = Future()
        with self.lock:
            self.results[uuid_int] = future

        # send data and wait for response
        punished = 0
        for num in range(1, retry + 1):
            for sock in socks:
                try:
                    if sock.fileno() < 0:
                        continue
                    sock.sendall(msg)
                    result = future.result(timeout / len(socks))
                    return result, sock
                except PenaltyError as e:
                    if responsible is not None:
                        log.warning(f"punish {responsible} {penalty}p!")
                        raise self.mark_penalty(responsible, penalty, e.reason)
                    log.warning(f"punished {e.point}p! by {peer}: {e.reason}")
                    punished = e.point
                    break
                except TimeoutError:
                    continue
            log.warning(f"retry throw_command() {num}/{retry} sock={len(socks)} uuid={uuid_int}")

        # finished but incomplete
        if 0 < punished:
            raise PenaltyError(
                punished, f"punished but no responsible sock! cmd={cmd} uuid={uuid_int} sock={len(socks)} peer={peer}")
        else:
            raise ConnectionError(
                f"timeout on throw_command() cmd={cmd} uuid={uuid_int} sock={len(socks)} peer={peer}")

    def _callback_recv(self, data: bytes, sock: Sock) -> None:
        """execute when receive msg"""
        res_fnc: _ResponseFuc = None

        # note: bit0 is cmd, bit1~7 is uuid, bit8~ is body
        cmd = data[0]
        uuid_bytes: bytes = data[1:8]
        uuid_int = int.from_bytes(uuid_bytes, 'big')
        body = data[8:]

        try:

            # 1. receive work result
            if cmd == InnerCmd.RESPONSE_PROCESSING:
                # response: processing work now (result will be sent)
                log.warning(f"{sock} says that PROCESSING work now uuid={uuid_int}")
                return
            elif cmd == InnerCmd.RESPONSE_SUCCESS:
                # response: success
                assert uuid_int in self.results, ("unknown uuid", uuid_int)
                future = self.results[uuid_int]
                if future.done():
                    log.debug(f"duplicated receive msg (success) uuid={uuid_int} body={body!r}")
                else:
                    future.set_result(body)
                return
            elif cmd == InnerCmd.RESPONSE_FAILED:
                # response: failed
                assert uuid_int in self.results, ("unknown uuid", uuid_int)
                future = self.results[uuid_int]
                if future.done():
                    log.debug(f"duplicated receive msg (failed) uuid={uuid_int} body={body!r}")
                else:
                    future.set_exception(ConnectionError(str(body)))
                return

            elif cmd == InnerCmd.RESPONSE_PENALTY:
                # response: penalty by the other
                assert uuid_int in self.results, ("unknown uuid", uuid_int)
                future = self.results[uuid_int]
                if future.done():
                    log.debug(f"duplicated receive msg (failed) uuid={uuid_int} body={body!r}")
                else:
                    future.set_exception(PenaltyError(body[0], body[1:].decode(errors="replace")))
                return

            else:
                pass

            # 2. check already requested work
            if uuid_int in self.works:
                # already known uuid
                result_fut = self.works[uuid_int]
                # resend result again or notify PROCESSING flag
                if result_fut.done():
                    sock.sendall(result_fut.result())
                else:
                    sock.sendall(_PROCESSING + uuid_bytes + b"")
                log.debug(f"{sock} will be unstable because same request received uuid={uuid_int}")
                return
            else:
                result_fut = self.works[uuid_int] = Future()
                res_fnc = response_generator(sock, uuid_bytes, uuid_int, result_fut)

            # 3. execute new work
            if cmd in self.commands:
                # request: user defined commands
                future = executor.submit(self.commands[cmd], res_fnc, body, sock, self)
                callback = callback_generator(cmd, uuid_int, res_fnc, result_fut)
                future.add_done_callback(callback)

            else:
                # request: not found command
                msg = f"unknown request cmd={cmd} uuid={uuid_int} body={body!r}"
                res_fnc(_FAILED, msg.encode())
                log.debug(msg)

        except Exception as e:
            # 4. raised exception
            if sock.fileno() == -1:
                log.debug(f"socket send error occurred uuid={uuid_int}")
            else:
                msg = f"callback_recv() exception cmd={cmd} uuid={uuid_int} e={e} body={body!r}"
                if res_fnc is None:
                    sock.sendall(_FAILED + uuid_bytes + msg.encode())
                    log.warning(msg, exc_info=True)
                else:
                    res_fnc(_FAILED, msg.encode())

    def _callback_accept(self, sock: Sock, pool: SockPool) -> None:
        """execute it when accept new TCP socket"""
        assert sock.stype == SockType.INBOUND, (sock.stype, SockType.INBOUND)
        log.debug(f"try callback_accept() {sock}")
        new_peer: Peer = None

        # check already banned host
        if sock.get_opposite_host() in self.ban_host:
            pool.close_sock(sock, b"you are already banned")
            return

        try:
            # update sock's flag
            # normal TCP connection require stream protect
            assert sock.establish_encryption(True).wait(20.0), ("encryption failed", sock)
            assert sock.validate_the_other(True).wait(20.0), ("validation failed", sock)
            assert sock.measure_delay_time(True).wait(20.0), ("measure_delay failed", sock)

            # detect which peer's public key
            assert sock.others_key is not None, "sock.others_key is None"
            peer = self.get_peer_by_pubkey(sock.others_key)

            if peer is None:
                # accept new peer by dummy info
                dummy_info = PeerInfo(list(), sock.others_key, False, False)
                new_peer = Peer(dummy_info)
                new_peer.socks.append(sock)
                self.peers.append(new_peer)

                # update peer info
                assert sock in pool.socks, (sock, pool.socks)
                response, _sock = self.throw_command(new_peer, InnerCmd.REQUEST_PEER_INFO, b"")
                new_peer.info = PeerInfo.from_bytes(BytesIO(response))
                log.debug(f"accept {new_peer}")

            else:
                # add sock to the peer
                peer.socks.append(sock)
                log.debug(f"accept {sock} to {peer}")

            # success
            return
        except AssertionError as e:
            log.debug("AssertionError %s", e)
        except ConnectionError as e:
            log.debug("ConnectionError %s", e)
        except Exception:
            log.warning("callback_accept()", exc_info=True)

        # failed
        reason = f"callback_accept() failed"
        # close sock
        self.pool.close_sock(sock, reason.encode())
        # close peer
        if new_peer is not None:
            self.close_peer(new_peer, reason.encode())
        log.debug(reason)

    def _callback_close(self, sock: Sock, _pool: SockPool) -> None:
        """execute after sock closed"""
        peer = self.get_peer_by_sock(sock)
        if peer is None:
            return
        if sock in peer.socks:
            peer.socks.remove(sock)
        if len(peer.socks) == 0:
            self.close_peer(peer, b"peer's sock is empty")

    def mark_penalty(self, sock: Sock, point: int, reason: str) -> PenaltyError:
        """add penalty score and notify punish by raise error"""
        peer = self.get_peer_by_sock(sock)
        assert peer is not None, ("unknown peer of sock", sock)
        peer.penalty += point
        if BAN_THRESHOLD < peer.penalty:
            # disconnect and BAN
            for sock in peer.socks:
                assert sock.stype != SockType.SERVER, ("sock is server type", sock)
                host = sock.get_opposite_host()
                self.ban_host.add(host)
                log.info(f"BANNED {host} of {peer}")
            self.close_peer(peer, b"too match warn pont: " + reason.encode())
        else:
            # increase warn and return FAIL response
            log.info(f"punished {peer} {point}p by '{reason}'")
        return PenaltyError(point, reason)

    def close(self) -> None:
        if self.closed is False:
            self.pool.close()
            for peer in self.peers:
                peer.close()
            self.peers.clear()
            self.closed = True


__all__ = [
    "CommandFnc",
    "Peer2Peer",
]
