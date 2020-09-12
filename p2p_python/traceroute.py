from p2p_python.sockpool import Sock
from p2p_python.tools import *
from typing import TYPE_CHECKING, List
from Cryptodome.Random import get_random_bytes
from ecdsa.keys import SigningKey, VerifyingKey
from hashlib import sha256
from io import BytesIO
from time import time
import random
import logging


log = logging.getLogger(__name__)


if TYPE_CHECKING:
    from p2p_python.peer2peer import Peer2Peer


class TracerouteCmd(CmdThreadBase):
    """
    trace p2p network public key route

    * input: nonce + src_tmp_pk + dest_pk + hop
    * output: List[VerifyingKey]
    """
    cmd = InnerCmd.REQUEST_TRACEROUTE

    @staticmethod
    def encode(nonce: bytes, src_tmp_pk: VerifyingKey, dest_pk: VerifyingKey, hop: int) -> bytes:  # type: ignore
        assert len(nonce) == 32, ("nonce is 32bytes", nonce.hex())
        assert hop < 30, ("hop is too large", hop)
        io = BytesIO()
        io.write(len(nonce).to_bytes(4, "big"))
        io.write(nonce)
        pubkey_to_bytes(src_tmp_pk, io)
        pubkey_to_bytes(dest_pk, io)
        io.write(hop.to_bytes(4, "big"))
        return io.getvalue()

    @staticmethod
    def decode(io: BytesIO, nonce: bytes, tmp_sk: SigningKey) -> List[VerifyingKey]:  # type: ignore
        keys = list()
        while io.tell() < len(io.getbuffer()):
            pk = VerifyingKey.from_string(decrypt_by_secret(tmp_sk, io), CURVE)
            sign = decrypt_by_secret(tmp_sk, io)
            # verify you are the real owner or raise BadSignatureError
            pk.verify(sign, nonce, sha256)
            # ordered neer to far
            keys.append(pk)
        return keys

    @staticmethod
    def encrypt_pubkey(p2p: 'Peer2Peer', tmp_pk: VerifyingKey, nonce: bytes) -> bytes:
        """encrypt my pubkey and sign of nonce"""
        my_pk = p2p.my_info.public_key.to_string()
        sign: bytes = p2p.pool.secret_key.sign(nonce, hashfunc=sha256)
        return encrypt_by_public(tmp_pk, my_pk) + encrypt_by_public(tmp_pk, sign)

    @staticmethod
    def thread(res_fnc: _ResponseFuc, body: bytes, sock: 'Sock', p2p: 'Peer2Peer') -> bytes:
        # decode
        io = BytesIO(body)
        nonce_len = int.from_bytes(io.read(4), "big")
        nonce = io.read(nonce_len)
        src_tmp_pk = pubkey_from_bytes(io)
        dst_pk = pubkey_from_bytes(io)
        hop = int.from_bytes(io.read(4), "big")
        assert hop < 30, ("hop is too large", hop)

        # encrypt pubkey in another thread
        fut = executor.submit(TracerouteCmd.encrypt_pubkey, p2p, src_tmp_pk, nonce)

        # check I'm is dest
        if dst_pk == p2p.my_info.public_key:
            return fut.result(20.0)

        # check neers is dest
        for peer in p2p.peers:
            if peer.info.public_key == dst_pk:
                body = TracerouteCmd.encode(nonce, src_tmp_pk, dst_pk, hop - 1)
                response, _sock = p2p.throw_command(peer, InnerCmd.REQUEST_TRACEROUTE, body, responsible=sock)
                return fut.result(20.0) + response

        # hop limit
        if hop == 0:
            raise p2p.penalty_error(sock, 1, "hop limit reached")

        # get random next hop peer
        peers = p2p.peers.copy()
        random.shuffle(peers)
        now = time()
        tried = 0
        for next_peer in peers:
            if 20.0 < time() - now:
                raise ConnectionAbortedError("timeout on checking peers")
            elif not next_peer.is_stable():
                continue  # skip unstable
            elif sock in next_peer.socks:
                continue  # skip origin of cmd sender
            else:
                # success to get random next node
                tried += 1
                try:
                    body = TracerouteCmd.encode(nonce, src_tmp_pk, dst_pk, hop - 1)
                    response, _sock = p2p.throw_command(next_peer, InnerCmd.REQUEST_TRACEROUTE, body, responsible=sock)
                    return fut.result(20.0) + response
                except ConnectionError as e:
                    log.debug(f"failed to traceroute next peer hop={hop} peer={next_peer} by {e}")
                    continue
        else:
            raise ConnectionAbortedError(f"not found next hop peer tried={tried} all={len(peers)}")


def traceroute_network(p2p: 'Peer2Peer', dest_pk: VerifyingKey) -> List[VerifyingKey]:
    """throw traceroute commands and get """
    nonce = get_random_bytes(32)
    src_tmp_sk = SigningKey.generate(CURVE, hashfunc=sha256)
    src_tmp_pk = src_tmp_sk.get_verifying_key()
    log.debug(f"traceroute start nonce={nonce.hex()} dest={dest_pk}")

    # trow work
    peers = p2p.peers.copy()
    random.shuffle(peers)
    for peer in peers:
        if not peer.is_stable():
            continue
        body = TracerouteCmd.encode(nonce, src_tmp_pk, dest_pk, random.randint(8, 12))
        try:
            response, _sock = p2p.throw_command(peer, InnerCmd.REQUEST_TRACEROUTE, body)
            route = TracerouteCmd.decode(BytesIO(response), nonce, src_tmp_sk)
            log.debug(f"traceroute success len={len(route)}")
            break
        except ConnectionError as e:
            log.debug(f"failed traceroute by {e}")
    else:
        raise ConnectionAbortedError("not found stable peer")

    # check
    assert 0 < len(route), ("route is too short", route)
    assert route[-1] == dest_pk, ("destination is wrong pubkey", route[-1], dest_pk)
    return route


__all__ = [
    "TracerouteCmd",
    "traceroute_network",
]
