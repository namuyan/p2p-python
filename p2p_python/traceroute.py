from p2p_python.sockpool import Sock
from p2p_python.tools import *
from typing import TYPE_CHECKING, List, Tuple
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from ecdsa.keys import VerifyingKey
from hashlib import sha256
from io import BytesIO
import random
import logging


log = logging.getLogger(__name__)
DEFAULT_VERSION = 1

if TYPE_CHECKING:
    from p2p_python.peer2peer import Peer2Peer


class TracerouteCmd(CmdThreadBase):
    """
    trace p2p network public key route

    * input: nonce + src_pk(RSA) + dest_pk(ECDSA) + hop
    * output: List[VerifyingKey]
    """
    cmd = InnerCmd.REQUEST_TRACEROUTE

    @staticmethod
    def encode(nonce: bytes, src_pk: RSA.RsaKey, dest_pk: VerifyingKey, hop: int) -> bytes:  # type: ignore
        assert len(nonce) == 32, ("nonce is 32bytes", nonce.hex())
        assert hop < 30, ("hop is too large", hop)
        assert not src_pk.has_private(), ("RSA key is public", src_pk)
        io = BytesIO()
        io.write(len(nonce).to_bytes(4, "big"))
        io.write(nonce)
        src_pk_bytes = src_pk.export_key("DER")
        io.write(len(src_pk_bytes).to_bytes(4, "big"))
        io.write(src_pk_bytes)
        dest_pk_bytes = dest_pk.to_string()
        io.write(len(dest_pk_bytes).to_bytes(4, "big"))
        io.write(dest_pk_bytes)
        io.write(hop.to_bytes(4, "big"))
        return io.getvalue()

    @staticmethod
    def decode(io: BytesIO) -> List[Tuple[bytes, bytes]]:
        """decrypt by RSA key"""
        keys = list()
        while io.tell() < len(io.getbuffer()):
            length = int.from_bytes(io.read(4), "big")
            enc_pk = io.read(length)
            length = int.from_bytes(io.read(4), "big")
            enc_sign = io.read(length)
            keys.append((enc_pk, enc_sign))
        return keys

    @staticmethod
    def encrypt_pubkey(p2p: 'Peer2Peer', pk: RSA.RsaKey, nonce: bytes) -> bytes:
        """encrypt my pubkey by RSA"""
        pk_bytes = p2p.my_info.public_key.to_string()
        pk_enc = PKCS1_OAEP.new(pk).encrypt(pk_bytes)
        sign: bytes = p2p.pool.secret_key.sign(nonce, hashfunc=sha256)
        sign_enc = PKCS1_OAEP.new(pk).encrypt(sign)
        return len(pk_enc).to_bytes(4, "big") + pk_enc + len(sign_enc).to_bytes(4, "big") + sign_enc

    @staticmethod
    def thread(res_fnc: _ResponseFuc, body: bytes, sock: 'Sock', p2p: 'Peer2Peer') -> bytes:
        # decode
        io = BytesIO(body)
        nonce_len = int.from_bytes(io.read(4), "big")
        nonce = io.read(nonce_len)
        src_pk_len = int.from_bytes(io.read(4), "big")
        src_pk = RSA.import_key(io.read(src_pk_len))
        dst_pk_len = int.from_bytes(io.read(4), "big")
        dst_pk = VerifyingKey.from_string(io.read(dst_pk_len), curve=CURVE)
        hop = int.from_bytes(io.read(4), "big")
        assert hop < 30, ("hop is too large", hop)

        # hop limit
        if hop < 1:
            raise ConnectionRefusedError("hop limit reached")

        # encrypt pubkey in another thread
        fut = executor.submit(TracerouteCmd.encrypt_pubkey, p2p, src_pk, nonce)

        # check I'm is dest
        if dst_pk == p2p.my_info.public_key:
            return fut.result(20.0)

        # check neers is dest
        for peer in p2p.peers:
            if peer.info.public_key == dst_pk:
                body = TracerouteCmd.encode(nonce, src_pk, dst_pk, hop - 1)
                response, _sock = p2p.throw_command(peer, InnerCmd.REQUEST_TRACEROUTE, body)
                return fut.result(20.0) + response

        # get random next hop peer
        peers = p2p.peers.copy()
        random.shuffle(peers)
        for next_peer in peers:
            if not next_peer.is_stable():
                continue  # skip unstable
            elif sock in next_peer.socks:
                continue  # skip origin of cmd sender
            else:
                # success to get random next node
                try:
                    body = TracerouteCmd.encode(nonce, src_pk, dst_pk, hop - 1)
                    response, _sock = p2p.throw_command(next_peer, InnerCmd.REQUEST_TRACEROUTE, body)
                    return fut.result(20.0) + response
                except ConnectionError as e:
                    log.debug(f"failed to traceroute next peer peer={next_peer} by {e}")
                    continue
        else:
            raise Exception("not found next hop peer")


def traceroute_network(p2p: 'Peer2Peer', dest_pk: VerifyingKey) -> List[VerifyingKey]:
    """"""
    # generate temporary RSA key
    nonce = get_random_bytes(32)
    src_tmp_sk = RSA.generate(2048)
    src_tmp_pk = src_tmp_sk.publickey()
    log.debug(f"traceroute start nonce={nonce.hex()} dest={dest_pk}")

    # trow work
    peer = p2p.get_random_peer()
    assert peer is not None, "not found stable peer"
    body = TracerouteCmd.encode(nonce, src_tmp_pk, dest_pk, random.randint(8, 12))
    response, _sock = p2p.throw_command(peer, InnerCmd.REQUEST_TRACEROUTE, body)
    enc_keys = TracerouteCmd.decode(BytesIO(response))
    log.debug(f"traceroute success len={len(enc_keys)}")

    # decrypt route keys
    cipher = PKCS1_OAEP.new(src_tmp_sk)
    route = list()
    for enc_key, enc_sign in enc_keys:
        pk = VerifyingKey.from_string(cipher.decrypt(enc_key), curve=CURVE)
        sign = cipher.decrypt(enc_sign)
        assert pk.verify(sign, nonce, hashfunc=sha256), ("verify failed", pk)
        route.append(pk)
    assert 0 < len(route), ("route is too short", route)
    assert route[-1] == dest_pk, ("ordered neer to far", route, dest_pk)
    return route


__all__ = [
    "TracerouteCmd",
    "traceroute_network",
]
