from p2p_python.tools import *
from p2p_python.sockpool import *
from p2p_python.bloomfilter import BloomFilter
from typing import TYPE_CHECKING, List, Tuple
from io import BytesIO

if TYPE_CHECKING:
    from p2p_python.peer2peer import Peer2Peer


class AskNeersCmd(CmdThreadBase):
    """
    get all peer infos of a specified peer

    * input: None
    * output: PeerInfo0 + PeerInfo1 + ... + BloomFilter
    """
    cmd = InnerCmd.REQUEST_ASK_NEERS

    @staticmethod
    def encode() -> bytes:  # type: ignore
        return b""

    @staticmethod
    def decode(io: BytesIO) -> Tuple[List[PeerInfo], BloomFilter]:  # type: ignore
        peers = list()
        length = int.from_bytes(io.read(4), "big")
        for _ in range(length):
            peers.append(PeerInfo.from_bytes(io))
        bloom = BloomFilter.restore(io)
        return peers, bloom

    @staticmethod
    def thread(_res_fnc: _ResponseFuc, _body: bytes, _sock: Sock, p2p: 'Peer2Peer') -> bytes:
        io = BytesIO()
        io.write(len(p2p.peers).to_bytes(4, "big"))
        for peer in p2p.peers:
            peer.info.to_bytes(io)
        p2p.my_bloom.export(io)
        return io.getvalue()


class PeerInfoCmd(CmdThreadBase):
    cmd = InnerCmd.REQUEST_PEER_INFO

    @staticmethod
    def encode() -> bytes:  # type: ignore
        return b""

    @staticmethod
    def decode(io: BytesIO) -> PeerInfo:  # type: ignore
        return PeerInfo.from_bytes(io)

    @staticmethod
    def thread(res_fnc: _ResponseFuc, body: bytes, sock: 'Sock', p2p: 'Peer2Peer') -> bytes:
        io = BytesIO()
        p2p.my_info.to_bytes(io)
        return io.getvalue()


__all__ = [
    "AskNeersCmd",
    "PeerInfoCmd",
]
