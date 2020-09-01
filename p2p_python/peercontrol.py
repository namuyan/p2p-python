from p2p_python.tools import *
from p2p_python.sockpool import *
from typing import TYPE_CHECKING, List
from io import BytesIO

if TYPE_CHECKING:
    from p2p_python.peer2peer import Peer2Peer


class AskNeersCmd(CmdThreadBase):
    """
    get all peer info connected specified a peer

    * input: None
    * output: PeerInfo + PeerInfo + ...
    """
    cmd = InnerCmd.REQUEST_ASK_NEERS

    @staticmethod
    def encode() -> bytes:  # type: ignore
        return b""

    @staticmethod
    def decode(io: BytesIO) -> List[PeerInfo]:
        peers = list()
        while io.tell() < len(io.getbuffer()):
            peers.append(PeerInfo.from_bytes(io))
        assert len(io.getbuffer()) == io.tell(), (len(io.getbuffer()), io.tell())
        return peers

    @staticmethod
    def thread(_res_fnc: _ResponseFuc, _body: bytes, _sock: Sock, p2p: 'Peer2Peer') -> bytes:
        io = BytesIO()
        for peer in p2p.peers:
            peer.info.to_bytes(io)
        return io.getvalue()


class PeerInfoCmd(CmdThreadBase):
    cmd = InnerCmd.REQUEST_PEER_INFO

    @staticmethod
    def encode() -> bytes:  # type: ignore
        return b""

    @staticmethod
    def decode(io: BytesIO) -> PeerInfo:
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
