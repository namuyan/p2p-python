from asyncio.streams import StreamReader, StreamWriter
from logging import getLogger
from time import time
from typing import Dict
import asyncio


log = getLogger(__name__)


class UserHeader(object):
    """user shared data on network"""
    __slots__ = (
        "name",  # (str) Name randomly chosen by name_list.txt
        "client_ver",  # (str) __version__ of __init__.py
        "network_ver",  # (int) Random number assigned to each P2P net
        "p2p_accept",  # (bool) flag of accept TCP connection
        "p2p_udp_accept",  # (bool) flag of accept UDP packet
        "p2p_port",  # (int) P2P port
        "start_time",  # (int) start UNIX time
        "last_seen",  # (int) last time we get socket data
    )

    def __init__(self, **kwargs):
        self.name: str = kwargs['name']
        self.client_ver: int = kwargs['client_ver']
        self.network_ver: int = kwargs['network_ver']
        self.p2p_accept: bool = kwargs['p2p_accept']
        self.p2p_udp_accept: bool = kwargs['p2p_udp_accept']
        self.p2p_port: int = kwargs['p2p_port']
        self.start_time: int = kwargs['start_time']
        self.last_seen = kwargs.get('last_seen', int(time()))

    def __repr__(self):
        return f"<UserHeader {self.name} {self.start_time}>"

    def getinfo(self):
        return {
            'name': self.name,
            'client_ver': self.client_ver,
            'network_ver': self.network_ver,
            'p2p_accept': self.p2p_accept,
            'p2p_udp_accept': self.p2p_udp_accept,
            'p2p_port': self.p2p_port,
            'start_time': self.start_time,
            'last_seen': self.last_seen,
        }

    def update_last_seen(self):
        self.last_seen = int(time())


class User(object):
    __slots__ = (
        "header",  # (UserHeader)
        "number",  # (int) unique number assigned to each User object
        "_reader",  # (StreamReader) TCP socket reader
        "_writer",  # (StreamWriter) TCP socket writer
        "host_port",  # ([str, int])  Interface used on our PC
        "aeskey",  # (str) Common key
        "sock_type",  # (str) We are as server or client side
        "neers",  # ({host_port: header})  Neer clients info
        "score",  # (int )User score
        "warn",  # (int) User warning score
        "event",  # (Event) user event object used for PingPong
    )

    def __init__(self, header, number, reader, writer, host_port, aeskey, sock_type):
        self.header: UserHeader = header
        self.number = number
        self._reader: StreamReader = reader
        self._writer: StreamWriter = writer
        self.host_port = host_port
        self.aeskey = aeskey
        self.sock_type = sock_type
        self.neers: Dict[(str, int), UserHeader] = dict()
        # user experience
        self.score = 0
        self.warn = 0
        self.event = asyncio.Event()

    def __repr__(self):
        age = int(time()) - self.header.start_time
        host_port = self.host_port[0] + ":" + str(self.header.p2p_port)
        if self.closed:
            status = 'close'
        elif not self.event.is_set():
            status = 'ping..'
        else:
            status = 'open'
        return f"<User {self.header.name} {status} {age//60}m {host_port} {self.score}/{self.warn}>"

    def __del__(self):
        self.close()

    @property
    def closed(self):
        return self._writer.transport.is_closing()

    def close(self):
        if not self.closed:
            self._writer.close()

    async def send(self, msg):
        self._writer.write(msg)
        await self._writer.drain()

    async def recv(self, timeout=1.0):
        return await asyncio.wait_for(self._reader.read(8192), timeout)

    def getinfo(self):
        return {
            'header': self.header.getinfo(),
            'neers': {"{}:{}".format(*host_port): header.getinfo() for host_port, header in self.neers.items()},
            'number': self.number,
            'host_port': self.get_host_port(),
            'sock_type': self.sock_type,
            'score': self.score,
            'warn': self.warn,
        }

    def get_host_port(self) -> tuple:
        # connection先
        host_port = list(self.host_port)
        host_port[1] = self.header.p2p_port
        return tuple(host_port)

    def update_neers(self, items):
        # [[(host,port), header],..]
        for host_port, header in items:
            self.neers[tuple(host_port)] = UserHeader(**header)


__all__ = [
    "UserHeader",
    "User",
]
