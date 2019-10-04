from asyncio.streams import StreamReader, StreamWriter
from logging import getLogger
from time import time
from typing import Dict
from collections import deque
import asyncio


log = getLogger(__name__)


class UserHeader(object):
    """user shared data on network"""
    __slots__ = (
        "name",  # (str) Name randomly chosen by name_list.txt
        "client_ver",  # (str) __version__ of __init__.py
        "network_ver",  # (int) Random number assigned to each P2P net
        "my_host_name",  # (str) user's optional hostname (higher priority than peername)
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
        self.my_host_name: str = kwargs.get('my_host_name')
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
            'my_host_name': self.my_host_name,
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
        "direction",  # (str) We are as server or client side
        "neers",  # ({host_port: header})  Neer clients info
        "score",  # (int )User score
        "warn",  # (int) User warning score
        "create_time",  # (int) User object creation time
        "process_time",  # list of time used for process
    )

    def __init__(self, header, number, reader, writer, host_port, aeskey, direction):
        self.header: UserHeader = header
        self.number = number
        self._reader: StreamReader = reader
        self._writer: StreamWriter = writer
        self.host_port = host_port
        self.aeskey = aeskey
        self.direction = direction
        self.neers: Dict[(str, int), UserHeader] = dict()
        # user experience
        self.score = 0
        self.warn = 0
        self.create_time = int(time())
        self.process_time = deque(maxlen=10)

    def __repr__(self):
        age = (int(time()) - self.header.start_time) // 60
        passed = (int(time()) - self.create_time) // 60
        host_port = self.host_port[0] + ":" + str(self.header.p2p_port)
        if self.closed:
            status = 'close'
        else:
            status = 'open'
        return f"<User {self.header.name} {status} {passed}/{age}m ({host_port}) {self.score}/{self.warn}>"

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
            'number': self.number,
            'object': repr(self),
            'header': self.header.getinfo(),
            'neers': [stringify_host_port(*host_port) for host_port in self.neers.keys()],
            'host_port': stringify_host_port(*self.get_host_port()),
            'direction': self.direction,
            'score': self.score,
            'warn': self.warn,
            'average_process_time': self.average_process_time(),
        }

    def get_host_port(self) -> tuple:
        # connection先
        host_port = list(self.host_port)
        if self.header.my_host_name:
            host_port[0] = self.header.my_host_name
        host_port[1] = self.header.p2p_port
        return tuple(host_port)

    def update_neers(self, items):
        # [[(host,port), header],..]
        for host_port, header in items:
            self.neers[tuple(host_port)] = UserHeader(**header)

    def average_process_time(self):
        if len(self.process_time) == 0:
            return None
        else:
            return sum(self.process_time) / len(self.process_time)


def stringify_host_port(*args):
    if len(args) == 2:
        return "{}:{}".format(args[0], args[1])
    elif len(args) == 4:
        return "[{}]:{}".format(args[0], args[1])
    else:
        return str(args)


__all__ = [
    "UserHeader",
    "User",
]
