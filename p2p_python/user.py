from threading import Lock
from time import time
from typing import Dict


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
        "sock",  # (socket) TCP socket object
        "host_port",  # ([str, int])  Interface used on our PC
        "aeskey",  # (str) Common key
        "sock_type",  # (str) We are as server or client side
        "neers",  # ({host_port: header})  Neer clients info
        "score",  # (int )User score
        "warn",  # (int) User warning score
        "_lock",  # (Lock) socket lock object
    )

    def __init__(self, header, number, sock, host_port, aeskey, sock_type):
        self.header: UserHeader = header
        self.number = number
        self.sock = sock
        self.host_port = host_port
        self.aeskey = aeskey
        self.sock_type = sock_type
        self.neers: Dict[(str, int), UserHeader] = dict()
        # user experience
        self.score = 0
        self.warn = 0
        self._lock = Lock()

    def __repr__(self):
        age = int(time()) - self.header.start_time
        return f"<User {self.header.name} {age//60}m {self.get_host_port()} {self.score}/{self.warn}>"

    def __del__(self):
        self.close()

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def send(self, msg):
        with self._lock:
            self.sock.sendall(msg)

    def getinfo(self):
        return {
            'header': self.header.getinfo(),
            'neers': {"{}:{}".format(*host_port): header.getinfo() for host_port, header in self.neers.items()},
            'number': self.number,
            'sock': str(self.sock),
            'host_port': self.host_port,
            'aeskey': self.aeskey,
            'sock_type': self.sock_type,
            'score': self.score,
            'warn': self.warn,
        }

    def get_host_port(self) -> (str, int):
        # connection先
        return self.host_port[0], self.header.p2p_port

    def update_neers(self, items):
        # [[(host,port), header],..]
        for host_port, header in items:
            self.neers[tuple(host_port)] = header


__all__ = [
    "UserHeader",
    "User",
]
