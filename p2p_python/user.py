from threading import Lock
from time import time


class User(object):
    __slots__ = (
        "name",  # (str) Name randomly chosen by name_list.txt
        "client_ver",  # (str) __version__ of __init__.py
        "network_ver",  # (int) Random number assigned to each P2P net
        "p2p_accept",  # (bool) flag of accept TCP connection
        "p2p_udp_accept",  # (bool) flag of accept UDP packet
        "p2p_port",  # (int) P2P port
        "start_time",  # (int) start UNIX time
        "number",  # (int) unique number assigned to each User object
        "sock",  # (socket) TCP socket object
        "host_port",  # ([str, int])  Interface used on our PC
        "aeskey",  # (str) Common key
        "sock_type",  # (str) We are as server or client side
        "neers",  # ({host_port: header})  Neer clients info
        "score",  # (int )User score
        "warn",  # (int) User warning score
        "last_seen",  # (int) last time we get socket data
        "_lock",  # (Lock) socket lock object
    )

    def __init__(self, number, sock, host_port, aeskey, sock_type):
        self.number = number
        self.sock = sock
        self.host_port = host_port
        self.aeskey = aeskey
        self.sock_type = sock_type
        self.neers = dict()
        # user experience
        self.score = 0
        self.warn = 0
        self.last_seen = int(time())
        self._lock = Lock()

    def __repr__(self):
        return "<User {} {}s {} score={} warn={}>".format(
            self.name,
            int(time()) - self.start_time, (self.host_port[0], self.p2p_port), self.score, self.warn)

    def __del__(self):
        self.close()

    def close(self):
        try:
            self.sock.close()
        except Exception as e:
            pass

    def send(self, msg):
        with self._lock:
            self.sock.sendall(msg)

    def getinfo(self):
        r = {
            'header': self.serialize(),
            'neers': self.neers,
            'number': self.number,
            'sock': str(self.sock),
            'host_port': self.host_port,
            'aeskey': self.aeskey,
            'sock_type': self.sock_type,
            'score': self.score,
            'warn': self.warn
        }
        return r

    def serialize(self):
        return {
            'name': self.name,
            'client_ver': self.client_ver,
            'network_ver': self.network_ver,
            'p2p_accept': self.p2p_accept,
            'p2p_udp_accept': self.p2p_udp_accept,
            'p2p_port': self.p2p_port,
            'start_time': self.start_time,
            'last_seen': self.last_seen
        }

    def deserialize(self, s):
        self.name = s['name']
        self.client_ver = s['client_ver']
        self.network_ver = s['network_ver']
        self.p2p_accept = s['p2p_accept']
        self.p2p_udp_accept = s.get('p2p_udp_accept', False)
        self.p2p_port = s['p2p_port']
        self.start_time = s['start_time']
        self.last_seen = s.get('last_seen', self.last_seen)

    def get_host_port(self) -> (str, int):
        # connection先
        host_port = list(self.host_port)
        host_port[1] = self.p2p_port
        return tuple(host_port)

    def update_neers(self, items):
        # [[(host,port), header],..]
        for host_port, header in items:
            self.neers[tuple(host_port)] = header


__all__ = [
    "User",
]
