from time import time
import socket
from threading import Lock


class User:
    __slots__ = ("name", "client_ver", "network_ver", "p2p_accept", "p2p_udp_accept", "p2p_port",
                 "start_time", "number", "sock", "host_port", "aeskey", "sock_type", "neers", "score", "warn",
                 "last_seen", "lock")

    def __init__(self, number, sock, host_port, aeskey, sock_type):
        self.name = None
        self.client_ver = None
        self.network_ver = None
        self.p2p_accept = None
        self.p2p_udp_accept = None
        self.p2p_port = None
        self.start_time = None
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
        self.lock = Lock()

    def __repr__(self):
        return "<User {} {}s {} score={} warn={}>".format(
            self.name,
            int(time()) - self.start_time, (self.host_port[0], self.p2p_port), self.score, self.warn)

    def __del__(self):
        self.close()

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            pass
        try:
            self.sock.close()
        except Exception as e:
            pass

    def send(self, msg):
        with self.lock:
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
        r = {
            'name': self.name,
            'client_ver': self.client_ver,
            'network_ver': self.network_ver,
            'p2p_accept': self.p2p_accept,
            'p2p_udp_accept': self.p2p_udp_accept,
            'p2p_port': self.p2p_port,
            'start_time': self.start_time,
            'last_seen': self.last_seen
        }
        return r

    def deserialize(self, s):
        self.name = s['name']
        self.client_ver = s['client_ver']
        self.network_ver = s['network_ver']
        self.p2p_accept = s['p2p_accept']
        self.p2p_udp_accept = s.get('p2p_udp_accept', False)
        self.p2p_port = s['p2p_port']
        self.start_time = s['start_time']
        self.last_seen = s.get('last_seen', self.last_seen)

    def get_host_port(self):
        # connection先
        host_port = list(self.host_port)
        host_port[1] = self.p2p_port
        return tuple(host_port)

    def update_neers(self, items):
        # [[(host,port), header],..]
        for host_port, header in items:
            self.neers[tuple(host_port)] = header
