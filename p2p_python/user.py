from .config import C, V, PeerToPeerError
import time


class User:
    # header
    name = None
    client_ver = None
    network_ver = None
    p2p_accept = None
    p2p_port = None
    start_time = None

    def __init__(self, number, sock, host_port, aeskey, sock_type):
        self.number = number
        self.sock = sock
        self.host_port = host_port
        self.aeskey = aeskey
        self.sock_type = sock_type
        self.neers = dict()
        self.warn = 0

    def __repr__(self):
        return "<User name={} start={}s warn={}>"\
            .format(self.name, int(time.time())-self.start_time, self.warn)

    def getinfo(self):
        r = {
            'header': self.serialize(),
            'neers': self.neers,
            'number': self.number,
            'sock': str(self.sock),
            'host_port': self.host_port,
            'aeskey': self.aeskey,
            'sock_type': self.sock_type}
        return r

    def serialize(self):
        r = {'name': self.name,
             'client_ver': self.client_ver,
             'network_ver': self.network_ver,
             'p2p_accept': self.p2p_accept,
             'p2p_port': self.p2p_port,
             'start_time': self.start_time}
        return r

    def deserialize(self, s):
        self.name = s['name']
        self.client_ver = s['client_ver']
        self.network_ver = s['network_ver']
        self.p2p_accept = s['p2p_accept']
        self.p2p_port = s['p2p_port']
        self.start_time = s['start_time']

    def get_host_port(self):
        # connection先
        return self.host_port[0], self.p2p_port

    def update_neers(self, items):
        # {(host,port): header, ..}
        self.neers = items

    def add_warn(self):
        self.warn += 1
        if self.warn > 3:
            try: self.sock.close()
            except: pass
