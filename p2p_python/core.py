#!/user/env python3
# -*- coding: utf-8 -*-

import socket
import time
import json
import random
import threading
import queue
import os
import logging
import socks
from .encryption import AESCipher, EncryptRSA
from .utils import get_here_path
from .traffic import Traffic


HEAR_PATH = get_here_path(__file__)
CLIENT_VER = next((line.split('=')[1].strip().replace("'", '')
                   for line in open(os.path.join(HEAR_PATH, '__init__.py'))
                   if line.startswith('__version__ = ')), '0.0.dev0')
NAME_LIST = open(os.path.join(HEAR_PATH, 'name_list.txt')).read().split()
MAX_RECEIVE_SIZE = 260000  # 260kBytes

# constant
SERVER_SIDE = 'Server'
CLIENT_SIDE = 'Client'
F_DEBUG = False


class Core(threading.Thread):
    number = 0
    server_sock = None
    f_tor = False  # Use tor mode, Only allowed client mode

    def __init__(self, port, net_ver, host='', cp=True, name=None, listen=10, buffsize=2048, keysize=3072):
        """
        :param port: P2P server port(int)
        :param net_ver: P2P network version(int)
        :param host: Server host(str)
        :param cp: Use zlib compress flag(bool)
        :param name: Server name(str)
        :param listen: P2P listen(int)
        :param buffsize: Socket buffer size(int)
        :param keysize: RSA key size(int)
        """
        super().__init__(name='P2P_Core', daemon=True)
        self.client = list()
        self.stream_que = queue.LifoQueue(maxsize=100)
        self.lock = threading.Lock()
        self.host = host
        self.port = port
        self.net_ver = net_ver
        self.listen = listen
        self.buffsize = buffsize
        self.name = name if name else (random.choice(NAME_LIST) + str(random.randint(10000, 99999)))
        self.header = {
            'name': self.name,
            'client_ver': CLIENT_VER,
            'network_ver': net_ver,
            'p2p_accept': False,
            'p2p_port': self.port,
            'compress': cp,
            'time': int(time.time())}
        self.keysize = keysize
        self.private_pem = None
        self.public_pem = None
        self.traffic = Traffic()
        self.traffic.start()

    def close_server(self):
        self.traffic.close()
        with self.lock:
            self.header['p2p_accept'] = False
        try:
            self.server_sock.close()
        except:
            pass

    def run(self):
        # Check tor mode
        if self.f_tor:
            raise ConnectionAbortedError('Do not use server with tor mode.')
        # Create server socket
        self.server_sock = self.create_server_sock()
        with self.lock:
            self.header['p2p_accept'] = True

        # Create public Key
        self.private_pem, self.public_pem = EncryptRSA.create_keypair(self.keysize)

        # Pooling connection
        host_port = ('', 0)
        sock = None
        logging.info("Start server %d" % self.port)
        while self.header['p2p_accept']:
            try:
                sock, host_port = self.server_sock.accept()
                sock.settimeout(10)

                received = sock.recv(self.buffsize)
                self.traffic.put_traffic_down(received)
                header = json.loads(received.decode())
                send = self.public_pem.encode()
                sock.sendall(send)
                self.traffic.put_traffic_up(send)

                threading.Thread(
                    target=self.receive_msg, name='S:' + header['name'], daemon=True,
                    args=(sock, host_port, header, None, SERVER_SIDE),
                ).start()

            except json.decoder.JSONDecodeError:
                try: sock.close()
                except: pass
                continue  # only checked by 'is_reachable()'
            except socket.timeout as e:
                logging.debug("S:Socket error %s" % e)
                continue
            except Exception as e:
                logging.debug("%s New server connection failed. %s" % (host_port, e), exc_info=F_DEBUG)
        with self.lock:
            self.header['p2p_accept'] = False

    def create_server_sock(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(self.listen)
        return server_sock

    def create_connection(self, host, port):
        try:
            host_port = (socket.gethostbyname(host), int(port))
            if self.f_tor and not self.header['p2p_accept']:
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
                sock = socks.socksocket()
            elif self.f_tor:
                return Exception('Do not run server with tor mode.')
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(host_port)

            # Send my header first
            send = json.dumps(self.header).encode()
            sock.sendall(send)
            self.traffic.put_traffic_up(send)
            # get server public key
            receive = sock.recv(self.buffsize)
            self.traffic.put_traffic_down(receive)
            public_pem = receive.decode()
            if len(public_pem) == 0:
                raise ConnectionAbortedError('received msg is zero.')
            # Send encrypted aes-key
            aes_key = AESCipher.create_key()
            encrypted = EncryptRSA.encrypt(public_pem, aes_key.encode())
            sock.sendall(encrypted)
            self.traffic.put_traffic_up(encrypted)

            threading.Thread(
                target=self.receive_msg, name='C:' + self.header['name'], daemon=True,
                args=(sock, host_port, None, aes_key, CLIENT_SIDE)
            ).start()

            c = 20
            while len(self.client) == 0 and c > 0:
                time.sleep(1)
                c -= 1
            if c == 0:
                return False
            else:
                return True
        except Exception as e:
            return False

    def remove_connection(self, client):
        if client in self.client:
            with self.lock:
                self.client.remove(client)
            number, sock, host_port, header, aes_key, sock_type = client
            try: sock.close()
            except: pass
            logging.debug("Close sock %s" % header['name'])
            return True
        else:
            return False

    def send_msg(self, msg_body, client=None):
        assert type(msg_body) == bytes, 'message should be bytes'

        # get client
        if len(self.client) == 0:
            raise ConnectionError('client connection is zero.')
        elif len(msg_body) > MAX_RECEIVE_SIZE + 1000:
            raise ConnectionRefusedError('Max message size is %sKb '
                                         '(You try %sKb)' % (MAX_RECEIVE_SIZE / 1000, len(msg_body) / 1000))
        elif client is None or client == list():
            client = random.choice(self.client)
        number, sock, host_port, header, aes_key, sock_type = client

        # send message
        cp = header['compress'] and self.header['compress']
        msg_body = AESCipher.encrypt(key=aes_key, raw=msg_body, z=cp)
        msg_len = len(msg_body).to_bytes(4, 'big')
        sock.sendall(msg_len + msg_body)
        self.traffic.put_traffic_up(msg_len + msg_body)
        logging.debug("Send %sKb to \"%s\"" % (len(msg_len + msg_body) / 1000, header['name']))
        return client

    def receive_msg(self, sock, host_port, header, aes_key, sock_type):
        try:
            if sock_type == SERVER_SIDE:
                # Get AES-KEY from client
                encrypted = sock.recv(self.buffsize)
                self.traffic.put_traffic_down(encrypted)
                if len(encrypted) == 0:
                    raise ConnectionAbortedError('received msg is zero.')
                aes_key = EncryptRSA.decrypt(self.private_pem, encrypted).decode()
                if not AESCipher.is_aes_key(aes_key):
                    raise ConnectionAbortedError('Not correct AES key length.')
                send = json.dumps(self.header).encode()
                sock.sendall(send)
                self.traffic.put_traffic_up(send)

            elif sock_type == CLIENT_SIDE:
                receive = sock.recv(self.buffsize)
                self.traffic.put_traffic_down(receive)
                header = json.loads(receive.decode())

            # Version check
            if header['network_ver'] != self.header['network_ver']:
                raise ConnectionAbortedError('Network ver %d differ from %d' % (
                    header['network_ver'], self.header['network_ver']
                ))
            # Check duplicated connection
            names = tuple(header['name'] for n, s, hp, header, ak, st in self.client)
            if header['name'] in names:
                raise ConnectionAbortedError("Same connection detected. \"%s\"" % header['name'])

        except ConnectionAbortedError as e:
            logging.debug(e)
            try: sock.close()
            except: pass
            return
        except Exception as e:
            logging.debug(e, exc_info=F_DEBUG)
            try: sock.close()
            except: pass
            return

        # Accept connection
        with self.lock:
            self.number += 1
            client = (self.number, sock, host_port, header, aes_key, sock_type)
            self.client.append(client)
        logging.info("New connection from (%s:%d)" % host_port)

        # pooling
        msg_prefix = b''
        msg_len = 0
        msg_body = b''
        cp = header['compress'] and self.header['compress']
        while True:
            try:
                count = 0
                if len(msg_prefix) == 0:
                    sock.settimeout(3600)  # Wait for 1hour
                    first_msg = sock.recv(self.buffsize)
                    self.traffic.put_traffic_down(first_msg)
                    sock.settimeout(60)  # waiting for other message
                else:
                    first_msg, msg_prefix = msg_prefix, b''

                # Start receive message
                msg_len = int.from_bytes(first_msg[:4], 'big')
                msg_body = first_msg[4:]

                # Notice long message
                if msg_len != len(msg_body):
                    logging.debug("Receive long msg, len=%d, body=%d" % (msg_len, len(msg_body)))

                if msg_len == 0:
                    raise ConnectionAbortedError("1:Socket error, fall in loop.")
                elif len(msg_body) == 0:
                    raise ConnectionAbortedError("2:Socket error, fall in loop.")
                elif len(msg_body) >= msg_len:
                    msg_body, msg_prefix = msg_body[:msg_len], msg_body[msg_len:]
                    msg_body = AESCipher.decrypt(key=aes_key, enc=msg_body, z=cp)
                    self.stream_que.put((client, msg_body))
                    continue
                else:
                    pass

                # continue receiving message
                while True:
                    count += 1
                    new_body = sock.recv(self.buffsize)
                    self.traffic.put_traffic_down(new_body)
                    msg_body += new_body
                    if len(new_body) == 0:
                        raise ConnectionAbortedError("3:Socket error, fall in loop.")
                    elif len(msg_body) >= msg_len:
                        msg_body, msg_prefix = msg_body[:msg_len], msg_body[msg_len:]
                        msg_body = AESCipher.decrypt(key=aes_key, enc=msg_body, z=cp)
                        self.stream_que.put((client, msg_body))
                        break
                    elif len(msg_body) > MAX_RECEIVE_SIZE + 1000:
                        raise ConnectionAbortedError("Too many!(MAX %dKB)" % (MAX_RECEIVE_SIZE // 1000))
                    else:
                        continue

            except ConnectionAbortedError as e:
                logging.debug("1:ConnectionAbortedError. \"%s\"" % e, exc_info=False)
                logging.debug("2:msg_len=%d, msg_body=%d" % (msg_len, len(msg_body)))
                break
            except ConnectionResetError:
                logging.debug("Closed by peer. \"%s\"" % header['name'], exc_info=False)
                break
            except socket.timeout:
                logging.debug("timeout \"%s\"" % header['name'], exc_info=False)
            except OSError as e:
                logging.debug("OS error by \"%s\"" % e, exc_info=F_DEBUG)
                break
            except Exception as e:
                logging.debug("Pool exception \"%s\"" % e, exc_info=F_DEBUG)
                break

        # raised exception on loop
        if not self.remove_connection(client):
            logging.debug("Failed remove client \"%s\"" % header['name'])

    @staticmethod
    def client2peer_format(client, peers):
        # peer_format: {(host, port): {'header': header, 'score': score}}
        number, sock, host_port, header, aes_key, sock_type = client
        k = (host_port[0], header['p2p_port'])
        v = {'header': header, 'score': peers[k]['score'] if k in peers else 0}
        return k, v

    def peer_format2client(self, k):
        with self.lock:
            for client in self.client:
                number, sock, host_port, header, aes_key, sock_type = client
                if host_port[0] == k[0] and header['p2p_port'] == k[1]:
                    return client
            else:
                return None
