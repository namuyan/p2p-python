from p2p_python.config import C, V, Debug, PeerToPeerError
from p2p_python.user import User
from p2p_python.serializer import dumps
from p2p_python.tool.traffic import Traffic
from p2p_python.tool.utils import AESCipher
from nem_ed25519_rust import generate_keypair, encrypt, decrypt
from threading import Thread, current_thread, RLock, Event
from typing import Optional, List
from logging import getLogger
from binascii import a2b_hex
from time import time, sleep
from queue import Queue
from io import BytesIO
import selectors
import json
import random
import socket
import socks
import zlib


# constant
SERVER_SIDE = 'Server'
CLIENT_SIDE = 'Client'

log = getLogger(__name__)
listen_sel = selectors.DefaultSelector()
ban_address = list()  # deny connection address


class Core(object):

    def __init__(self, host=None, listen=15, buffsize=4096):
        assert V.DATA_PATH is not None, 'Setup p2p params before CoreClass init.'
        assert host is None or host == 'localhost'
        # status params
        self.f_stop = False
        self.f_finish = False
        self.f_running = False
        # working info
        self.start_time = int(time())
        self.number = 0
        self.user: List[User] = list()
        self.lock = RLock()
        self.host = host  # local=>'localhost', 'global'=>None
        self.core_que = Queue(maxsize=200)
        self.listen = listen
        self.buffsize = buffsize
        self.traffic = Traffic()
        self._ping = Event()
        self._ping.set()

    def close(self):
        if not self.f_running:
            raise PeerToPeerError('Core is not running.')
        self.traffic.close()
        for user in self.user.copy():
            self.remove_connection(user, 'Manually closing.')
        listen_sel.close()
        self.f_stop = True

    def ping(self, user: User, f_udp=False):
        try:
            self._ping.wait(10)
            self._ping.clear()
            self.send_msg_body(msg_body=b'Ping', user=user, f_udp=f_udp, f_pro_force=True)
            r = self._ping.wait(5)
            self._ping.set()
            return r
        except Exception as e:
            log.debug(f"failed ping by {e} udp={f_udp}")
            self._ping.set()
            return False

    def start(self, s_family=socket.AF_UNSPEC):
        assert s_family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNSPEC)
        self.traffic.start()
        # Pooling connection
        if V.P2P_ACCEPT:
            create_tcp_server_socks(core=self, s_family=s_family)
        if V.P2P_UDP_ACCEPT:
            create_udp_server_socks(core=self, s_family=s_family)
        # listen socket ipv4/ipv6
        if V.P2P_ACCEPT or V.P2P_UDP_ACCEPT:
            Thread(target=sock_listen_loop, args=(self,), name='Listen', daemon=True).start()
        else:
            log.info("set p2p accept flag = False")
        self.f_running = True

    def get_server_header(self):
        return {
            'name': V.SERVER_NAME,
            'client_ver': V.CLIENT_VER,
            'network_ver': V.NETWORK_VER,
            'p2p_accept': V.P2P_ACCEPT,
            'p2p_udp_accept': V.P2P_UDP_ACCEPT,
            'p2p_port': V.P2P_PORT,
            'start_time': self.start_time,
            'last_seen': int(time())
        }

    def create_connection(self, host, port):
        sock = None
        try:
            for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                af, socktype, proto, canonname, host_port = res
                if host_port[0] in ban_address:
                    return False  # baned address
                try:
                    if V.TOR_CONNECTION:
                        if af != socket.AF_INET:
                            continue
                        sock = socks.socksocket()
                        sock.setproxy(socks.PROXY_TYPE_SOCKS5, V.TOR_CONNECTION[0], V.TOR_CONNECTION[1])
                    else:
                        sock = socket.socket(af, socktype, proto)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except OSError:
                    continue
                sock.setblocking(True)
                sock.settimeout(10)
                # Connection
                try:
                    sock.connect(host_port)
                    break
                except OSError:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    continue
            else:
                # create no connection
                return False
            log.debug(f"success create connection to {host_port}")
            # 1. receive plain message
            try:
                msg = sock.recv(self.buffsize)
                if msg != b'hello':
                    raise PeerToPeerError('first plain msg not correct? {}'.format(msg))
            except socket.timeout:
                raise PeerToPeerError('timeout on first plain msg receive')
            # 2. send my header
            send = json.dumps(self.get_server_header()).encode()
            sock.sendall(send)
            self.traffic.put_traffic_up(send)
            # 3. receive public key
            try:
                my_sec, my_pub = generate_keypair()
                receive = sock.recv(self.buffsize)
                self.traffic.put_traffic_down(receive)
                msg = json.loads(receive.decode())
            except socket.timeout:
                raise PeerToPeerError('timeout on public key receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on public key receive')
            other_pk = msg['public-key']
            other_pub = a2b_hex(other_pk)
            # 4. send public key
            send = json.dumps({'public-key': my_pub.hex()}).encode()
            sock.sendall(send)
            self.traffic.put_traffic_up(send)
            # 5. Get AES key and header and decrypt
            try:
                receive = sock.recv(self.buffsize)
                self.traffic.put_traffic_down(receive)
                dec = decrypt(my_sec, other_pub, receive)
                data = json.loads(dec.decode())
            except socket.timeout:
                raise PeerToPeerError('timeout on AES key and header receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on AES key and header receive')
            aeskey, header = data['aes-key'], data['header']
            # 6. generate new user
            with self.lock:
                new_user = User(self.number, sock, host_port, aeskey, C.T_CLIENT)
                new_user.deserialize(header)
                # 7. check header
                if new_user.network_ver != V.NETWORK_VER:
                    raise PeerToPeerError('Don\'t same network version [{}!={}]'.format(
                        new_user.network_ver, V.NETWORK_VER))
                self.number += 1
            # 8. send accept signal
            encrypted = AESCipher.encrypt(new_user.aeskey, b'accept')
            sock.sendall(encrypted)
            self.traffic.put_traffic_up(encrypted)

            # 9. accept connection
            log.info(f"New connection to {new_user.name} {new_user.get_host_port()}")
            Thread(target=self.receive_loop, name='C:' + new_user.name, args=(new_user,), daemon=True).start()

            c = 20
            while new_user not in self.user and c > 0:
                sleep(1)
                c -= 1
            self.is_reachable(new_user)
            if c == 0:
                return False
            else:
                return True
        except PeerToPeerError as e:
            msg = "peer2peer error, {} ({})".format(e, host)
        except ConnectionRefusedError as e:
            msg = "connection refused error, {} ({})".format(e, host)
        except ValueError as e:
            msg = "ValueError: {} {}".format(host, e)
        except Exception as e:
            log.error("NewConnectionError", exc_info=True)
            msg = "NewConnectionError {} {}".format(host, e)

        # close socket
        log.debug(msg)
        try:
            sock.sendall(msg.encode())
            sock.close()
        except Exception as e:
            pass
        return False

    def remove_connection(self, user, reason=None) -> bool:
        if user is None:
            return False
        try:
            if reason:
                user.send(b'1111' + str(reason).encode())
        except Exception:
            pass
        user.close()
        with self.lock:
            if user in self.user:
                self.user.remove(user)
                log.debug(f"remove connection to {user.name} by {reason}")
                return True
            else:
                log.debug(f"failed remove connection by {reason}, not found {user.name}")
                return False

    def send_msg_body(self, msg_body, user=None, status=200, f_udp=False, f_pro_force=False):
        # StatusCode: https://ja.wikipedia.org/wiki/HTTPステータスコード
        assert isinstance(msg_body, bytes), 'msg_body is bytes'
        assert 200 <= status < 600, 'Not found status code {}'.format(status)

        # get client
        if len(self.user) == 0:
            raise ConnectionError('client connection is zero.')
        elif len(msg_body) > C.MAX_RECEIVE_SIZE + 5000:
            error = 'Max message size is {}kb (You try {}Kb)'.format(
                round(C.MAX_RECEIVE_SIZE / 1000000, 3), round(len(msg_body) / 1000000, 3))
            self.send_msg_body(msg_body=dumps(error), user=user, status=500)
            raise ConnectionRefusedError(error)
        elif user is None:
            user = random.choice(self.user)

        # send message
        if f_udp and f_pro_force:
            self._udp_body(msg_body, user)
        elif f_udp and user.p2p_udp_accept and len(msg_body) < 1400:
            self._udp_body(msg_body, user)
        else:
            msg_body = zlib.compress(msg_body)
            msg_body = AESCipher.encrypt(key=user.aeskey, raw=msg_body)
            msg_len = len(msg_body).to_bytes(4, 'big')
            send_data = msg_len + msg_body
            user.send(send_data)
            self.traffic.put_traffic_up(send_data)
        # log.debug("Send {}Kb to '{}'".format(len(msg_len+msg_body) / 1000, user.name))
        return user

    def _udp_body(self, msg_body, user):
        name_len = len(V.SERVER_NAME.encode()).to_bytes(1, 'big')
        msg_body = AESCipher.encrypt(key=user.aeskey, raw=msg_body)
        send_data = name_len + V.SERVER_NAME.encode() + msg_body
        host_port = user.get_host_port()
        sock_family = socket.AF_INET if len(host_port) == 2 else socket.AF_INET6
        with socket.socket(sock_family, socket.SOCK_DGRAM) as sock:
            sock.sendto(send_data, host_port)
        self.traffic.put_traffic_up(send_data)

    def initial_connection_check(self, sock, host_port):
        current_thread().setName('InitCheck')
        sock.settimeout(10)
        try:
            # 1. send plain message
            sock.sendall(b'hello')
            # 2. receive other's header
            try:
                received = sock.recv(self.buffsize)
                if len(received) == 0:
                    raise PeerToPeerError('empty msg receive')
                header = json.loads(received.decode())
            except socket.timeout:
                raise PeerToPeerError('timeout on other\'s header receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on other\'s header receive')
            # 3. generate new user
            with self.lock:
                new_user = User(self.number, sock, host_port, AESCipher.create_key(), C.T_SERVER)
                self.number += 1
                new_user.deserialize(header)
                if new_user.name == V.SERVER_NAME:
                    raise ConnectionAbortedError('Same origin connection.')
            # 4. send my public key
            my_sec, my_pub = generate_keypair()
            send = json.dumps({'public-key': my_pub.hex()}).encode()
            sock.sendall(send)
            self.traffic.put_traffic_up(send)
            # 5. receive public key
            try:
                receive = sock.recv(self.buffsize)
                self.traffic.put_traffic_down(receive)
                if len(receive) == 0:
                    raise ConnectionAbortedError('received msg is zero.')
                data = json.loads(receive.decode())
            except socket.timeout:
                raise PeerToPeerError('timeout on public key receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on public key receive')
            other_pub = a2b_hex(data['public-key'])
            # 6. encrypt and send AES key and header
            send = json.dumps({
                'aes-key': new_user.aeskey,
                'header': self.get_server_header(),
            })
            encrypted = encrypt(my_sec, other_pub, send.encode())
            sock.send(encrypted)
            self.traffic.put_traffic_up(encrypted)
            # 7. receive accept signal
            try:
                encrypted = sock.recv(self.buffsize)
                self.traffic.put_traffic_down(encrypted)
            except socket.timeout:
                raise PeerToPeerError('timeout on accept signal receive')
            receive = AESCipher.decrypt(new_user.aeskey, encrypted)
            if receive != b'accept':
                raise ConnectionAbortedError('Not accept signal!')

            # 8. accept connection
            log.info(f"New connection from {new_user.name} {new_user.get_host_port()}")
            Thread(target=self.receive_loop, name='S:' + new_user.name, args=(new_user,), daemon=True).start()
            # Port accept check
            sleep(10)
            if new_user in self.user:
                self.is_reachable(new_user)
            return
        except ConnectionAbortedError as e:
            msg = "connection aborted error, {} ({})".format(e, host_port[0])
        except PeerToPeerError as e:
            msg = "peer2peer error, {} ({})".format(e, host_port[0])
        except Exception as e:
            log.error("InitialConnCheck", exc_info=True)
            msg = "InitialConnCheck: {}".format(e)

        # close socket
        log.debug(msg)
        try:
            sock.sendall(msg.encode())
        except Exception:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def receive_loop(self, user):
        # Accept connection
        with self.lock:
            for check_user in self.user:
                if check_user.name != user.name:
                    continue
                if self.ping(check_user):
                    error = "Remove new connection {}, continue connect {}".format(user, check_user)
                    self.remove_connection(user, error)
                    log.info(error)
                else:
                    error = "Same origin, Replace new connection {} => {}".format(check_user, user)
                    self.remove_connection(check_user, error)
                    log.info(error)
            self.user.append(user)
        log.info(f"accept connection {user.name}")

        try:
            user.sock.settimeout(10)
        except OSError:
            error = 'settimeout failed on _receive_msg'
            self.remove_connection(user, error)
            log.info(error)
            return
        bio = BytesIO()  # Warning: don't use initial_bytes, same duplicate ID used?
        bio_length = 0
        msg_length = 0
        f_raise_timeout = False
        error = None
        while not self.f_stop:
            try:
                get_msg = user.sock.recv(self.buffsize)
                if len(get_msg) == 0:
                    error = "Fall in loop, socket closed."
                    break

                # check message params init
                bio_length += bio.write(get_msg)
                if msg_length == 0:
                    # init message params
                    msg_bytes = bio.getvalue()
                    msg_length, initial_bytes = int.from_bytes(msg_bytes[:4], 'big'), msg_bytes[4:]
                    bio.truncate(0)
                    bio.seek(0)
                    bio_length = bio.write(initial_bytes)
                elif bio_length == 0:
                    error = "Why bio_length is zero?, msg_length={}".format(msg_length, bio_length)
                    break
                else:
                    pass

                # check complete message receive
                if bio_length >= msg_length:
                    # success, get all message
                    msg_bytes = bio.getvalue()
                    msg_body, initial_bytes = msg_bytes[:msg_length], msg_bytes[msg_length:]
                    if len(initial_bytes) == 0:
                        # no another message
                        msg_length = 0
                        f_raise_timeout = False
                    elif len(initial_bytes) < 4:
                        error = "Failed to get message length? {}".format(initial_bytes)
                        break
                    else:
                        # another message pushing
                        msg_length, initial_bytes = int.from_bytes(initial_bytes[:4],
                                                                   'big'), initial_bytes[4:]
                        f_raise_timeout = True
                    bio.truncate(0)
                    bio.seek(0)
                    bio_length = bio.write(initial_bytes)
                else:
                    # continue getting message
                    f_raise_timeout = True
                    continue

                # continue to process msg_body
                self.traffic.put_traffic_down(msg_body)
                msg_body = AESCipher.decrypt(key=user.aeskey, enc=msg_body)
                msg_body = zlib.decompress(msg_body)
                if msg_body == b'Ping':
                    log.debug(f"receive Ping from {user.name}")
                    self.send_msg_body(b'Pong', user)
                elif msg_body == b'Pong':
                    log.debug(f"receive Pong from {user.name}")
                    self._ping.set()
                else:
                    self.core_que.put((user, msg_body))
                f_raise_timeout = False

            except socket.timeout:
                if f_raise_timeout:
                    error = "Timeout: Not allowed timeout when getting message!".format(user.name)
                    break
            except ConnectionError as e:
                error = "ConnectionError: " + str(e)
                break
            except OSError as e:
                error = "OSError: " + str(e)
                break
            except Exception:
                import traceback
                error = "Exception: " + str(traceback.format_exc())
                break

        # After exit from loop, close socket
        if not bio.closed:
            bio.close()
        if not self.remove_connection(user, error):
            log.debug(f"failed remove user {user.name}")

    def is_reachable(self, new_user):
        # Check connect to the user TCP/UDP port
        if new_user not in self.user:
            return
        f_tcp = True
        host_port = new_user.get_host_port()
        af = socket.AF_INET if len(host_port) == 2 else socket.AF_INET6
        sock = socket.socket(af, socket.SOCK_STREAM)
        try:
            r = sock.connect_ex(host_port)
            if r != 0:
                f_tcp = False
        except OSError:
            f_tcp = False
        try:
            sock.close()
        except OSError:
            pass
        f_udp = self.ping(user=new_user, f_udp=True)
        f_changed = False
        # reflect user status
        if f_tcp is not new_user.p2p_accept:
            log.debug(f"{new_user} Update TCP accept status {new_user.p2p_accept}>{f_tcp}")
            new_user.p2p_accept = f_tcp
            f_changed = True
        if f_udp is not new_user.p2p_udp_accept:
            log.debug(f"{new_user} Update UDP accept status {new_user.p2p_udp_accept}>{f_udp}")
            new_user.p2p_udp_accept = f_udp
            f_changed = True
        # if f_changed:
        #    log.info("{} Change TCP/UDP accept status tcp={} udp={}"
        #                 .format(new_user, f_tcp, f_udp))

    def name2user(self, name) -> Optional[User]:
        for user in self.user:
            if user.name == name:
                return user
        return None

    def host_port2user(self, host_port) -> Optional[User]:
        for user in self.user:
            if host_port == user.get_host_port():
                return user
        return None


"""socket connection functions
"""


def tcp_server_listen(core: Core):
    """TCP server new connection control"""
    def handle(server_sock, mask):
        try:
            sock, host_port = server_sock.accept()
            sock.setblocking(True)
            Thread(target=core.initial_connection_check, args=(sock, host_port), daemon=True).start()
            log.info(f"server accept from {host_port}")
        except OSError as e:
            log.debug(f"OSError {str(e)}")
        except Exception as e:
            log.debug(e, exc_info=Debug.P_EXCEPTION)
    return handle


def udp_server_listen(core: Core):
    """UDP server new connection control"""
    def handle(server_sock, mask):
        try:
            msg, address = server_sock.recvfrom(8192)
            msg_len = msg[0]
            msg_name, msg_body = msg[1:msg_len + 1], msg[msg_len + 1:]
            user = core.name2user(msg_name.decode())
            if user is None:
                return
            core.traffic.put_traffic_down(msg_body)
            msg_body = AESCipher.decrypt(key=user.aeskey, enc=msg_body)
            if msg_body == b'Ping':
                log.info(f"get udp accept from {user}")
                core.send_msg_body(msg_body=b'Pong', user=user)
            else:
                log.debug(f"get udp packet from {user}")
                core.core_que.put((user, msg_body))
        except OSError as e:
            log.debug(f"OSError {str(e)}")
        except Exception as e:
            log.debug(e, exc_info=Debug.P_EXCEPTION)
    return handle


def create_tcp_server_socks(core: Core, s_family):
    """create new TCP socket server"""
    for res in socket.getaddrinfo(core.host, V.P2P_PORT, s_family, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        af, sock_type, proto, canon_name, sa = res
        try:
            sock = socket.socket(af, sock_type, proto)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError as e:
            log.debug(f"failed tcp socket {sa}")
            continue
        try:
            sock.bind(sa)
            sock.listen(core.listen)
            sock.setblocking(False)
        except OSError as e:
            try:
                sock.close()
            except OSError:
                pass
            log.debug(f"failed tcp bind or listen {sa}")
            continue
        if af == socket.AF_INET or af == socket.AF_INET6:
            listen_sel.register(sock, selectors.EVENT_READ, tcp_server_listen(core))
            sock_type = "IPV4" if sock.family == 2 else "IPV6"
            log.info(f"new tcp server {sock_type} {sa}")
        else:
            log.warning(f"not found socket type {af}")
    if len(listen_sel.get_map()) == 0:
        log.error("could not open tcp sockets")
        V.P2P_ACCEPT = False


def create_udp_server_socks(core: Core, s_family):
    """create new UDP socket server"""
    before_num = len(listen_sel.get_map())
    for res in socket.getaddrinfo(core.host, V.P2P_PORT, s_family, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE):
        af, sock_type, proto, canon_name, sa = res
        try:
            sock = socket.socket(af, sock_type, proto)
        except OSError as e:
            log.debug(f"failed udp socket {sa}")
            continue
        try:
            sock.bind(sa)
            sock.setblocking(False)
        except OSError as e:
            sock.close()
            log.debug(f"failed udp bind {sa}")
            continue
        if af == socket.AF_INET or af == socket.AF_INET6:
            listen_sel.register(sock, selectors.EVENT_READ, udp_server_listen(core))
            sock_type = "IPV4" if sock.family == 2 else "IPV6"
            log.info(f"new udp server {sock_type} {sa}")
        else:
            log.warning(f"not found socket type {af}")
    if len(listen_sel.get_map()) == before_num:
        log.error("could not open udp sockets")
        V.P2P_UDP_ACCEPT = False


def sock_listen_loop(core: Core):
    """TCP/UDP server's selector"""
    while not core.f_stop:
        try:
            listen_map = listen_sel.get_map()
            if listen_map is None:
                log.debug("close sock listen loop")
                return
            while len(listen_map) == 0:
                sleep(0.5)
            events = listen_sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
        except Exception as e:
            log.error(e)
            sleep(3)


__all__ = [
    "SERVER_SIDE",
    "CLIENT_SIDE",
    "ban_address",
    "Core",
]
