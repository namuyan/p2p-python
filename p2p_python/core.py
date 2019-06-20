from p2p_python.config import V, Debug, PeerToPeerError
from p2p_python.user import UserHeader, User
from p2p_python.serializer import dumps
from p2p_python.tool.traffic import Traffic
from p2p_python.tool.utils import AESCipher
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.curves import NIST256p
from typing import Optional, Union, List
from logging import getLogger
from binascii import a2b_hex
from time import time
from io import BytesIO
from hashlib import sha256
from asyncio.streams import StreamWriter, StreamReader
import asyncio
import json
import random
import socket
import socks
import zlib


# constant
SERVER_SIDE = 'server'
CLIENT_SIDE = 'client'

log = getLogger(__name__)
loop = asyncio.get_event_loop()
tcp_servers: List[asyncio.AbstractServer] = list()
udp_servers: List[socket.socket] = list()
ban_address = list()  # deny connection address
BUFFER_SIZE = 8192
socket2name = {
    socket.AF_INET: "ipv4",
    socket.AF_INET6: "ipv6",
    socket.AF_UNSPEC: "ipv4/6",
}


class Core(object):

    def __init__(self, host=None, listen=15):
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
        self.user_lock = asyncio.Lock()
        self.host = host  # local=>'localhost', 'global'=>None
        self.core_que = asyncio.Queue()
        self.backlog = listen
        self.traffic = Traffic()
        self._ping = asyncio.Event()
        self._ping.set()

    def close(self):
        if not self.f_running:
            raise Exception('Core is not running')
        self.traffic.close()
        for user in self.user.copy():
            self.remove_connection(user, 'manual closing')
        for sock in tcp_servers:
            sock.close()
            asyncio.ensure_future(sock.wait_closed())
        for sock in udp_servers:
            loop.remove_reader(sock.fileno())
            sock.close()
        self.f_stop = True

    async def ping(self, user: User, f_udp=False):
        try:
            await asyncio.wait_for(self._ping.wait(), 5.0)
            self._ping.clear()
            await self.send_msg_body(msg_body=b'Ping', user=user, allow_udp=f_udp, f_pro_force=True)
            await asyncio.wait_for(self._ping.wait(), 5.0)
            self._ping.set()
            return True
        except asyncio.TimeoutError:
            log.debug(f"failed to udp ping {user}")
            self._ping.set()
            return False
        except ConnectionError as e:
            log.debug(f"socket error on ping by {e}")
            self._ping.set()
            return False

    def start(self, s_family=socket.AF_UNSPEC):
        assert s_family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNSPEC)
        # setup TCP/UDP socket server
        setup_all_socket_server(core=self, s_family=s_family)
        # listen socket ipv4/ipv6
        log.info(f"setup socket server "
                 f"tcp{len(tcp_servers)}={V.P2P_ACCEPT} udp{len(udp_servers)}={V.P2P_UDP_ACCEPT}")
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

    async def create_connection(self, host, port):
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
                sock.connect(host_port)
                sock.setblocking(False)
                reader, writer = await asyncio.open_connection(sock=sock, loop=loop)
                break
            except ConnectionRefusedError:
                continue  # try to connect closed socket
            except OSError as e:
                log.debug(f"socket creation error by {str(e)}")
                continue
        else:
            # create no connection
            return False
        log.debug(f"success create connection to {host_port}")

        try:
            # 1. receive plain message
            try:
                msg = await asyncio.wait_for(reader.read(BUFFER_SIZE), 5.0)
                if msg != b'hello':
                    raise PeerToPeerError('first plain msg not correct? {}'.format(msg))
            except asyncio.TimeoutError:
                raise PeerToPeerError('timeout on first plain msg receive')

            # 2. send my header
            send = json.dumps(self.get_server_header()).encode()
            writer.write(send)
            await writer.drain()
            self.traffic.put_traffic_up(send)

            # 3. receive public key
            try:
                my_sec, my_pub = generate_keypair()
                receive = await asyncio.wait_for(reader.read(BUFFER_SIZE), 5.0)
                self.traffic.put_traffic_down(receive)
                msg = json.loads(receive.decode())
            except asyncio.TimeoutError:
                raise PeerToPeerError('timeout on public key receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on public key receive')

            # 4. send public key
            send = json.dumps({'public-key': my_pub}).encode()
            writer.write(send)
            await writer.drain()
            self.traffic.put_traffic_up(send)

            # 5. Get AES key and header and decrypt
            try:
                receive = await asyncio.wait_for(reader.read(BUFFER_SIZE), 5.0)
                self.traffic.put_traffic_down(receive)
                key = generate_shared_key(my_sec, msg['public-key'])
                dec = AESCipher.decrypt(key, receive)
                data = json.loads(dec.decode())
            except asyncio.TimeoutError:
                raise PeerToPeerError('timeout on AES key and header receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on AES key and header receive')
            aeskey, header = data['aes-key'], data['header']

            # 6. generate new user
            user_header = UserHeader(**header)
            new_user = User(user_header, self.number, reader, writer, host_port, aeskey, CLIENT_SIDE)

            # 7. check header
            if new_user.header.network_ver != V.NETWORK_VER:
                raise PeerToPeerError('Don\'t same network version [{}!={}]'.format(
                    new_user.header.network_ver, V.NETWORK_VER))
            self.number += 1

            # 8. send accept signal
            encrypted = AESCipher.encrypt(new_user.aeskey, b'accept')
            await new_user.send(encrypted)
            self.traffic.put_traffic_up(encrypted)

            # 9. accept connection
            log.info(f"established connection as client to {new_user.header.name} {new_user.get_host_port()}")
            asyncio.ensure_future(self.receive_loop(new_user))
            # server port's reachable check
            await asyncio.sleep(1.0)
            await self.check_reachable(new_user)
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
        if not writer.transport.is_closing():
            writer.close()
        return False

    def remove_connection(self, user: User, reason: str) -> bool:
        if user is None:
            return False
        user.close()
        if user in self.user:
            self.user.remove(user)
            if 0 < user.score:
                log.info(f"remove connection of {user.header.name} by '{reason}'")
            else:
                log.debug(f"remove connection of {user.header.name} by '{reason}'")
            return True
        else:
            return False

    async def send_msg_body(self, msg_body, user: Optional[User] = None, status=200, allow_udp=False, f_pro_force=False):
        # StatusCode: https://ja.wikipedia.org/wiki/HTTPステータスコード
        assert isinstance(msg_body, bytes), 'msg_body is bytes'
        assert 200 <= status < 600, 'Not found status code {}'.format(status)

        # get client
        if len(self.user) == 0:
            raise ConnectionError('client connection is zero.')
        elif len(msg_body) > Debug.P_MAX_RECEIVE_SIZE + 5000:
            error = 'Max message size is {}kb (You try {}Kb)'.format(
                round(Debug.P_MAX_RECEIVE_SIZE / 1000000, 3), round(len(msg_body) / 1000000, 3))
            await self.send_msg_body(msg_body=dumps(error), user=user, status=500)
            raise ConnectionRefusedError(error)
        elif user is None:
            user = random.choice(self.user)

        # send message
        if allow_udp and f_pro_force:
            self._send_udp_body(msg_body, user)
        elif allow_udp and user.header.p2p_udp_accept and len(msg_body) < 1400:
            self._send_udp_body(msg_body, user)
        else:
            msg_body = zlib.compress(msg_body)
            msg_body = AESCipher.encrypt(key=user.aeskey, raw=msg_body)
            msg_len = len(msg_body).to_bytes(4, 'big')
            send_data = msg_len + msg_body
            await user.send(send_data)
            self.traffic.put_traffic_up(send_data)
        return user

    def _send_udp_body(self, msg_body, user):
        name_len = len(V.SERVER_NAME.encode()).to_bytes(1, 'big')
        msg_body = AESCipher.encrypt(key=user.aeskey, raw=msg_body)
        send_data = name_len + V.SERVER_NAME.encode() + msg_body
        host_port = user.get_host_port()
        sock_family = socket.AF_INET if len(host_port) == 2 else socket.AF_INET6
        with socket.socket(sock_family, socket.SOCK_DGRAM) as sock:
            sock.sendto(send_data, host_port)
        self.traffic.put_traffic_up(send_data)

    async def initial_connection_check(self, reader: StreamReader, writer: StreamWriter):
        host_port = writer.get_extra_info('peername')
        new_user: Optional[User] = None
        try:
            # 1. send plain message
            writer.write(b'hello')
            await writer.drain()

            # 2. receive other's header
            try:
                received = await asyncio.wait_for(reader.read(BUFFER_SIZE), 5.0)
                if len(received) == 0:
                    raise PeerToPeerError('empty msg receive')
                header = json.loads(received.decode())
            except asyncio.TimeoutError:
                raise PeerToPeerError('timeout on other\'s header receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on other\'s header receive')

            # 3. generate new user
            user_header = UserHeader(**header)
            new_user = User(user_header, self.number, reader, writer, host_port, AESCipher.create_key(), SERVER_SIDE)
            self.number += 1
            if new_user.header.name == V.SERVER_NAME:
                raise ConnectionAbortedError('Same origin connection')

            # 4. send my public key
            my_sec, my_pub = generate_keypair()
            send = json.dumps({'public-key': my_pub}).encode()
            await new_user.send(send)
            self.traffic.put_traffic_up(send)

            # 5. receive public key
            try:
                receive = await new_user.recv()
                self.traffic.put_traffic_down(receive)
                if len(receive) == 0:
                    raise ConnectionAbortedError('received msg is zero.')
                data = json.loads(receive.decode())
            except asyncio.TimeoutError:
                raise PeerToPeerError('timeout on public key receive')
            except json.JSONDecodeError:
                raise PeerToPeerError('json decode error on public key receive')

            # 6. encrypt and send AES key and header
            send = json.dumps({
                'aes-key': new_user.aeskey,
                'header': self.get_server_header(),
            })
            key = generate_shared_key(my_sec, data['public-key'])
            encrypted = AESCipher.encrypt(key, send.encode())
            await new_user.send(encrypted)
            self.traffic.put_traffic_up(encrypted)

            # 7. receive accept signal
            try:
                encrypted = await new_user.recv()
                self.traffic.put_traffic_down(encrypted)
            except asyncio.TimeoutError:
                raise PeerToPeerError('timeout on accept signal receive')
            receive = AESCipher.decrypt(new_user.aeskey, encrypted)
            if receive != b'accept':
                raise PeerToPeerError(f"Not accept signal! {receive}")

            # 8. accept connection
            log.info(f"established connection as server from {new_user.header.name} {new_user.get_host_port()}")
            asyncio.ensure_future(self.receive_loop(new_user))
            # server port's reachable check
            await asyncio.sleep(1.0)
            await self.check_reachable(new_user)
            return
        except (ConnectionAbortedError, ConnectionResetError) as e:
            msg = f"disconnect error {host_port} {e}"
        except PeerToPeerError as e:
            msg = f"peer2peer error {host_port} {e}"
        except Exception as e:
            msg = "InitialConnCheck: {}".format(e)
            log.error(msg, exc_info=True)

        # EXCEPTION!
        if new_user:
            # remove user
            self.remove_connection(new_user, msg)
        else:
            # close socket
            log.debug(msg)
            try:
                writer.write(msg.encode())
                await writer.drain()
            except Exception:
                pass
            try:
                writer.close()
            except Exception:
                pass

    async def receive_loop(self, user: User):
        # Accept connection
        for check_user in self.user.copy():
            if check_user.header.name != user.header.name:
                continue
            elif await self.ping(check_user):
                error = f"same origin found and ping success, remove new connection"
                self.remove_connection(user, error)
                return
            else:
                error = f"same origin found but ping failed, remove old connection"
                self.remove_connection(check_user, error)
        self.user.append(user)
        log.info(f"check success and go into loop {user}")

        bio = BytesIO()  # Warning: don't use initial_bytes, same duplicate ID used?
        bio_length = 0
        msg_length = 0
        f_raise_timeout = False
        error = None
        while not self.f_stop:
            try:
                get_msg = await user.recv()
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
                    log.debug(f"receive Ping from {user.header.name}")
                    await self.send_msg_body(b'Pong', user)
                elif msg_body == b'Pong':
                    log.debug(f"receive Pong from {user.header.name}")
                    self._ping.set()
                else:
                    await self.core_que.put((user, msg_body))
                f_raise_timeout = False

            except asyncio.TimeoutError:
                if f_raise_timeout:
                    error = "Timeout: Not allowed timeout when getting message!"
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
        self.remove_connection(user, error)

    async def check_reachable(self, new_user: User):
        """check TCP/UDP port is opened"""
        try:
            # wait for accept or reject as user
            while new_user not in self.user:
                if new_user.closed:
                    log.debug(f"user connection closed on check_reachable {new_user}")
                    return
                await asyncio.sleep(1.0)
            # try to check
            f_tcp = True
            host_port = new_user.get_host_port()
            af = socket.AF_INET if len(host_port) == 2 else socket.AF_INET6
            sock = socket.socket(af, socket.SOCK_STREAM)
            try:
                r = sock.connect_ex(host_port)
                if r != 0:
                    f_tcp = False
                sock.close()
            except OSError:
                f_tcp = False
            f_udp = await self.ping(user=new_user, f_udp=True)
            f_changed = False
            # reflect user status
            if f_tcp is not new_user.header.p2p_accept:
                log.debug(f"{new_user} Update TCP accept status {new_user.header.p2p_accept}=>{f_tcp}")
                new_user.header.p2p_accept = f_tcp
                f_changed = True
            if f_udp is not new_user.header.p2p_udp_accept:
                log.debug(f"{new_user} Update UDP accept status {new_user.header.p2p_udp_accept}=>{f_udp}")
                new_user.header.p2p_udp_accept = f_udp
                f_changed = True
            if f_changed:
                log.debug(f"{new_user} Change socket status tcp={f_tcp} udp={f_udp}")
        except Exception:
            log.error("check_reachable exception", exc_info=True)

    def name2user(self, name) -> Optional[User]:
        for user in self.user:
            if user.header.name == name:
                return user
        return None

    def host_port2user(self, host_port) -> Optional[User]:
        for user in self.user:
            if host_port == user.get_host_port():
                return user
        return None


"""ECDH functions
"""


def generate_shared_key(sk, vk_str) -> bytes:
    vk = VerifyingKey.from_string(a2b_hex(vk_str), NIST256p)
    point = sk.privkey.secret_multiplier * vk.pubkey.point
    return sha256(point.x().to_bytes(32, 'big')).digest()


def generate_keypair() -> (SigningKey, str):
    sk = SigningKey.generate(NIST256p)
    vk = sk.get_verifying_key()
    return sk, vk.to_string().hex()


"""socket connection functions
"""


async def udp_server_handle(msg, addr, core: Core):
    msg_body = None
    try:
        msg_len = msg[0]
        msg_name, msg_body = msg[1:msg_len + 1], msg[msg_len + 1:]
        user = core.name2user(msg_name.decode())
        if user is None:
            return
        core.traffic.put_traffic_down(msg_body)
        msg_body = AESCipher.decrypt(key=user.aeskey, enc=msg_body)
        if msg_body == b'Ping':
            log.info(f"get udp ping from {user.header.name} addr:{addr}")
            await core.send_msg_body(msg_body=b'Pong', user=user)
        else:
            log.debug(f"get udp packet from {user.header.name} addr:{addr}")
            await core.core_que.put((user, msg_body))
    except ValueError as e:
        log.debug(f"maybe decrypt failed by {e} {msg_body}")
    except OSError as e:
        log.debug(f"OSError on udp listen by {str(e)}")
    except Exception as e:
        log.debug("UDP handle exception", exc_info=Debug.P_PRINT_EXCEPTION)


def create_tcp_server(core: Core, family):
    assert family == socket.AF_INET or family == socket.AF_INET6
    coroutine = asyncio.start_server(
        core.initial_connection_check, core.host, V.P2P_PORT,
        family=family, backlog=core.backlog, loop=loop)
    return loop.run_until_complete(coroutine)


def create_udp_server(core: Core, family):
    assert family == socket.AF_INET or family == socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_DGRAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind((core.host, V.P2P_PORT))
    fd = sock.fileno()

    def listen():
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            asyncio.ensure_future(udp_server_handle(data, addr, core))
        except (BlockingIOError, InterruptedError):
            pass
        except Exception:
            log.warning("UDP server exception", exc_info=True)
    # UDP server is not stream
    loop.add_reader(fd, listen)
    return sock


def setup_all_socket_server(core: Core, s_family):
    # create new TCP socket server
    log.info(f"try to setup server socket {core.host}:{V.P2P_PORT}")
    if V.P2P_ACCEPT:
        V.P2P_ACCEPT = False
        for res in socket.getaddrinfo(core.host, V.P2P_PORT, s_family, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, sock_type, proto, canon_name, sa = res
            try:
                sock = create_tcp_server(core, af)
                log.debug(f"success tcp server creation af={socket2name.get(af)}")
                tcp_servers.append(sock)
                V.P2P_ACCEPT = True
            except Exception:
                log.debug("create tcp server exception", exc_info=True)
    # create new UDP socket server
    if V.P2P_UDP_ACCEPT:
        V.P2P_UDP_ACCEPT = False
        for res in socket.getaddrinfo(core.host, V.P2P_PORT, s_family, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE):
            af, sock_type, proto, canon_name, sa = res
            try:
                sock = create_udp_server(core, af)
                log.debug(f"success udp server creation af={socket2name.get(af)}")
                udp_servers.append(sock)
                V.P2P_UDP_ACCEPT = True
            except Exception:
                log.debug("create udp server exception", exc_info=True)


__all__ = [
    "SERVER_SIDE",
    "CLIENT_SIDE",
    "ban_address",
    "Core",
]
