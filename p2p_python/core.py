#!/user/env python3
# -*- coding: utf-8 -*-

import json
import bjson
import logging
import random
import socket
import time
import zlib
import select
from threading import Thread, Lock
from nem_ed25519.base import Encryption
from .tool.traffic import Traffic
from .tool.utils import AESCipher, QueueSystem
from .config import C, V, Debug, PeerToPeerError
from .user import User

# constant
SERVER_SIDE = 'Server'
CLIENT_SIDE = 'Client'


class Core:
    f_stop = False
    f_finish = False
    f_running = False
    server_sock = None

    def __init__(self, host=None, listen=15, buffsize=2048):
        assert V.DATA_PATH is not None, 'Setup p2p params before CoreClass init.'
        self.start_time = int(time.time())
        self.number = 0
        self.user = list()
        self.lock = Lock()
        self.host = host  # local=>'localhost', 'global'=>None
        self.ecc = Encryption()
        self.ecc.secret_key()
        self.ecc.public_key()
        self.core_que = QueueSystem(maxsize=listen*100)
        self.listen = listen
        self.buffsize = buffsize
        self.traffic = Traffic()

    def close(self):
        if not self.f_running:
            raise PeerToPeerError('Core is not running.')
        self.f_stop = True
        self.traffic.close()
        # Server/client のソケットを全て閉じる
        for user in self.user:
            self.remove_connection(user, 'Manually close.')
        try: self.server_sock.close()
        except: pass

    def start(self, s_family=socket.AF_UNSPEC):
        def loop():
            logging.info("Start {} servers".format(len(sockets)))
            sock = server_sock = None
            while not self.f_stop:
                rfds = list(sockets)
                rrdy, wrdy, err = select.select(rfds, list(), list(), 3)
                try:
                    for server_sock in rrdy:
                        if server_sock in sockets:
                            sock, host_port = server_sock.accept()
                            Thread(target=self.__initial_connection_check,
                                   args=(sock, host_port), daemon=True).start()
                except TimeoutError:
                    pass
                except OSError as e:
                    try: sock.close()
                    except: pass
                    logging.debug("OSError {}".format(e))
                except Exception as e:
                    try: sock.close()
                    except: pass
                    logging.debug(e, exc_info=Debug.P_EXCEPTION)
            # out of loop
            for sock in sockets:
                try: sock.close()
                except: pass
            self.f_finish = True
            self.f_running = False
            logging.info("{} servers closed.".format(len(sockets)))

        def create_server_socks():
            for res in socket.getaddrinfo(self.host, V.P2P_PORT, s_family, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
                af, sock_type, proto, canon_name, sa = res
                try:
                    sock = socket.socket(af, sock_type, proto)
                except OSError:
                    continue
                try:
                    sock.bind(sa)
                    sock.listen(self.listen)
                except OSError as msg:
                    sock.close()
                    continue
                if af == socket.AF_INET or af == socket.AF_INET6:
                    sockets.append(sock)
                    self.f_running = True
                else:
                    logging.warning("Not found socket type {}".format(af))
            if not sockets:
                logging.error('could not open sockets')
            # Wait for connection
            Thread(target=loop, name="InnerCore", daemon=True).start()

        assert s_family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNSPEC)
        self.traffic.start()
        # Pooling connection
        if not V.P2P_ACCEPT:
            logging.info('You set p2p accept flag False.')
        # create server ipv4/ipv6
        sockets = list()
        create_server_socks()

    def get_server_header(self):
        return {
            'name': V.SERVER_NAME,
            'client_ver': V.CLIENT_VER,
            'network_ver': V.NETWORK_VER,
            'p2p_accept': V.P2P_ACCEPT,
            'p2p_port': V.P2P_PORT,
            'start_time': self.start_time}

    def create_connection(self, host, port):
        sock = host_port = None
        try:
            for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                af, socktype, proto, canonname, host_port = res
                try:
                    sock = socket.socket(af, socktype, proto)
                except OSError:
                    continue
                if self.host_port2user(host_port) is not None:
                    continue  # Already connected.
                sock.settimeout(10)
                # Connection
                try:
                    sock.connect(host_port)
                    break
                except OSError:
                    sock.close()
                    continue
            else:
                # create no connection
                return False
            # ヘッダーを送る
            send = json.dumps(self.get_server_header()).encode()
            with self.lock:
                sock.sendall(send)
            self.traffic.put_traffic_up(send)
            # 公開鍵を受取る
            receive = sock.recv(self.buffsize)
            self.traffic.put_traffic_down(receive)
            public_key = json.loads(receive.decode())['public-key']
            # 公開鍵を送る
            send = json.dumps({'public-key': self.ecc.pk}).encode()
            with self.lock:
                sock.sendall(send)
            self.traffic.put_traffic_up(send)
            # AESKEYとヘッダーを取得し復号化する
            receive = sock.recv(self.buffsize)
            self.traffic.put_traffic_down(receive)
            data = json.loads(self.ecc.decrypt(sender_pk=public_key, enc=receive).decode())
            aeskey, header = data['aes-key'], data['header']
            # ユーザーを作成する
            with self.lock:
                new_user = User(self.number, sock, host_port, aeskey, C.T_CLIENT)
                new_user.deserialize(header)
                # headerのチェック
                if new_user.network_ver != V.NETWORK_VER:
                    raise PeerToPeerError('Don\'t same network version [{}!={}]'
                                          .format(new_user.network_ver, V.NETWORK_VER))
                self.number += 1
            # Acceptシグナルを送る
            encrypted = AESCipher.encrypt(new_user.aeskey, b'accept')
            with self.lock:
                sock.sendall(encrypted)
            self.traffic.put_traffic_up(encrypted)

            Thread(target=self.__receive_msg,
                   name='C:' + new_user.name, args=(new_user,), daemon=True).start()

            c = 20
            while len(self.user) == 0 and c > 0:
                time.sleep(1)
                c -= 1
            if c == 0:
                return False
            else:
                return True
        except json.JSONDecodeError:
            logging.debug("Json decode error.")
        except PeerToPeerError as e:
            logging.debug("NewConnectionError {} {}".format(host_port, e), exc_info=Debug.P_EXCEPTION)
        except ConnectionRefusedError as e:
            logging.debug("ConnectionRefusedError {} {}".format(host_port, e), exc_info=Debug.P_EXCEPTION)
        except Exception as e:
            logging.error("NewConnectionError {} {}".format(host_port, e), exc_info=Debug.P_EXCEPTION)
        # close socket
        try: sock.close()
        except: pass
        return False

    def remove_connection(self, user, reason=None):
        with self.lock:
            if user in self.user:
                self.user.remove(user)
                try: user.close()
                except: pass
                logging.debug("remove connection to {} by \"{}\"".format(user.name, reason))
                return True
            return False

    def send_msg_body(self, msg_body, user=None):
        assert type(msg_body) == bytes, 'msg_body is bytes'

        # get client
        if len(self.user) == 0:
            raise ConnectionError('client connection is zero.')
        elif len(msg_body) > C.MAX_RECEIVE_SIZE + 5000:
            error = 'Max message size is {}kb (You try {}Kb)'.format(
                round(C.MAX_RECEIVE_SIZE/1000000, 3), round(len(msg_body)/1000000, 3))
            self.send_msg_body(msg_body=bjson.dumps(error), user=user)
            raise ConnectionRefusedError(error)
        elif user is None:
            user = random.choice(self.user)

        # send message
        msg_body = zlib.compress(msg_body)
        msg_body = AESCipher.encrypt(key=user.aeskey, raw=msg_body)
        msg_len = len(msg_body).to_bytes(4, 'big')
        with self.lock:
            user.sock.sendall(msg_len + msg_body)
        self.traffic.put_traffic_up(msg_len + msg_body)
        # logging.debug("Send {}Kb to '{}'".format(len(msg_len+msg_body) / 1000, user.name))
        return user

    def __initial_connection_check(self, sock, host_port):
        sock.settimeout(10)
        try:
            # ヘッダーを受取る
            received = sock.recv(self.buffsize)
            self.traffic.put_traffic_down(received)
            header = json.loads(received.decode())
            with self.lock:
                new_user = User(self.number, sock, host_port,
                                aeskey=AESCipher.create_key(), sock_type=C.T_SERVER)
                if self.host_port2user(new_user.get_host_port()) is not None:
                    return  # Already connected.
                self.number += 1
            new_user.deserialize(header)
            if new_user.name == V.SERVER_NAME:
                raise ConnectionAbortedError('Same origin connection.')
            # こちらの公開鍵を送る
            send = json.dumps({'public-key': self.ecc.pk}).encode()
            with self.lock:
                sock.sendall(send)
            self.traffic.put_traffic_up(send)
            # 公開鍵を取得する
            receive = new_user.sock.recv(self.buffsize)
            self.traffic.put_traffic_down(receive)
            if len(receive) == 0:
                raise ConnectionAbortedError('received msg is zero.')
            public_key = json.loads(receive.decode())['public-key']
            # AESKEYとHeaderを暗号化して送る
            encrypted = self.ecc.encrypt(recipient_pk=public_key, msg=json.dumps(
                {'aes-key': new_user.aeskey, 'header': self.get_server_header()}).encode(), encode='raw')
            with self.lock:
                new_user.sock.sendall(encrypted)
            self.traffic.put_traffic_up(encrypted)
            # Accept信号を受け取る
            encrypted = new_user.sock.recv(self.buffsize)
            self.traffic.put_traffic_down(encrypted)
            receive = AESCipher.decrypt(new_user.aeskey, encrypted)
            if receive != b'accept':
                raise ConnectionAbortedError('Not accept signal.')
        except ConnectionAbortedError as e:
            logging.debug(e)
        except json.decoder.JSONDecodeError:
            pass
        except socket.timeout:
            pass
        except Exception as e:
            logging.debug(e, exc_info=Debug.P_EXCEPTION)
        else:
            Thread(target=self.__receive_msg,
                   name='S:'+new_user.name, args=(new_user,), daemon=True).start()
            return
        # close socket
        try: sock.close()
        except: pass

    def __receive_msg(self, user):
        # Accept connection
        with self.lock:
            self.user.append(user)
        logging.info("New connection from {}".format(user.name))

        # pooling
        msg_prefix = b''
        msg_len = 0
        msg_body = b''
        user.sock.settimeout(3600)
        while not self.f_stop:
            try:
                if len(msg_prefix) == 0:

                    first_msg = user.sock.recv(self.buffsize)
                else:
                    first_msg, msg_prefix = msg_prefix, b''

                # Start receive message
                msg_len = int.from_bytes(first_msg[:4], 'big')
                msg_body = first_msg[4:]

                # Notice long message
                if Debug.F_LONG_MSG_INFO and msg_len != len(msg_body):
                    logging.debug("Receive long msg, len=%d, body=%d" % (msg_len, len(msg_body)))

                if msg_len == 0:
                    raise ConnectionAbortedError("1:Socket error, fall in loop.")
                elif len(msg_body) == 0:
                    raise ConnectionAbortedError("2:Socket error, fall in loop.")
                elif len(msg_body) >= msg_len:
                    msg_body, msg_prefix = msg_body[:msg_len], msg_body[msg_len:]
                    self.traffic.put_traffic_down(msg_body)
                    msg_body = AESCipher.decrypt(key=user.aeskey, enc=msg_body)
                    msg_body = zlib.decompress(msg_body)
                    self.core_que.broadcast((user, msg_body))
                    continue
                else:
                    pass

                # continue receiving message
                while True:
                    new_body = user.sock.recv(self.buffsize)
                    msg_body += new_body
                    if len(new_body) == 0:
                        raise ConnectionAbortedError("3:Socket error, fall in loop.")
                    elif len(msg_body) >= msg_len:
                        msg_body, msg_prefix = msg_body[:msg_len], msg_body[msg_len:]
                        self.traffic.put_traffic_down(msg_body)
                        msg_body = AESCipher.decrypt(key=user.aeskey, enc=msg_body)
                        msg_body = zlib.decompress(msg_body)
                        self.core_que.broadcast((user, msg_body))
                        break
                    elif len(msg_body) > C.MAX_RECEIVE_SIZE + 5000:
                        raise ConnectionAbortedError("Too many data! (MAX {}Kb)"
                                                     .format(C.MAX_RECEIVE_SIZE // 1000))
                    else:
                        continue

            except socket.timeout:
                logging.debug("socket timeout {}".format(user.name))
                break
            except ConnectionAbortedError:
                logging.debug("1ConnectionAbortedError", exc_info=Debug.P_EXCEPTION)
                logging.debug("2ConnectionAbortedError :len={}, msg={}".format(msg_len, msg_body))
                break
            except ConnectionResetError:
                logging.debug("ConnectionResetError by {}".format(user.name), exc_info=Debug.P_EXCEPTION)
                break
            except OSError as e:
                logging.debug("OSError by {}, {}".format(user.name, e), exc_info=Debug.P_EXCEPTION)
                break
            except Exception as e:
                logging.debug("BaseException by {}, {}".format(user.name, e), exc_info=Debug.P_EXCEPTION)
                break

        # raised exception on loop
        if not self.remove_connection(user):
            logging.debug("Failed remove user {}".format(user.name))

    def name2user(self, name):
        for user in self.user:
            if user.name == name:
                return user
        return None

    def host_port2user(self, host_port):
        for user in self.user:
            if host_port == user.get_host_port():
                return user
        return None
