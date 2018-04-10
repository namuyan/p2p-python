#!/user/env python3
# -*- coding: utf-8 -*-

import json
import logging
import random
import socket
import time
import zlib
from threading import Thread, Lock
from nem_ed25519.base import Encryption
from .tool.traffic import Traffic
from .tool.utils import AESCipher, QueueSystem
from .config import C, V, Debug, PeerToPeerError
from .user import User

# constant
SERVER_SIDE = 'Server'
CLIENT_SIDE = 'Client'


class Core(Thread):
    f_stop = False
    f_finish = False
    f_running = False
    server_sock = None

    def __init__(self, host='', listen=15, buffsize=2048):
        assert V.DATA_PATH is not None, 'Setup p2p params before CoreClass init.'
        super().__init__(name='InnerCore', daemon=True)
        self.start_time = int(time.time())
        self.number = 0
        self.user = list()
        self.lock = Lock()
        self.host = host
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
        try: self.server_sock.close()
        except: pass
        for user in self.user:
            try: user.sock.close()
            except: pass

    def run(self):
        self.traffic.start()
        # Pooling connection
        if not V.P2P_ACCEPT:
            logging.info('You set p2p accept flag False.')
            return

        sock = host_port = None
        server_sock = self.__create_server_sock()
        logging.info("Start server %d" % V.P2P_PORT)
        self.f_running = True
        while not self.f_stop:
            try:
                sock, host_port = server_sock.accept()
                Thread(target=self.__initial_connection_check,
                       args=(sock, host_port), daemon=True).start()

            except json.decoder.JSONDecodeError:
                try: sock.close()
                except: pass
                logging.debug("JSONDecodeError by {}".format(host_port[0]))
            except OSError as e:
                try: sock.close()
                except: pass
                logging.debug("OSError {}".format(e))
            except Exception as e:
                try: sock.close()
                except: pass
                logging.debug(e, exc_info=Debug.P_EXCEPTION)
        try: server_sock.close()
        except: pass
        self.f_finish = True
        self.f_running = False
        logging.info("Server closed.")

    def __create_server_sock(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, V.P2P_PORT))
        server_sock.listen(self.listen)
        self.server_sock = server_sock
        return server_sock

    def get_server_header(self):
        return {
            'name': V.SERVER_NAME,
            'client_ver': V.CLIENT_VER,
            'network_ver': V.NETWORK_VER,
            'p2p_accept': V.P2P_ACCEPT,
            'p2p_port': V.P2P_PORT,
            'start_time': self.start_time}

    def create_connection(self, host, port):
        host_port = (socket.gethostbyname(host), int(port))
        if self.host_port2user(host_port) is not None:
            return False  # Already connected.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect(host_port)
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
                   name='C:' + new_user.name, daemon=True, args=(new_user,)).start()

            c = 20
            while len(self.user) == 0 and c > 0:
                time.sleep(1)
                c -= 1
            if c == 0:
                return False
            else:
                return True
        except PeerToPeerError as e:
            try: sock.close()
            except: pass
            logging.debug("NewConnectionError {} {}".format(host_port, e), exc_info=Debug.P_EXCEPTION)
        except ConnectionRefusedError as e:
            try: sock.close()
            except: pass
            logging.debug("ConnectionRefusedError {} {}".format(host_port, e), exc_info=Debug.P_EXCEPTION)
        except Exception as e:
            try: sock.close()
            except: pass
            logging.error("NewConnectionError {} {}".format(host_port, e), exc_info=Debug.P_EXCEPTION)
        return False

    def remove_connection(self, user):
        with self.lock:
            if user in self.user:
                self.user.remove(user)
                try: user.close()
                except: pass
                logging.debug("remove connection to %s" % user.name)
                return True
            return False

    def send_msg_body(self, msg_body, user=None):
        assert type(msg_body) == bytes, 'msg_body is bytes'

        # get client
        if len(self.user) == 0:
            raise ConnectionError('client connection is zero.')
        elif len(msg_body) > C.MAX_RECEIVE_SIZE + 5000:
            raise ConnectionRefusedError('Max message size is {}Kb (You try {}Kb)'
                                         .format(C.MAX_RECEIVE_SIZE / 1000, len(msg_body) / 1000))
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
            Thread(target=self.__receive_msg, name='S:' + new_user.name,
                   daemon=True, args=(new_user,)).start()
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
                if msg_len != len(msg_body):
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
