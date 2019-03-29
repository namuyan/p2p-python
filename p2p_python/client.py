import os.path
import random
import queue
from collections import deque
import socket
from time import time, sleep
from threading import Thread, get_ident
from expiringdict import ExpiringDict
from p2p_python.config import V, Debug, PeerToPeerError
from p2p_python.core import Core, ban_address
from p2p_python.utils import is_reachable
from p2p_python.tool.utils import *
from p2p_python.tool.upnpc import UpnpClient
from p2p_python.serializer import *
from logging import getLogger

log = getLogger('p2p-python')

LOCAL_IP = UpnpClient.get_localhost_ip()
GLOBAL_IPV4 = UpnpClient.get_global_ip()
GLOBAL_IPV6 = UpnpClient.get_global_ip_ipv6()
STICKY_LIMIT = 2

# Constant type
T_REQUEST = 'type/client/request'
T_RESPONSE = 'type/client/response'
T_ACK = 'type/client/ack'


class ClientCmd:
    # ノード間で内部的に用いるコマンド
    PING_PONG = 'cmd/client/ping-pong'  # ping-pong
    BROADCAST = 'cmd/client/broadcast'  # 全ノードに伝播
    GET_PEER_INFO = 'cmd/client/get-peer-info'  # 隣接ノードの情報を取得
    GET_NEARS = 'cmd/client/get-nears'  # ピアリストを取得
    CHECK_REACHABLE = 'cmd/client/check-reachable'  # 外部からServerに到達できるかチェック
    DIRECT_CMD = 'cmd/client/direct-cmd'  # 隣接ノードに直接CMDを打つ


class PeerClient:

    def __init__(self, listen=15, f_local=False, default_hook=only_key_check, object_hook=None):
        assert V.DATA_PATH is not None, 'Setup p2p params before PeerClientClass init.'
        # status params
        self.f_stop = False
        self.f_finish = False
        self.f_running = False
        # connection objects
        self.p2p = Core(host='localhost' if f_local else None, listen=listen)
        self.event = EventIgnition()  # DirectCmdを受け付ける窓口
        self._broadcast_uuid = deque(maxlen=listen * 20)  # Broadcastされたuuid
        self._user2user_route = ExpiringDict(max_len=1000, max_age_seconds=900)
        self._result_ques = ExpiringDict(max_len=1000, max_age_seconds=900)
        self.peers = Peers(os.path.join(V.DATA_PATH, 'peer.dat'))  # {(host, port): header,..}
        # recode traffic if f_debug true
        if Debug.F_RECODE_TRAFFIC:
            self.p2p.traffic.recode_dir = V.TMP_PATH
        self.threadid = None
        # serializer/deserializer function
        self.default_hook = default_hook
        self.object_hook = object_hook

    def close(self):
        self.p2p.close()
        self.f_stop = True

    def start(self, s_family=socket.AF_UNSPEC, f_stabilize=True):
        temporary_que = queue.Queue(maxsize=3000)

        def processing():
            self.threadid = get_ident()
            while not self.f_stop:
                user = msg_body = None
                try:
                    user, msg_body = self.p2p.core_que.get(timeout=1)
                    item = loads(b=msg_body, object_hook=self.object_hook)

                    if item['type'] == T_REQUEST:
                        if item['cmd'] == ClientCmd.BROADCAST:
                            # broadcastはCheckを含む為に別スレッド
                            temporary_que.put((user, item))
                        else:
                            self.type_request(user=user, item=item)
                    elif item['type'] == T_RESPONSE:
                        self.type_response(user=user, item=item)
                        user.last_seen = int(time())
                    elif item['type'] == T_ACK:
                        self.type_ack(user=user, item=item)
                    else:
                        log.debug("Unknown type {}".format(item['type']))
                except queue.Empty:
                    pass
                except Exception as e:
                    self.p2p.remove_connection(user)
                    log.debug(
                        "Processing error, ({}, {}, {})".format(user.name, msg_body, e),
                        exc_info=Debug.P_EXCEPTION)
            self.f_finish = True
            self.f_running = False
            log.info("Close processing.")

        def broadcast():
            while not self.f_stop:
                user = None
                try:
                    user, item = temporary_que.get(timeout=1)
                    self.type_request(user=user, item=item)
                except queue.Empty:
                    pass
                except Exception as e:
                    log.debug("Processing error, ({}, {})".format(user.name, e), exc_info=Debug.P_EXCEPTION)
            log.info("Close broadcast.")

        self.f_running = True
        self.p2p.start(s_family)
        if f_stabilize:
            Thread(target=self.stabilize, name='Stabilize', daemon=True).start()
        # Processing
        Thread(target=processing, name='Process', daemon=True).start()
        Thread(target=broadcast, name="Broadcast", daemon=True).start()
        log.info("start user, name is {}, port is {}".format(V.SERVER_NAME, V.P2P_PORT))

    def type_request(self, user, item):
        temperate = {
            'type': T_RESPONSE,
            'cmd': item['cmd'],
            'data': None,
            'time': time(),
            'uuid': item['uuid']
        }
        allow_list = list()
        deny_list = list()
        ack_list = list()
        f_udp = False

        if item['cmd'] == ClientCmd.PING_PONG:
            temperate['data'] = {'ping': item['data'], 'pong': time()}
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.BROADCAST:
            if item['uuid'] in self._broadcast_uuid:
                return  # already get broadcast data
            elif item['uuid'] in self._result_ques:
                return  # I'm broadcaster, get from ack
            elif not self.broadcast_check(item['data']):
                user.warn += 1
                self._broadcast_uuid.append(item['uuid'])
                return  # not allowed broadcast data
            else:
                user.score += 1
                self._broadcast_uuid.append(item['uuid'])
                deny_list.append(user)
                allow_list = None
                # send ACK
                ack_list.append(user)
                # send Response
                temperate['type'] = T_REQUEST
                temperate['data'] = item['data']
                f_udp = True

        elif item['cmd'] == ClientCmd.GET_PEER_INFO:
            # [[(host,port), header],..]
            temperate['data'] = list(self.peers.copy().items())
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.GET_NEARS:
            # [[(host,port), header],..]
            temperate['data'] = [(user.get_host_port(), user.serialize()) for user in self.p2p.user]
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.CHECK_REACHABLE:
            try:
                port = item['data']['port']
            except Exception as e:
                port = user.p2p_port
            temperate['data'] = is_reachable(host=user.host_port[0], port=port)
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.DIRECT_CMD:

            def direct_cmd():
                data = item['data']
                temperate['data'] = self.event.work(cmd=data['cmd'], data=data['data'])
                self._send_msg(item=temperate, allows=[user])

            if 'cmd' in item['data'] and item['data']['cmd'] in self.event:
                Thread(target=direct_cmd, name='DirectCmd', daemon=True).start()
        else:
            pass

        # send message
        send_count = self._send_msg(item=temperate, allows=allow_list, denys=deny_list, f_udp=f_udp)
        # send ack
        ack_count = 0
        if len(ack_list) > 0:
            temperate['type'] = T_ACK
            temperate['data'] = send_count
            ack_count = self._send_msg(item=temperate, allows=ack_list)
        # debug
        if Debug.P_RECEIVE_MSG_INFO:
            log.debug("Reply to request {} All={}, Send={}, Ack={}".format(temperate['cmd'], len(
                self.p2p.user), send_count, ack_count))

    def type_response(self, user, item):
        cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']
        if uuid in self._result_ques:
            que = self._result_ques[uuid]
            if que:
                que.put((user, data))
            # log.debug("Get response from {}, cmd={}, uuid={}".format(user.name, cmd, uuid))
            # log.debug("2:Data is '{}'".format(trim_msg(str(data), 80)))

    def type_ack(self, user, item):
        cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']

        if uuid in self._result_ques:
            que = self._result_ques[uuid]
            if que:
                que.put((user, data))
            # log.debug("Get ack from {}".format(user.name))

    def _send_msg(self, item, allows=None, denys=None, f_udp=False):
        msg_body = dumps(obj=item, default=self.default_hook)
        if allows is None:
            allows = self.p2p.user
        if denys is None:
            denys = list()

        c = 0
        for user in allows:
            if user not in denys:
                try:
                    self.p2p.send_msg_body(msg_body=msg_body, user=user, f_udp=f_udp)
                    c += 1
                except Exception as e:
                    user.warn += 1
                    if 5 < user.warn:
                        self.try_reconnect(user=user, reason="failed to send msg.")
                    log.debug("Failed send msg to {} '{}'".format(user.name, e))
        return c  # how many send

    def send_command(self, cmd, data=None, uuid=None, user=None, timeout=10):
        assert get_ident() != self.threadid, "The thread is used by p2p_python!"
        uuid = uuid if uuid else random.randint(10, 0xffffffff)
        # 1. Make template
        temperate = {'type': T_REQUEST, 'cmd': cmd, 'data': data, 'time': time(), 'uuid': uuid}
        f_udp = False

        # 2. Setup allows to send nodes
        if len(self.p2p.user) == 0:
            raise ConnectionError('No client connection.')
        elif cmd == ClientCmd.BROADCAST:
            allows = self.p2p.user
            f_udp = True
        elif user is None:
            user = random.choice(self.p2p.user)
            allows = [user]
        elif user in self.p2p.user:
            allows = [user]
        else:
            raise ConnectionError("Not found client")
        if timeout <= 0:
            raise PeerToPeerError('timeout is zero.')

        # 3. Send message to a node or some nodes
        que = queue.Queue()
        self._result_ques[uuid] = que
        send_num = self._send_msg(item=temperate, allows=allows, f_udp=f_udp)
        if send_num == 0:
            raise PeerToPeerError('We try to send no client? {}clients connected.'.format(len(self.p2p.user)))

        # 4. Get response
        item = None
        try:
            user, item = que.get(timeout=timeout)
            user.warn = 0
            self._result_ques[uuid] = None
            f_success = True
        except queue.Empty:
            if user:
                user.warn += 1
            self._result_ques[uuid] = None
            f_success = False

        # 5. Process response
        if f_success:
            return user, item
        else:
            if user:
                if 5 < user.warn:
                    self.try_reconnect(user=user, reason="Timeout by waiting '{}'".format(cmd))
                raise TimeoutError('command timeout {} {} {} {}'.format(cmd, uuid, user.name, data))
            else:
                raise TimeoutError('command timeout on broadcast to {}users, {} {}'.format(
                    len(allows), uuid, data))

    def try_reconnect(self, user, reason=None):
        self.p2p.remove_connection(user, reason)
        host_port = user.get_host_port()
        if self.p2p.create_connection(host=host_port[0], port=host_port[1]):
            log.debug("Reconnect to {}:{} is success".format(user.name, host_port))
        else:
            log.warning("Reconnect to {}:{} is failed".format(user.name, host_port))

    def send_direct_cmd(self, cmd, data, user=None, uuid=None):
        if len(self.p2p.user) == 0:
            raise PeerToPeerError('No peers.')
        user = user if user else random.choice(self.p2p.user)
        uuid = uuid if uuid else random.randint(100, 0xffffffff)
        send_data = {'cmd': cmd, 'data': data, 'uuid': uuid}
        dummy, item = self.send_command(ClientCmd.DIRECT_CMD, send_data, uuid, user)
        return user, item

    def stabilize(self):
        sleep(5)
        log.info("start stabilize.")
        ignore_peers = {(GLOBAL_IPV4, V.P2P_PORT), (GLOBAL_IPV6, V.P2P_PORT), (LOCAL_IP, V.P2P_PORT),
                        ('127.0.0.1', V.P2P_PORT), ('::1', V.P2P_PORT)}
        if len(self.peers) == 0:
            log.info("peer list is zero, need bootnode.")
        else:
            need = max(1, self.p2p.listen // 2)
            log.info("Connect first nodes, min %d users." % need)
            peer_host_port = list(self.peers.keys())
            random.shuffle(peer_host_port)
            for host_port in peer_host_port:
                if host_port in ignore_peers:
                    self.peers.remove(host_port)
                    continue
                header = self.peers.get(host_port)
                if header['p2p_accept']:
                    if self.p2p.create_connection(host=host_port[0], port=host_port[1]):
                        need -= 1
                    else:
                        self.peers.remove(host_port)
                if need <= 0:
                    break
                else:
                    sleep(5)

        # Stabilize
        user_score = dict()
        sticky_nodes = dict()
        count = 0
        need_connection = 3
        while not self.f_stop:
            count += 1
            if len(self.p2p.user) <= need_connection:
                sleep(3)
            else:
                sleep(1.5 * (1 + random.random()) * len(self.p2p.user))
            if count % 24 == 1 and len(sticky_nodes) > 0:
                log.debug("Clean sticky_nodes. [{}=>0]".format(len(sticky_nodes)))
                sticky_nodes.clear()
            try:
                if len(self.p2p.user) == 0 and len(self.peers) > 0:
                    host_port = random.choice(list(self.peers.keys()))
                    if host_port in ignore_peers:
                        self.peers.remove(host_port)
                        continue
                    if self.p2p.create_connection(host_port[0], host_port[1]):
                        sleep(5)
                    else:
                        self.peers.remove(host_port)
                        continue
                elif len(self.p2p.user) == 0 and len(self.peers) == 0:
                    sleep(10)
                    continue

                # peer list update (user)
                for user in self.p2p.user:
                    self.peers.add(user.get_host_port(), user.serialize())

                # update near info
                sample_user, item = self.send_command(cmd=ClientCmd.GET_NEARS)
                sample_user.update_neers(item)

                # Calculate score (高ければ優先度が高い)
                search = set(self.peers.keys())
                for user in self.p2p.user:
                    for host_port in user.neers.keys():
                        search.add(host_port)
                search.difference_update(ignore_peers)
                average = sum(user_score.values()) // len(user_score) if len(user_score) > 0 else 0
                for host_port in search:  # 第一・二層を含む
                    score = user_score[host_port] if host_port in user_score else 20
                    score -= average
                    score += sum(1 for user in self.p2p.user if host_port in user.neers)  # 第二層は加点
                    score -= sum(1 for user in self.p2p.user if host_port == user.get_host_port())  # 第一層は減点
                    user_score[host_port] = max(-20, min(20, score))
                if len(user_score) == 0:
                    continue

                # Action join or remove or nothing
                if len(self.p2p.user) > self.p2p.listen * 2 // 3:  # Remove
                    # スコアの下位半分を取得
                    sorted_score = sorted(user_score.items(), key=lambda x: x[1])[:len(user_score) // 3]
                    # 既接続のもののみを取得
                    sorted_score = [(host_port, score)
                                    for host_port, score in sorted_score
                                    if host_port in [user.get_host_port() for user in self.p2p.user]]
                    if len(sorted_score) == 0:
                        sleep(10)
                        continue
                    log.debug("Remove Score {}".format(sorted_score))
                    host_port, score = random.choice(sorted_score)
                    user = self.p2p.host_port2user(host_port)
                    if user is None:
                        pass  # 既接続でない
                    elif len(user.neers) < need_connection:
                        pass  # 接続数が少なすぎるノード
                    elif self.p2p.remove_connection(user):
                        log.debug("Remove connection {} {}".format(host_port, score))
                    else:
                        log.debug("Failed remove connection. Already disconnected?")
                        if self.peers.remove(host_port):
                            del user_score[host_port]

                elif len(self.p2p.user) < self.p2p.listen * 2 // 3:  # Join
                    # スコア上位半分を取得
                    sorted_score = sorted(
                        user_score.items(), key=lambda x: x[1], reverse=True)[:len(user_score) // 3]
                    # 既接続を除く
                    sorted_score = [(host_port, score)
                                    for host_port, score in sorted_score
                                    if host_port not in [user.get_host_port() for user in self.p2p.user] and
                                    sticky_nodes.get(host_port, 0) < STICKY_LIMIT]
                    if len(sorted_score) == 0:
                        sleep(10)
                        continue
                    log.debug("Join Score {}".format(sorted_score))
                    host_port, score = random.choice(sorted_score)
                    if self.p2p.host_port2user(host_port):
                        continue  # 既に接続済み
                    elif sticky_nodes.get(host_port, 0) > STICKY_LIMIT:
                        continue  # 接続不能回数大杉
                    elif host_port in ignore_peers:
                        self.peers.remove(host_port)
                        continue
                    elif host_port[0] in ban_address:
                        continue  # BAN address
                    elif self.p2p.create_connection(host=host_port[0], port=host_port[1]):
                        log.debug("New connection {}".format(host_port))
                    else:
                        log.info("Failed connect, remove {}".format(host_port))
                        sticky_nodes[host_port] = sticky_nodes.get(host_port, 0) + 1
                        if self.peers.remove(host_port):
                            del user_score[host_port]
                else:
                    # check connection alive by ping-pong
                    user = random.choice(self.p2p.user)
                    if self.p2p.ping(user=user, f_udp=False):
                        sleep(60)  # stable connection status
                    else:
                        self.try_reconnect(user=user, reason='regular ping check failed')

            except TimeoutError as e:
                log.info("Stabilize {}".format(e))
            except ConnectionError as e:
                log.debug("ConnectionError {}".format(e))
            except PeerToPeerError as e:
                log.debug("Peer2PeerError: {}".format(e))
            except Exception as e:
                log.debug("Stabilize {}".format(e), exc_info=True)
        log.error("Get out from loop of stabilize.")

    @staticmethod
    def broadcast_check(data):
        return False  # overwrite


class FileReceiveError(FileExistsError):
    pass
