from p2p_python.tool.utils import *
from p2p_python.tool.upnpc import *
from p2p_python.config import V, Debug, PeerToPeerError
from p2p_python.core import Core, ban_address
from p2p_python.utils import is_reachable
from p2p_python.user import User
from p2p_python.serializer import *
from threading import Thread, get_ident
from expiringdict import ExpiringDict
from time import time, sleep
from logging import getLogger
from collections import deque
import os.path
import random
import queue
import socket


log = getLogger(__name__)

LOCAL_IP = get_localhost_ip()
GLOBAL_IPV4 = get_global_ip()
GLOBAL_IPV6 = get_global_ip_ipv6()
STICKY_LIMIT = 2

# Constant type
T_REQUEST = 'type/client/request'
T_RESPONSE = 'type/client/response'
T_ACK = 'type/client/ack'


class Peer2PeerCmd:
    # ノード間で内部的に用いるコマンド
    PING_PONG = 'cmd/client/ping-pong'  # ping-pong
    BROADCAST = 'cmd/client/broadcast'  # 全ノードに伝播
    GET_PEER_INFO = 'cmd/client/get-peer-info'  # 隣接ノードの情報を取得
    GET_NEARS = 'cmd/client/get-nears'  # ピアリストを取得
    CHECK_REACHABLE = 'cmd/client/check-reachable'  # 外部からServerに到達できるかチェック
    DIRECT_CMD = 'cmd/client/direct-cmd'  # 隣接ノードに直接CMDを打つ


class Peer2Peer(object):

    def __init__(self, listen=15, f_local=False, default_hook=None, object_hook=None):
        assert V.DATA_PATH is not None, 'Setup p2p params before PeerClientClass init.'
        # status params
        self.f_stop = False
        self.f_finish = False
        self.f_running = False
        # connection objects
        self.core = Core(host='localhost' if f_local else None, listen=listen)
        self.event = EventIgnition()  # DirectCmdを受け付ける窓口
        self._broadcast_uuid = deque(maxlen=listen * 20)  # Broadcastされたuuid
        self._user2user_route = ExpiringDict(max_len=1000, max_age_seconds=900)
        self._result_ques = ExpiringDict(max_len=1000, max_age_seconds=900)
        self.peers = PeerData(os.path.join(V.DATA_PATH, 'peer.dat'))  # {(host, port): header,..}
        # recode traffic if f_debug true
        if Debug.F_RECODE_TRAFFIC:
            self.core.traffic.recode_dir = V.TMP_PATH
        self.threadid = None
        # serializer/deserializer function
        self.default_hook = default_hook
        self.object_hook = object_hook

    def close(self):
        self.core.close()
        self.f_stop = True

    def start(self, s_family=socket.AF_UNSPEC, f_stabilize=True):
        temporary_que = queue.Queue(maxsize=3000)

        def processing():
            self.threadid = get_ident()
            while not self.f_stop:
                user = msg_body = None
                try:
                    user, msg_body = self.core.core_que.get(timeout=1)
                    item = loads(b=msg_body, object_hook=self.object_hook)

                    if item['type'] == T_REQUEST:
                        if item['cmd'] == Peer2PeerCmd.BROADCAST:
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
                        log.debug(f"unknown type={item['type']}")
                except queue.Empty:
                    pass
                except Exception as e:
                    self.core.remove_connection(user)
                    log.debug(f"Processing error {user.name}", exc_info=Debug.P_EXCEPTION)
            self.f_finish = True
            self.f_running = False
            log.info("close processing")

        def broadcast():
            while not self.f_stop:
                user = None
                try:
                    user, item = temporary_que.get(timeout=1)
                    self.type_request(user=user, item=item)
                except queue.Empty:
                    pass
                except Exception as e:
                    log.debug(f"Processing error {user.name}", exc_info=Debug.P_EXCEPTION)
            log.info("close broadcast")

        self.core.start(s_family=s_family)
        if f_stabilize:
            Thread(target=auto_stabilize_network, args=(self,), name='Stabilize', daemon=True).start()
        # Processing
        Thread(target=processing, name='Process', daemon=True).start()
        Thread(target=broadcast, name="Broadcast", daemon=True).start()
        log.info(f"start user, name={V.SERVER_NAME} port={V.P2P_PORT}")
        self.f_running = True

    def type_request(self, user: User, item: dict):
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

        if item['cmd'] == Peer2PeerCmd.PING_PONG:
            temperate['data'] = {'ping': item['data'], 'pong': time()}
            allow_list.append(user)

        elif item['cmd'] == Peer2PeerCmd.BROADCAST:
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

        elif item['cmd'] == Peer2PeerCmd.GET_PEER_INFO:
            # [[(host,port), header],..]
            temperate['data'] = list(self.peers.copy().items())
            allow_list.append(user)

        elif item['cmd'] == Peer2PeerCmd.GET_NEARS:
            # [[(host,port), header],..]
            temperate['data'] = [(user.get_host_port(), user.serialize()) for user in self.core.user]
            allow_list.append(user)

        elif item['cmd'] == Peer2PeerCmd.CHECK_REACHABLE:
            try:
                port = item['data']['port']
            except Exception as e:
                port = user.p2p_port
            temperate['data'] = is_reachable(host=user.host_port[0], port=port)
            allow_list.append(user)

        elif item['cmd'] == Peer2PeerCmd.DIRECT_CMD:

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
            log.debug(f"reply to request {temperate['cmd']} {len(self.core.user)} {send_count} {ack_count}")

    def type_response(self, user: User, item: dict):
        cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']
        if uuid in self._result_ques:
            que = self._result_ques[uuid]
            if que:
                que.put((user, data))
            # log.debug("Get response from {}, cmd={}, uuid={}".format(user.name, cmd, uuid))
            # log.debug("2:Data is '{}'".format(trim_msg(str(data), 80)))

    def type_ack(self, user: User, item: dict):
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
            allows = self.core.user
        if denys is None:
            denys = list()

        c = 0
        for user in allows:
            if user not in denys:
                try:
                    self.core.send_msg_body(msg_body=msg_body, user=user, f_udp=f_udp)
                    c += 1
                except Exception as e:
                    user.warn += 1
                    if 5 < user.warn:
                        self.try_reconnect(user=user, reason="failed to send msg.")
                    log.debug(f"failed send msg to {user.name} {str(e)}")
        return c  # how many send

    def send_command(self, cmd, data=None, uuid=None, user=None, timeout=10):
        assert get_ident() != self.threadid, "The thread is used by p2p_python!"
        uuid = uuid if uuid else random.randint(10, 0xffffffff)
        # 1. Make template
        temperate = {'type': T_REQUEST, 'cmd': cmd, 'data': data, 'time': time(), 'uuid': uuid}
        f_udp = False

        # 2. Setup allows to send nodes
        if len(self.core.user) == 0:
            raise ConnectionError('No client connection.')
        elif cmd == Peer2PeerCmd.BROADCAST:
            allows = self.core.user
            f_udp = True
        elif user is None:
            user = random.choice(self.core.user)
            allows = [user]
        elif user in self.core.user:
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
            raise PeerToPeerError('We try to send no client? {}clients connected.'.format(len(self.core.user)))

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
        self.core.remove_connection(user, reason)
        host_port = user.get_host_port()
        if self.core.create_connection(host=host_port[0], port=host_port[1]):
            log.debug(f"reconnect success {user.name}:{host_port}")
        else:
            log.warning(f"reconnect failed {user.name}:{host_port}")

    def send_direct_cmd(self, cmd, data, user=None, uuid=None):
        if len(self.core.user) == 0:
            raise PeerToPeerError('No peers.')
        user = user if user else random.choice(self.core.user)
        uuid = uuid if uuid else random.randint(100, 0xffffffff)
        send_data = {'cmd': cmd, 'data': data, 'uuid': uuid}
        dummy, item = self.send_command(Peer2PeerCmd.DIRECT_CMD, send_data, uuid, user)
        return user, item

    @staticmethod
    def broadcast_check(data):
        """return true if spread to all connections"""
        return False  # overwrite


def auto_stabilize_network(p2p: Peer2Peer):
    """automatic stabilize p2p network"""
    while not p2p.f_running:
        sleep(1)
    log.info("start stabilize")
    ignore_peers = {
        (GLOBAL_IPV4, V.P2P_PORT),
        (GLOBAL_IPV6, V.P2P_PORT),
        (LOCAL_IP, V.P2P_PORT),
        ('127.0.0.1', V.P2P_PORT),
        ('::1', V.P2P_PORT),
    }
    if len(p2p.peers) == 0:
        log.info("peer list is zero, need bootnode")
    else:
        need = max(1, p2p.core.listen // 2)
        log.info(f"connect first nodes, min {need} users")
        peer_host_port = list(p2p.peers.keys())
        random.shuffle(peer_host_port)
        for host_port in peer_host_port:
            if host_port in ignore_peers:
                p2p.peers.remove(host_port)
                continue
            header = p2p.peers.get(host_port)
            if header['p2p_accept']:
                if p2p.core.create_connection(host=host_port[0], port=host_port[1]):
                    need -= 1
                else:
                    p2p.peers.remove(host_port)
            if need <= 0:
                break
            else:
                sleep(5)

    # Stabilize
    user_score = dict()
    sticky_nodes = dict()
    count = 0
    need_connection = 3
    while p2p.f_running:
        count += 1
        if len(p2p.core.user) <= need_connection:
            sleep(3)
        else:
            sleep(1.5 * (1 + random.random()) * len(p2p.core.user))
        if count % 24 == 1 and len(sticky_nodes) > 0:
            log.debug(f"clean sticky_nodes [{len(sticky_nodes)}=>0]")
            sticky_nodes.clear()
        try:
            if len(p2p.core.user) == 0 and len(p2p.peers) > 0:
                host_port = random.choice(list(p2p.peers.keys()))
                if host_port in ignore_peers:
                    p2p.peers.remove(host_port)
                    continue
                if p2p.core.create_connection(host_port[0], host_port[1]):
                    sleep(5)
                else:
                    p2p.peers.remove(host_port)
                    continue
            elif len(p2p.core.user) == 0 and len(p2p.peers) == 0:
                sleep(10)
                continue

            # peer list update (user)
            for user in p2p.core.user:
                p2p.peers.add(user.get_host_port(), user.serialize())

            # update near info
            sample_user, item = p2p.send_command(cmd=Peer2PeerCmd.GET_NEARS)
            sample_user.update_neers(item)

            # Calculate score (高ければ優先度が高い)
            search = set(p2p.peers.keys())
            for user in p2p.core.user:
                for host_port in user.neers.keys():
                    search.add(host_port)
            search.difference_update(ignore_peers)
            average = sum(user_score.values()) // len(user_score) if len(user_score) > 0 else 0
            for host_port in search:  # 第一・二層を含む
                score = user_score[host_port] if host_port in user_score else 20
                score -= average
                score += sum(1 for user in p2p.core.user if host_port in user.neers)  # 第二層は加点
                score -= sum(1 for user in p2p.core.user if host_port == user.get_host_port())  # 第一層は減点
                user_score[host_port] = max(-20, min(20, score))
            if len(user_score) == 0:
                continue

            # Action join or remove or nothing
            if len(p2p.core.user) > p2p.core.listen * 2 // 3:  # Remove
                # スコアの下位半分を取得
                sorted_score = sorted(user_score.items(), key=lambda x: x[1])[:len(user_score) // 3]
                # 既接続のもののみを取得
                sorted_score = [(host_port, score)
                                for host_port, score in sorted_score
                                if host_port in [user.get_host_port() for user in p2p.core.user]]
                if len(sorted_score) == 0:
                    sleep(10)
                    continue
                log.debug(f"remove score {sorted_score}")
                host_port, score = random.choice(sorted_score)
                user = p2p.core.host_port2user(host_port)
                if user is None:
                    pass  # 既接続でない
                elif len(user.neers) < need_connection:
                    pass  # 接続数が少なすぎるノード
                elif p2p.core.remove_connection(user):
                    log.debug(f"remove connection {score} {host_port}")
                else:
                    log.debug("failed remove connection. Already disconnected?")
                    if p2p.peers.remove(host_port):
                        del user_score[host_port]

            elif len(p2p.core.user) < p2p.core.listen * 2 // 3:  # Join
                # スコア上位半分を取得
                sorted_score = sorted(
                    user_score.items(), key=lambda x: x[1], reverse=True)[:len(user_score) // 3]
                # 既接続を除く
                sorted_score = [(host_port, score)
                                for host_port, score in sorted_score
                                if host_port not in [user.get_host_port() for user in p2p.core.user] and
                                sticky_nodes.get(host_port, 0) < STICKY_LIMIT]
                if len(sorted_score) == 0:
                    sleep(10)
                    continue
                log.debug(f"join score {sorted_score}")
                host_port, score = random.choice(sorted_score)
                if p2p.core.host_port2user(host_port):
                    continue  # 既に接続済み
                elif sticky_nodes.get(host_port, 0) > STICKY_LIMIT:
                    continue  # 接続不能回数大杉
                elif host_port in ignore_peers:
                    p2p.peers.remove(host_port)
                    continue
                elif host_port[0] in ban_address:
                    continue  # BAN address
                elif p2p.core.create_connection(host=host_port[0], port=host_port[1]):
                    log.debug(f"new connection {host_port}")
                else:
                    log.info(f"failed connect, remove {host_port}")
                    sticky_nodes[host_port] = sticky_nodes.get(host_port, 0) + 1
                    if p2p.peers.remove(host_port):
                        del user_score[host_port]
            else:
                # check connection alive by ping-pong
                user = random.choice(p2p.core.user)
                if p2p.core.ping(user=user, f_udp=False):
                    sleep(60)  # stable connection status
                else:
                    p2p.try_reconnect(user=user, reason='regular ping check failed')

        except TimeoutError as e:
            log.info(f"stabilize {str(e)}")
        except ConnectionError as e:
            log.debug(f"ConnectionError {str(e)}")
        except PeerToPeerError as e:
            log.debug(f"Peer2PeerError: {str(e)}")
        except Exception as e:
            log.debug(f"Stabilize {str(e)}", exc_info=True)
    log.error("go out from loop of stabilize")


__all__ = [
    "LOCAL_IP",
    "GLOBAL_IPV4",
    "GLOBAL_IPV6",
    "T_REQUEST",
    "T_RESPONSE",
    "T_ACK",
    "Peer2PeerCmd",
    "Peer2Peer",
    "auto_stabilize_network",
]
