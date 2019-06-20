from p2p_python.tool.utils import *
from p2p_python.tool.upnpc import *
from p2p_python.config import V, Debug, PeerToPeerError
from p2p_python.core import Core, ban_address
from p2p_python.utils import is_reachable
from p2p_python.user import User
from p2p_python.serializer import *
from expiringdict import ExpiringDict
from time import time
from logging import getLogger
from collections import deque
from typing import Dict, List, Optional
import asyncio
import os.path
import random
import socket


log = getLogger(__name__)
loop = asyncio.get_event_loop()
loop_futures: List[asyncio.Future] = list()
LOCAL_IP = get_localhost_ip()
GLOBAL_IPV4 = get_global_ip()
GLOBAL_IPV6 = get_global_ip_ipv6()
STICKY_LIMIT = 2

# Constant type
T_REQUEST = 'request'
T_RESPONSE = 'response'
T_ACK = 'ack'


class Peer2PeerCmd:
    # ノード間で内部的に用いるコマンド
    PING_PONG = 'ping-pong'  # ping-pong
    BROADCAST = 'broadcast'  # 全ノードに伝播
    GET_PEER_INFO = 'get-peer-info'  # 隣接ノードの情報を取得
    GET_NEARS = 'get-nears'  # ピアリストを取得
    CHECK_REACHABLE = 'check-reachable'  # 外部からServerに到達できるかチェック
    DIRECT_CMD = 'direct-cmd'  # 隣接ノードに直接CMDを打つ


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
        self._result_ques: Dict[int, asyncio.Future] = ExpiringDict(max_len=1000, max_age_seconds=900)
        self.peers = PeerData(os.path.join(V.DATA_PATH, 'peer.dat'))  # {(host, port): header,..}
        # recode traffic if f_debug true
        if Debug.F_RECODE_TRAFFIC:
            self.core.traffic.recode_dir = V.TMP_PATH
        # serializer/deserializer function
        self.default_hook = default_hook
        self.object_hook = object_hook

    def close(self):
        self.f_stop = True
        self.core.close()

    def setup(self, s_family=socket.AF_UNSPEC, f_stabilize=True):
        async def inner_loop():
            user: Optional[User] = None
            broadcast_task: Optional[asyncio.Future] = None
            log.info("start P2P inner loop")
            while not self.f_stop:
                try:
                    user, msg_body = await asyncio.wait_for(self.core.core_que.get(), 1.0)
                    item = loads(b=msg_body, object_hook=self.object_hook)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    log.debug(f"core que getting exception", exc_info=True)
                    continue

                if Debug.P_SEND_RECEIVE_DETAIL:
                    log.debug(f"receive => {item}")

                try:
                    if not isinstance(item, dict):
                        log.debug("unrecognized message receive")
                    elif item['type'] == T_REQUEST:
                        if item['cmd'] == Peer2PeerCmd.BROADCAST:
                            # broadcast cmd is another thread
                            if broadcast_task:
                                if not broadcast_task.done():
                                    await asyncio.wait_for(broadcast_task, 10.0)
                            # overwrite new task
                            broadcast_task = asyncio.ensure_future(self.type_request(user, item))
                        else:
                            await self.type_request(user, item)
                    elif item['type'] == T_RESPONSE:
                        await self.type_response(user, item)
                        user.header.update_last_seen()
                    elif item['type'] == T_ACK:
                        await self.type_ack(user, item)
                    else:
                        log.debug(f"unknown type={item['type']}")
                except asyncio.TimeoutError:
                    log.warning(f"timeout on broadcast and cancel task")
                    broadcast_task.cancel()
                except Exception:
                    log.debug(f"core que processing exception of {user}", exc_info=True)
            self.f_finish = True
            self.f_running = False
            log.info("close inner_loop process")

        self.core.start(s_family=s_family)
        if f_stabilize:
            loop_futures.append(asyncio.ensure_future(auto_stabilize_network(self)))
        # Processing
        loop_futures.append(asyncio.ensure_future(inner_loop()))
        log.info(f"start user, name={V.SERVER_NAME} port={V.P2P_PORT}")
        self.f_running = True

    async def type_request(self, user: User, item: dict):
        temperate = {
            'type': T_RESPONSE,
            'cmd': item['cmd'],
            'data': None,
            'time': time(),
            'uuid': item['uuid']
        }
        allows: List[User] = list()
        denys: List[User] = list()
        ack_list: List[User] = list()
        allow_udp = False

        if item['cmd'] == Peer2PeerCmd.PING_PONG:
            temperate['data'] = {
                'ping': item['data'],
                'pong': time(),
            }
            allows.append(user)

        elif item['cmd'] == Peer2PeerCmd.BROADCAST:
            if item['uuid'] in self._broadcast_uuid:
                return  # already get broadcast data
            elif item['uuid'] in self._result_ques:
                return  # I'm broadcaster, get from ack
            else:
                # try to check broadcast data
                if asyncio.iscoroutinefunction(self.broadcast_check):
                    broadcast_result = await asyncio.wait_for(self.broadcast_check(user, item['data']), 10.0)
                else:
                    broadcast_result = self.broadcast_check(user, item['data'])
                if broadcast_result:
                    user.score += 1
                    self._broadcast_uuid.append(item['uuid'])
                    allows = self.core.user.copy()
                    denys.append(user)
                    # send ACK
                    ack_list.append(user)
                    # send Response
                    temperate['type'] = T_REQUEST
                    temperate['data'] = item['data']
                    allow_udp = True
                else:
                    user.warn += 1
                    self._broadcast_uuid.append(item['uuid'])
                    return  # not allowed broadcast data

        elif item['cmd'] == Peer2PeerCmd.GET_PEER_INFO:
            # [[(host,port), header],..]
            temperate['data'] = [(host_port, header.getinfo()) for host_port, header in self.peers.copy().items()]
            allows.append(user)

        elif item['cmd'] == Peer2PeerCmd.GET_NEARS:
            # [[(host,port), header],..]
            temperate['data'] = [(user.get_host_port(), user.header.getinfo()) for user in self.core.user]
            allows.append(user)

        elif item['cmd'] == Peer2PeerCmd.CHECK_REACHABLE:
            try:
                port = item['data']['port']
            except Exception as e:
                port = user.header.p2p_port
            temperate['data'] = is_reachable(host=user.host_port[0], port=port)
            allows.append(user)

        elif item['cmd'] == Peer2PeerCmd.DIRECT_CMD:

            async def direct_cmd():
                data = item['data']
                temperate['data'] = await self.event.ignition(user, data['cmd'], data['data'])
                await self._send_many_users(item=temperate, allows=[user], denys=[])

            if 'cmd' in item['data'] and item['data']['cmd'] in self.event:
                asyncio.ensure_future(direct_cmd())
        else:
            pass

        # send message
        send_count = await self._send_many_users(item=temperate, allows=allows, denys=denys, allow_udp=allow_udp)
        # send ack
        ack_count = 0
        if len(ack_list) > 0:
            ack_temperate = temperate.copy()
            ack_temperate['type'] = T_ACK
            ack_temperate['data'] = send_count
            ack_count = await self._send_many_users(item=ack_temperate, allows=ack_list, denys=[])
        # debug
        if Debug.P_SEND_RECEIVE_DETAIL:
            log.debug(f"reply  => {temperate}")
            log.debug(f"status => all={len(self.core.user)} send={send_count} ack={ack_count}")

    async def type_response(self, user: User, item: dict):
        # cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']
        if uuid in self._result_ques:
            future = self._result_ques[uuid]
            if not future.done():
                future.set_result((user, data))

    async def type_ack(self, user: User, item: dict):
        # cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']

        if uuid in self._result_ques:
            future = self._result_ques[uuid]
            if not future.done():
                future.set_result((user, data))

    async def _send_many_users(self, item, allows: List[User], denys: List[User], allow_udp=False) -> int:
        """send to many user and return how many send"""
        msg_body = dumps(obj=item, default=self.default_hook)
        count = 0
        for user in allows:
            if user not in denys:
                try:
                    await self.core.send_msg_body(msg_body=msg_body, user=user, allow_udp=allow_udp)
                    count += 1
                except Exception as e:
                    user.warn += 1
                    log.debug(f"failed send msg to {user} by {str(e)}")
        return count

    async def send_command(self, cmd, data=None, uuid=None, user=None, timeout=10.0) -> (User, dict):
        assert 0 < timeout
        uuid = uuid if uuid else random.randint(10, 0xffffffff)
        # 1. Make template
        temperate = {
            'type': T_REQUEST,
            'cmd': cmd,
            'data': data,
            'time': time(),
            'uuid': uuid,
        }
        f_udp = False

        # 2. Setup allows to send nodes
        if len(self.core.user) == 0:
            raise PeerToPeerError('no client connection found')
        elif cmd == Peer2PeerCmd.BROADCAST:
            allows = self.core.user.copy()
            f_udp = True
        elif user is None:
            user = random.choice(self.core.user)
            allows = [user]
        elif user in self.core.user:
            allows = [user]
        else:
            raise PeerToPeerError("Not found user in list")

        # 3. Send message to a node or some nodes
        future = asyncio.Future()
        self._result_ques[uuid] = future
        send_num = await self._send_many_users(item=temperate, allows=allows, denys=[], allow_udp=f_udp)
        if send_num == 0:
            raise PeerToPeerError(f"We try to send no users? {len(self.core.user)}user connected")

        # 4. Get response
        try:
            await asyncio.wait_for(future, timeout)
            receive_user, item = future.result()
            receive_user.warn = 0
            return receive_user, item
        except asyncio.TimeoutError:
            future.cancel()
            if user:
                if 3 < user.warn:
                    await self.try_reconnect(user, reason="too many warn point")
                else:
                    user.warn += 1
            log.debug(f"timeout on sending cmd({cmd}) to {user}, id={uuid}")
        raise asyncio.TimeoutError(f"timeout cmd")

    async def try_reconnect(self, user, reason):
        self.core.remove_connection(user, reason)
        host_port = user.get_host_port()
        if await self.core.create_connection(host=host_port[0], port=host_port[1]):
            log.debug(f"reconnect success {user} {host_port}")
            return True
        else:
            log.warning(f"reconnect failed {user} {host_port}")
            return False

    async def send_direct_cmd(self, cmd, data, user=None) -> (User, dict):
        if len(self.core.user) == 0:
            raise PeerToPeerError('not found peers')
        user = user if user else random.choice(self.core.user)
        uuid = random.randint(100, 0xffffffff)
        send_data = {'cmd': cmd, 'data': data, 'uuid': uuid}
        receive_user, item = await self.send_command(Peer2PeerCmd.DIRECT_CMD, send_data, uuid, user)
        if user != receive_user:
            log.warning(f"do not match sender and receiver {user} != {receive_user}")
        return user, item

    @staticmethod
    def broadcast_check(user: User, data):
        """return true if spread to all connections"""
        return False  # overwrite


async def auto_stabilize_network(p2p: Peer2Peer):
    """automatic stabilize p2p network"""
    try:
        while not p2p.f_running:
            await asyncio.sleep(1.0)
        log.info("start auto stabilize loop")
        ignore_peers = {
            # ipv4
            (GLOBAL_IPV4, V.P2P_PORT),
            (LOCAL_IP, V.P2P_PORT),
            ('127.0.0.1', V.P2P_PORT),
            # ipv6
            (GLOBAL_IPV6, V.P2P_PORT, 0, 0),
            ('::1', V.P2P_PORT, 0, 0),
        }
        if len(p2p.peers) == 0:
            log.info("peer list is zero, need bootnode")
        else:
            need = max(1, p2p.core.backlog // 2)
            log.info(f"connect first nodes, min {need} users")
            peer_host_port = list(p2p.peers.keys())
            random.shuffle(peer_host_port)
            for host_port in peer_host_port:
                if host_port in ignore_peers:
                    p2p.peers.remove_from_memory(host_port)
                    continue
                header = p2p.peers.get(host_port)
                if header and header.p2p_accept:
                    if await p2p.core.create_connection(host=host_port[0], port=host_port[1]):
                        need -= 1
                    else:
                        p2p.peers.remove_from_memory(host_port)
                if need <= 0:
                    break
                else:
                    await asyncio.sleep(5)
    except Exception:
        log.debug("init auto stabilize exception", exc_info=True)
        return

    # start stabilize connection
    user_score = dict()
    sticky_nodes = dict()
    count = 0
    need_connection = 3
    while p2p.f_running:
        count += 1
        if len(p2p.core.user) <= need_connection:
            await asyncio.sleep(3)
        else:
            await asyncio.sleep(1.5 * (1 + random.random()) * len(p2p.core.user))
        if count % 24 == 1 and len(sticky_nodes) > 0:
            log.debug(f"clean sticky_nodes [{len(sticky_nodes)}=>0]")
            sticky_nodes.clear()
        try:
            if len(p2p.core.user) == 0 and len(p2p.peers) > 0:
                host_port = random.choice(list(p2p.peers.keys()))
                if host_port in ignore_peers:
                    p2p.peers.remove_from_memory(host_port)
                    continue
                if await p2p.core.create_connection(host_port[0], host_port[1]):
                    await asyncio.sleep(5)
                else:
                    p2p.peers.remove_from_memory(host_port)
                    continue
            elif len(p2p.core.user) == 0 and len(p2p.peers) == 0:
                await asyncio.sleep(10)
                continue

            # peer list update (user)
            for user in p2p.core.user:
                p2p.peers.add(user)

            # update near info
            sample_user, item = await p2p.send_command(cmd=Peer2PeerCmd.GET_NEARS)
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
            if len(p2p.core.user) > p2p.core.backlog * 2 // 3:  # Remove
                # スコアの下位半分を取得
                sorted_score = sorted(user_score.items(), key=lambda x: x[1])[:len(user_score) // 3]
                # 既接続のもののみを取得
                already_connected = tuple(user.get_host_port() for user in p2p.core.user)
                sorted_score = list(filter(lambda x: x[0] in already_connected, sorted_score))
                if len(sorted_score) == 0:
                    await asyncio.sleep(10)
                    continue
                log.debug(f"remove score {sorted_score}")
                host_port, score = random.choice(sorted_score)
                user = p2p.core.host_port2user(host_port)
                if user is None:
                    pass  # 既接続でない
                elif len(user.neers) < need_connection:
                    pass  # 接続数が少なすぎるノード
                elif p2p.core.remove_connection(user, 'low score user'):
                    log.debug(f"remove connection {score} {user} {host_port}")
                else:
                    log.warning("failed remove connection. Already disconnected?")
                    if p2p.peers.remove_from_memory(host_port):
                        del user_score[host_port]

            elif len(p2p.core.user) < p2p.core.backlog * 2 // 3:  # Join
                # スコア上位半分を取得
                sorted_score = sorted(
                    user_score.items(), key=lambda x: x[1], reverse=True)[:len(user_score) // 3]
                # 既接続を除く
                already_connected = tuple(user.get_host_port() for user in p2p.core.user)
                sorted_score = list(filter(lambda x:
                                           x[0] not in already_connected and
                                           sticky_nodes.get(x[0], 0) < STICKY_LIMIT,
                                           sorted_score))
                if len(sorted_score) == 0:
                    await asyncio.sleep(10)
                    continue
                log.debug(f"join score {sorted_score}")
                host_port, score = random.choice(sorted_score)
                if p2p.core.host_port2user(host_port):
                    continue  # 既に接続済み
                elif sticky_nodes.get(host_port, 0) > STICKY_LIMIT:
                    continue  # 接続不能回数大杉
                elif host_port in ignore_peers:
                    p2p.peers.remove_from_memory(host_port)
                    continue
                elif host_port[0] in ban_address:
                    continue  # BAN address
                elif await p2p.core.create_connection(host=host_port[0], port=host_port[1]):
                    log.debug(f"new connection {host_port}")
                else:
                    log.debug(f"failed connect try, remove {host_port}")
                    sticky_nodes[host_port] = sticky_nodes.get(host_port, 0) + 1
                    if p2p.peers.remove_from_memory(host_port):
                        del user_score[host_port]
            else:
                # check warning point too high user
                for user in sorted(p2p.core.user, key=lambda x: x.warn, reverse=True):
                    if user.warn < 5:
                        continue
                    if await p2p.core.ping(user, f_udp=False):
                        continue
                    # looks problem on this user
                    p2p.core.remove_connection(user, 'too many warn and ping failed')
                    break

        except asyncio.TimeoutError as e:
            log.info(f"stabilize {str(e)}")
        except PeerToPeerError as e:
            log.debug(f"Peer2PeerError: {str(e)}")
        except Exception:
            log.debug("stabilize exception", exc_info=True)
    log.error("auto stabilization closed")


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
