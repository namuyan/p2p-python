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
from typing import Dict, List, Set, Optional
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
TIMEOUT = 10.0

# Constant type
T_REQUEST = 'request'
T_RESPONSE = 'response'
T_ACK = 'ack'

# stabilize objects
user_score: Dict[tuple, int] = dict()
sticky_peers: Set[tuple] = set()
ignore_peers = set()


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

        # object control params
        self.f_stop = False
        self.f_finish = False
        self.f_running = False

        # co-objects
        self.core = Core(host='localhost' if f_local else None, listen=listen)
        self.peers = PeerData(os.path.join(V.DATA_PATH, 'peer.dat'))  # {(host, port): header,..}
        self.event = EventIgnition()  # DirectCmdを受け付ける窓口

        # data status control
        self.broadcast_status: Dict[int, asyncio.Future] = ExpiringDict(max_len=5000, max_age_seconds=90)
        self.result_futures: Dict[int, asyncio.Future] = ExpiringDict(max_len=5000, max_age_seconds=90)

        # recode traffic if f_debug true
        if Debug.F_RECODE_TRAFFIC:
            self.core.traffic.recode_dir = V.DATA_PATH

        # serializer/deserializer hook
        self.default_hook = default_hook
        self.object_hook = object_hook

    def close(self):
        self.f_stop = True
        self.core.close()

    def setup(self, s_family=socket.AF_UNSPEC, f_stabilize=True):
        async def inner_loop():
            log.info("start P2P inner loop")
            while not self.f_stop:
                try:
                    user, msg_body, push_time = await asyncio.wait_for(self.core.core_que.get(), 1.0)
                    item = loads(b=msg_body, object_hook=self.object_hook)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    log.debug(f"core que getting exception", exc_info=True)
                    continue

                if Debug.P_SEND_RECEIVE_DETAIL:
                    log.debug(f"receive {int(time()-push_time)}s => {item}")

                try:
                    if not isinstance(item, dict):
                        log.debug("unrecognized message receive")
                    elif item['type'] == T_REQUEST:
                        # process request asynchronously
                        asyncio.ensure_future(self.type_request(user, item, push_time))
                    elif item['type'] == T_RESPONSE:
                        await self.type_response(user, item)
                        user.header.update_last_seen()
                    elif item['type'] == T_ACK:
                        await self.type_ack(user, item)
                    else:
                        log.debug(f"unknown type={item['type']}")
                except asyncio.TimeoutError:
                    log.warning(f"timeout on broadcast and cancel task")
                    broadcast_task = None
                except Exception:
                    log.debug(f"core que processing exception of {user}", exc_info=True)
            self.f_finish = True
            self.f_running = False
            log.info("close inner_loop process")

        assert not loop.is_running(), "setup before event loop start!"
        self.core.start(s_family=s_family)
        if f_stabilize:
            loop_futures.append(asyncio.ensure_future(auto_stabilize_network(self)))
        # Processing
        loop_futures.append(asyncio.ensure_future(inner_loop()))
        log.info(f"start user, name={V.SERVER_NAME} port={V.P2P_PORT}")
        self.f_running = True

    async def type_request(self, user: User, item: dict, push_time: float):
        temperate = {
            'type': T_RESPONSE,
            'cmd': item['cmd'],
            'data': None,
            'time': None,
            'received': push_time,
            'uuid': item['uuid']
        }
        allows: List[User] = list()
        denys: List[User] = list()
        ack_list: List[User] = list()
        ack_status: Optional[bool] = None
        allow_udp = False

        if item['cmd'] == Peer2PeerCmd.PING_PONG:
            temperate['data'] = {
                'ping': item['data'],
                'pong': time(),
            }
            allows.append(user)

        elif item['cmd'] == Peer2PeerCmd.BROADCAST:
            if item['uuid'] in self.broadcast_status:
                # already get broadcast data, only send ACK
                future = self.broadcast_status[item['uuid']]
                # send ACK after broadcast_check finish
                await asyncio.wait_for(future, TIMEOUT)
                ack_status = future.result()
                ack_list.append(user)

            elif item['uuid'] in self.result_futures:
                # I'm broadcaster, get from ack
                ack_status = True
                ack_list.append(user)
            else:
                # set future
                future = asyncio.Future()
                self.broadcast_status[item['uuid']] = future
                # try to check broadcast data
                if asyncio.iscoroutinefunction(self.broadcast_check):
                    broadcast_result = await asyncio.wait_for(
                        self.broadcast_check(user, item['data']), TIMEOUT)
                else:
                    broadcast_result = self.broadcast_check(user, item['data'])
                # set broadcast result
                future.set_result(broadcast_result)
                # prepare response
                if broadcast_result:
                    user.score += 1
                    # send ACK
                    ack_status = True
                    ack_list.append(user)
                    # broadcast to all
                    allows = self.core.user.copy()
                    denys.append(user)
                    temperate['type'] = T_REQUEST
                    temperate['data'] = item['data']
                    allow_udp = True
                else:
                    user.warn += 1
                    # send ACK
                    ack_status = False
                    ack_list.append(user)

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
            except Exception:
                port = user.header.p2p_port
            try:
                temperate['data'] = await asyncio.wait_for(
                    is_reachable(host=user.host_port[0], port=port), TIMEOUT)
            except Exception:
                temperate['data'] = False
            allows.append(user)

        elif item['cmd'] == Peer2PeerCmd.DIRECT_CMD:
            data = item['data']
            if self.event.have_event(data['cmd']):
                allows.append(user)
                temperate['data'] = await asyncio.wait_for(
                    self.event.ignition(user, data['cmd'], data['data']), TIMEOUT)
        else:
            log.debug(f"not found request cmd '{item['cmd']}'")

        # send message
        temperate['time'] = time()
        send_count = await self._send_many_users(item=temperate, allows=allows, denys=denys, allow_udp=allow_udp)
        # send ack
        ack_count = 0
        if len(ack_list) > 0:
            assert ack_status is not None
            ack_temperate = temperate.copy()
            ack_temperate['type'] = T_ACK
            ack_temperate['data'] = ack_status
            ack_count = await self._send_many_users(item=ack_temperate, allows=ack_list, denys=[])
        # debug
        if Debug.P_SEND_RECEIVE_DETAIL:
            log.debug(f"reply  => {temperate}")
            log.debug(f"status => all={len(self.core.user)} send={send_count} ack={ack_count}")

    async def type_response(self, user: User, item: dict):
        # cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']
        if uuid in self.result_futures:
            future = self.result_futures[uuid]
            if not future.done():
                future.set_result((user, data))
            elif future.cancelled():
                log.debug(f"uuid={uuid} type_response failed, already future canceled")
            else:
                pass
        else:
            log.debug(f"uuid={uuid} type_response failed, not found uuid")

    async def type_ack(self, user: User, item: dict):
        # cmd = item['cmd']
        ack_status = bool(item['data'])
        uuid = item['uuid']

        if uuid in self.result_futures:
            future = self.result_futures[uuid]
            if ack_status and not future.done():
                future.set_result((user, ack_status))

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

    async def send_command(self, cmd, data=None, user=None, timeout=10.0, retry=2) -> (User, dict):
        assert 0.0 < timeout and 0 < retry
        uuid = random.randint(10, 0xffffffff)
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
        start = time()
        future = asyncio.Future()
        self.result_futures[uuid] = future

        # get best timeout
        if user is None:
            # broadcast-cmd
            best_timeout = timeout / retry
        else:
            # inner-cmd/direct-cmd
            average = user.average_process_time()
            if average is None:
                best_timeout = timeout / retry
            else:
                best_timeout = min(5.0, max(1.0, average * 10))

        f_timeout = False
        for _ in range(retry):
            send_num = await self._send_many_users(item=temperate, allows=allows, denys=[], allow_udp=f_udp)
            send_time = time()
            if send_num == 0:
                raise PeerToPeerError(f"We try to send no users? {len(self.core.user)}user connected")
            if Debug.P_SEND_RECEIVE_DETAIL:
                log.debug(f"send({send_num}) => {temperate}")

            # 4. Get response
            try:
                # avoid future canceled by wait_for
                await asyncio.wait_for(asyncio.shield(future), best_timeout)
                if 5.0 < time() - start:
                    log.debug(f"id={uuid}, command {int(time()-start)}s blocked by {user}")
                if user is not None:
                    user.process_time.append(time() - send_time)
                break
            except (asyncio.TimeoutError, asyncio.CancelledError):
                log.debug(f"id={uuid}, timeout now, cmd({cmd}) to {user}")
            except Exception:
                log.debug("send_command exception", exc_info=True)

            # 5. will lost packet
            log.debug(f"id={uuid}, will lost packet and retry")

        else:
            f_timeout = True

        # 6. timeout
        if f_timeout and user:
            if user.closed or not await self.core.ping(user):
                # already closed or ping failed -> reconnect
                await self.core.try_reconnect(user, reason="ping failed on send_command")
            else:
                log.debug("timeout and retry but ping success")

        # 7. return result
        if future.done():
            return future.result()
        else:
            future.cancel()
            raise asyncio.TimeoutError("timeout cmd")

    async def send_direct_cmd(self, cmd, data, user=None) -> (User, dict):
        if len(self.core.user) == 0:
            raise PeerToPeerError('not found peers')
        if callable(cmd):
            cmd = cmd.__name__
        assert isinstance(cmd, str)
        user = user if user else random.choice(self.core.user)
        send_data = {'cmd': cmd, 'data': data}
        receive_user, item = await self.send_command(Peer2PeerCmd.DIRECT_CMD, send_data, user)
        if user != receive_user:
            log.warning(f"do not match sender and receiver {user} != {receive_user}")
        return user, item

    @staticmethod
    def broadcast_check(user: User, data):
        """return true if spread to all connections"""
        return False  # overwrite


async def auto_stabilize_network(
        p2p: Peer2Peer,
        auto_reset_sticky=True,
        self_disconnect=False,
):
    """
    automatic stabilize p2p network
    params:
        auto_reset_sticky: (bool) You know connections but can not connect again and again,
            stabilizer mark "sticky" and ignore forever. This flag enable auto reset the mark.
        self_disconnect: (bool) stabilizer keep a number of connection same with listen/2.
            self disconnection avoid overflow backlog but will make unstable network.
    """
    # update ignore peers
    ignore_peers.update({
        # ipv4
        (GLOBAL_IPV4, V.P2P_PORT),
        (LOCAL_IP, V.P2P_PORT),
        ('127.0.0.1', V.P2P_PORT),
        # ipv6
        (GLOBAL_IPV6, V.P2P_PORT, 0, 0),
        ('::1', V.P2P_PORT, 0, 0),
    })

    # wait for P2P running
    while not p2p.f_running:
        await asyncio.sleep(1.0)
    log.info(f"start auto stabilize loop known={len(p2p.peers)}")

    # show info
    if len(p2p.peers) == 0:
        log.info("peer list is zero, need bootnode")

    # start stabilize connection
    count = 0
    need_connection = 3
    while p2p.f_running:
        count += 1

        # decide wait time
        if len(p2p.core.user) <= need_connection:
            wait_time = 3.0
        else:
            wait_time = 4.0 * (4.5 + random.random())  # wait 18s~20s

        # waiting
        while p2p.f_running and 0.0 < wait_time:
            await asyncio.sleep(0.1)
            wait_time -= 0.1

        # clear sticky
        if count % 13 == 0 and len(sticky_peers) > 0:
            if auto_reset_sticky:
                log.debug(f"clean sticky_nodes num={len(sticky_peers)}")
                sticky_peers.clear()

        try:
            # no connection and try to connect from peer list
            if 0 == len(p2p.core.user):
                if 0 < len(p2p.peers):
                    peers = list(p2p.peers.keys())
                    while 0 < len(peers) and len(p2p.core.user) < need_connection:
                        host_port = peers.pop()
                        if host_port in ignore_peers:
                            p2p.peers.remove_from_memory(host_port)
                        elif await p2p.core.create_connection(host_port[0], host_port[1]):
                            pass
                        else:
                            sticky_peers.add(host_port)
                    log.info(f"init connection num={len(p2p.core.user)}")
                    # wait when disconnected from network
                    if len(p2p.core.user) == 0:
                        wait_time = 15.0
                else:
                    log.info("no peer info and no connections, wait 5s")
                    wait_time = 5.0

                # waiting if required
                while p2p.f_running and 0.0 < wait_time:
                    await asyncio.sleep(0.1)
                    wait_time -= 0.1

            # update 1 user's neer info one by one
            if 0 < len(p2p.core.user):
                update_user = p2p.core.user[count % len(p2p.core.user)]
                _, item = await p2p.send_command(cmd=Peer2PeerCmd.GET_NEARS, user=update_user)
                update_user.update_neers(item)
                # peer list update
                p2p.peers.add(update_user)

            # Calculate score (高ければ優先度が高い)
            search = set(p2p.peers.keys())
            for user in p2p.core.user:
                for host_port in user.neers.keys():
                    search.add(host_port)
            search.difference_update(ignore_peers)
            search.difference_update(sticky_peers)
            for host_port in search:  # 第一・二層を含む
                score = 0
                score += sum(1 for user in p2p.core.user if host_port in user.neers)  # 第二層は加点
                score -= sum(1 for user in p2p.core.user if host_port == user.get_host_port())  # 第一層は減点
                user_score[host_port] = max(-20, min(20, score))
            if len(user_score) == 0:
                continue

            # Action join or remove or nothing
            if len(p2p.core.user) > p2p.core.backlog * 2 // 3:  # Remove
                if not self_disconnect:
                    continue
                # スコアの下位半分を取得
                sorted_score = sorted(user_score.items(), key=lambda x: x[1])[:len(user_score) // 3]
                # 既接続のもののみを取得
                already_connected = tuple(user.get_host_port() for user in p2p.core.user)
                sorted_score = list(filter(lambda x: x[0] in already_connected, sorted_score))
                if len(sorted_score) == 0:
                    continue
                log.debug(f"try to remove score {sorted_score}")
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
                    sticky_peers.add(host_port)
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
                                           x[0] not in sticky_peers,
                                           sorted_score))
                if len(sorted_score) == 0:
                    continue
                log.debug(f"join score {sorted_score}")
                host_port, score = random.choice(sorted_score)
                if p2p.core.host_port2user(host_port):
                    continue  # 既に接続済み
                elif host_port in sticky_peers:
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
                    sticky_peers.add(host_port)
                    if p2p.peers.remove_from_memory(host_port):
                        del user_score[host_port]
            else:
                pass

        except asyncio.TimeoutError as e:
            log.info(f"stabilize {str(e)}")
        except PeerToPeerError as e:
            log.debug(f"Peer2PeerError: {str(e)}")
        except Exception:
            log.debug("stabilize exception", exc_info=True)
    log.info("auto stabilize closed")


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
    "user_score",
    "sticky_peers",
]
