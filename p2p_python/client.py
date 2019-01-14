import os.path
import random
import queue
from collections import deque
import socket
from time import time, sleep
from hashlib import sha256
from threading import Thread, get_ident
from expiringdict import ExpiringDict
from nem_ed25519.base import Encryption
from p2p_python.config import C, V, Debug, PeerToPeerError
from p2p_python.core import Core, ban_address
from p2p_python.utils import is_reachable
from p2p_python.tool.utils import *
from p2p_python.tool.upnpc import UpnpClient
import p2p_python.msgpack as msgpack
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
    FILE_CHECK = 'cmd/client/file-check'  # Fileが存在するかHashをチェック
    FILE_GET = 'cmd/client/file-get'  # Fileの転送を依頼
    FILE_DELETE = 'cmd/client/file-delete'  # 全ノードからFileを消去
    DIRECT_CMD = 'cmd/client/direct-cmd'  # 隣接ノードに直接CMDを打つ


class PeerClient:
    def __init__(self, listen=15, f_local=False):
        assert V.DATA_PATH is not None, 'Setup p2p params before PeerClientClass init.'
        # status params
        self.f_stop = False
        self.f_finish = False
        self.f_running = False
        # connection objects
        self.p2p = Core(host='localhost' if f_local else None, listen=listen)
        self.broadcast_que = QueueStream()  # BroadcastDataが流れてくる
        self.event = EventIgnition()  # DirectCmdを受け付ける窓口
        self._broadcast_uuid = deque(maxlen=listen * 20)  # Broadcastされたuuid
        self._user2user_route = ExpiringDict(max_len=1000, max_age_seconds=900)
        self._result_ques = ExpiringDict(max_len=1000, max_age_seconds=900)
        self.peers = JsonDataBase(os.path.join(V.DATA_PATH, 'peer.dat'), listen // 2)  # {(host, port): header,..}
        # recode traffic if f_debug true
        if Debug.F_RECODE_TRAFFIC:
            self.p2p.traffic.recode_dir = V.TMP_PATH
        self.threadid = None

    def close(self):
        self.p2p.close()
        self.f_stop = True

    def start(self, s_family=socket.AF_UNSPEC, f_stabilize=True):
        temporary_que = queue.Queue(maxsize=3000)

        def processing():
            self.threadid = get_ident()
            channel = 'processing'
            while not self.f_stop:
                user = msg_body = None
                try:
                    user, msg_body = self.p2p.core_que.get(channel=channel, timeout=1)
                    item = msgpack.loads(msg_body)

                    if item['type'] == T_REQUEST:
                        if item['cmd'] == ClientCmd.BROADCAST:
                            # broadcastはCheckを含む為に別スレッド
                            temporary_que.put((user, item))
                        else:
                            self.type_request(user=user, item=item)
                    elif item['type'] == T_RESPONSE:
                        self.type_response(user=user, item=item)
                    elif item['type'] == T_ACK:
                        self.type_ack(user=user, item=item)
                    else:
                        log.debug("Unknown type {}".format(item['type']))
                except queue.Empty:
                    pass
                except Exception as e:
                    self.p2p.remove_connection(user)
                    log.debug("Processing error, ({}, {}, {})"
                              .format(user.name, msg_body, e), exc_info=Debug.P_EXCEPTION)
            self.p2p.core_que.remove(channel)
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
                    log.debug("Processing error, ({}, {})"
                              .format(user.name, e), exc_info=Debug.P_EXCEPTION)
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
            'uuid': item['uuid']}
        allow_list = list()
        deny_list = list()
        ack_list = list()
        f_udp = False

        if item['cmd'] == ClientCmd.PING_PONG:
            temperate['data'] = {
                'ping': item['data'],
                'pong': time()}
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
                self.broadcast_que.put(item['data'])
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
            temperate['data'] = self.peers.copy()
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.GET_NEARS:
            temperate['data'] = {user.get_host_port(): user.serialize() for user in self.p2p.user}
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.CHECK_REACHABLE:
            try:
                port = item['data']['port']
            except:
                port = user.p2p_port
            temperate['data'] = is_reachable(host=user.host_port[0], port=port)
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.FILE_CHECK:
            # {'hash': hash, 'uuid': uuid}
            file_hash = item['data']['hash']
            file_path = os.path.join(V.TMP_PATH, 'file.' + file_hash + '.dat')
            f_existence = os.path.exists(file_path)
            if 'uuid' in item['data']:
                f_asked = bool(item['data']['uuid'] in self._user2user_route)
            else:
                f_asked = False
            temperate['data'] = {'have': f_existence, 'asked': f_asked}
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.FILE_GET:
            def asking():
                # ファイル要求元のNodeに近いNode群を無視する
                nears_name = set(user_.name for user_ in self.p2p.user)
                best_name = list(nears_name - already_asked_user)
                random.shuffle(best_name)
                nears_name = list(nears_name)
                random.shuffle(nears_name)
                # nearを最後に探索するように並び替え
                try_to_ask_name = best_name + nears_name

                # ファイル所持Nodeを見つけたら即コマンド送る、それ以外は候補をリスト化
                candidates = list()
                for ask_name in try_to_ask_name:
                    try:
                        ask_user = self.p2p.name2user(ask_name)
                        if ask_user is None:
                            continue
                        send_data = {'hash': file_hash, 'uuid': item['uuid']}
                        dummy, data = self.send_command(cmd=ClientCmd.FILE_CHECK, user=ask_user,
                                                        data=send_data, timeout=2)
                    except Exception as e:
                        log.debug("Check file existence one by one, %s", e)
                        continue
                    if data['have']:
                        # ファイル所持Nodeを発見したのでGETを即送信
                        hopeful = ask_user
                        break
                    elif not data['asked']:
                        candidates.append(ask_user)
                    else:
                        pass
                else:
                    # 候補がいなければここで探索終了
                    if len(candidates) == 0:
                        temperate['type'] = T_RESPONSE
                        self._send_msg(item=temperate, allows=[user], denys=list())
                        log.debug("Asking, stop asking file.")
                        return
                    else:
                        hopeful = random.choice(candidates)  # 一番新しいのを候補

                log.debug("Asking, Candidate={}, ask=>{}".format(len(candidates), hopeful.name))
                try:
                    data = {'hash': file_hash, 'asked': nears_name}
                    self._user2user_route[item['uuid']] = (user, hopeful)
                    from_client, data = self.send_command(ClientCmd.FILE_GET, data,
                                                          item['uuid'], user=hopeful, timeout=5)
                    temperate['data'] = data
                    if data is None:
                        log.debug("Asking failed from {} {}".format(hopeful.name, file_hash))
                    else:
                        log.debug("Asking success {} {}".format(hopeful.name, file_hash))
                except Exception as e:
                    log.debug("Asking raised {} {} {}".format(hopeful.name, file_hash, e))
                    temperate['data'] = None
                temperate['type'] = T_RESPONSE
                count = self._send_msg(item=temperate, allows=[user], denys=list())
                log.debug("Response file to {} {}({})".format(user.name, count, file_hash))
                return

            def sending():
                with open(file_path, mode='br') as f:
                    raw = f.read()
                temperate['type'] = T_RESPONSE
                temperate['data'] = raw
                self._user2user_route[item['uuid']] = (user, user)
                if 0 < self._send_msg(item=temperate, allows=[user], denys=list()):
                    log.debug("Send file to {} {}".format(user.name, file_hash))
                else:
                    log.debug("Failed send file to {} {}".format(user.name, file_hash))

            if item['uuid'] in self._user2user_route:
                return
            log.debug("Asked file get by {}".format(user.name))
            file_hash = item['data']['hash']
            already_asked_user = set(item['data']['asked'])
            file_path = os.path.join(V.TMP_PATH, 'file.' + file_hash + '.dat')
            # When you have file, sending. When you don't have file, asking
            if os.path.exists(file_path):
                Thread(target=sending, name='Sending', daemon=True).start()
            elif V.F_FILE_CONTINUE_ASKING:
                # Default disable
                Thread(target=asking, name='Asking', daemon=True).start()

        elif item['cmd'] == ClientCmd.FILE_DELETE:
            item_ = item['data']
            file_hash = item_['hash']
            signer_pk = item_['signer']
            sign = item_['sign']
            cert_sign = item_['cert']['sign']
            master_pk = item_['cert']['master']
            cert_start = item_['cert']['start']
            cert_stop = item_['cert']['stop']

            if not (cert_start < int(time()) < cert_stop):
                return  # old signature
            elif master_pk not in C.MASTER_KEYS:
                return
            elif item['uuid'] in self._broadcast_uuid:
                return  # already get broadcast data
            elif item['uuid'] in self._result_ques:
                return  # I'm broadcaster, get from ack

            self._broadcast_uuid.append(item['uuid'])
            cert_raw = msgpack.dumps((master_pk, signer_pk, cert_start, cert_stop))
            sign_raw = msgpack.dumps((file_hash, item['uuid']))
            deny_list.append(user)
            allow_list = None
            # send ACK
            ack_list.append(user)
            # send Response
            temperate['type'] = T_REQUEST
            temperate['data'] = item['data']
            # delete file check
            try:
                log.debug("1:Delete request {}".format(file_hash))
                ecc = Encryption()
                ecc.pk = master_pk  # 署名者の署名者チェック
                ecc.verify(msg=cert_raw, signature=cert_sign)
                ecc.pk = signer_pk  # 署名者チェック
                ecc.verify(msg=sign_raw, signature=sign)
                if self.remove_file(file_hash):
                    log.info("2:Delete request accepted!")
            except ValueError:
                allow_list = list()  # No sending

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
            log.debug("Reply to request {} All={}, Send={}, Ack={}"
                      .format(temperate['cmd'], len(self.p2p.user), send_count, ack_count))

    def type_response(self, user, item):
        cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']
        if cmd == ClientCmd.FILE_GET:
            # origin check
            if uuid in self._user2user_route:
                ship_from, ship_to = self._user2user_route[uuid]
                if ship_to != user:
                    log.debug("Origin({}) differ from ({})".format(ship_to.name, user.name))
                    return
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
        msg_body = msgpack.dumps(item)
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
        temperate = {
            'type': T_REQUEST,
            'cmd': cmd,
            'data': data,
            'time': time(),
            'uuid': uuid}
        f_udp = False

        # 2. Setup allows to send nodes
        if len(self.p2p.user) == 0:
            raise ConnectionError('No client connection.')
        elif cmd == ClientCmd.BROADCAST:
            allows = self.p2p.user
            f_udp = True
        elif cmd == ClientCmd.FILE_DELETE:
            allows = self.p2p.user
        elif cmd == ClientCmd.FILE_GET:
            user = user if user else random.choice(self.p2p.user)
            self._user2user_route[uuid] = (None, user)
            allows = [user]
            timeout = 5
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
            if cmd == ClientCmd.BROADCAST:
                self.broadcast_que.put(data)
            # Timeout時に raise queue.Empty
            return user, item
        else:
            if user:
                if 5 < user.warn:
                    self.try_reconnect(user=user, reason="Timeout by waiting '{}'".format(cmd))
                raise TimeoutError('command timeout {} {} {} {}'.format(cmd, uuid, user.name, data))
            else:
                raise TimeoutError('command timeout on broadcast to {}users, {} {}'
                                   .format(len(allows), uuid, data))

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
        send_data = {
            'cmd': cmd,
            'data': data,
            'uuid': uuid}
        dummy, item = self.send_command(ClientCmd.DIRECT_CMD, send_data, uuid, user)
        return user, item

    @staticmethod
    def share_file(data):
        assert isinstance(data, bytes), "You need input raw binary data"
        assert len(data) <= C.MAX_RECEIVE_SIZE, "Your data({}kb) exceed MAX({}kb) size." \
            .format(len(data) // 1000, C.MAX_RECEIVE_SIZE // 1000)

        file_hash = sha256(data).hexdigest()
        file_path = os.path.join(V.TMP_PATH, 'file.' + file_hash + '.dat')
        with open(file_path, mode='bw') as f:
            f.write(data)
        return file_hash

    def get_file(self, file_hash, only_check=False):
        file_hash = file_hash.lower()
        file_path = os.path.join(V.TMP_PATH, 'file.' + file_hash + '.dat')
        if only_check:
            return os.path.exists(file_path)
        elif os.path.exists(file_path):
            with open(file_path, mode='br') as fp:
                return fp.read()
        else:
            # Ask all near nodes
            if len(self.p2p.user) == 0:
                raise FileReceiveError('No user found.')
            choose_users = self.p2p.user.copy()
            random.shuffle(choose_users)
            for user in choose_users:
                dummy, msg = self.send_command(ClientCmd.FILE_CHECK, data={'hash': file_hash, 'uuid': 0}, user=user)
                if msg['have']:
                    hopeful = user
                    break
            else:
                hopeful = random.choice(self.p2p.user)

            asked_nears = [user.name for user in self.p2p.user]
            log.debug("Ask file send to {}".format(hopeful.name))
            dummy, raw = self.send_command(
                cmd=ClientCmd.FILE_GET, data={'hash': file_hash, 'asked': asked_nears}, user=hopeful)
            if raw is None:
                raise FileReceiveError('Peers send me Null data. Please retry.')
            if sha256(raw).hexdigest() == file_hash:
                with open(file_path, mode='bw') as f:
                    f.write(raw)
                return True if only_check else raw
            else:
                raise FileReceiveError('File hash don\'t match. Please retry.')

    @staticmethod
    def remove_file(file_hash):
        try:
            file_hash = file_hash.lower()
            file_path = os.path.join(V.TMP_PATH, 'file.' + file_hash + '.dat')
            os.remove(file_path)
            return True
        except:
            return False

    @staticmethod
    def create_cert(master_sk, signer_pk, cert_start, cert_stop):
        assert int(time()) < cert_start < cert_stop, 'wrong time setting of cert.'
        master_ecc = Encryption()
        master_ecc.sk = master_sk
        cert_raw = msgpack.dumps((master_ecc.pk, signer_pk, cert_start, cert_stop))
        cert = {
            'master': master_ecc.pk,
            'start': cert_start,
            'stop': cert_stop,
            'sign': master_ecc.sign(cert_raw, encode='hex')}
        return cert

    def remove_file_by_master(self, signer_sk, cert, file_hash):
        file_hash = file_hash.lower()
        file_path = os.path.join(V.DATA_PATH, 'file.' + file_hash + '.dat')
        uuid = random.randint(10, 99999999)
        signer_ecc = Encryption()
        signer_ecc.sk = signer_sk
        try:
            os.remove(file_path)
            sign_raw = msgpack.dumps((file_hash, uuid))
            send_data = {
                'signer': signer_ecc.pk,
                'sign': signer_ecc.sign(msg=sign_raw, encode='hex'),
                'cert': cert}
            dummy, result = self.send_command(ClientCmd.FILE_DELETE, send_data, uuid=uuid)
            log.debug("File delete success.")
        except:
            log.debug("Failed delete file.")
            pass

    def stabilize(self):
        sleep(5)
        log.info("start stabilize.")
        ignore_peers = {
            (GLOBAL_IPV4, V.P2P_PORT),
            (GLOBAL_IPV6, V.P2P_PORT),
            (LOCAL_IP, V.P2P_PORT),
            ('127.0.0.1', V.P2P_PORT),
            ('::1', V.P2P_PORT)}
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
                header = self.peers[host_port]
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
                    self.peers[user.get_host_port()] = user.serialize()

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
                    sorted_score = [(host_port, score) for host_port, score in sorted_score
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
                    sorted_score = sorted(user_score.items(), key=lambda x: x[1], reverse=True)[:len(user_score) // 3]
                    # 既接続を除く
                    sorted_score = [(host_port, score) for host_port, score in sorted_score
                                    if host_port not in [user.get_host_port() for user in self.p2p.user]
                                    and sticky_nodes.get(host_port, 0) < STICKY_LIMIT]
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


class FileReceiveError(FileExistsError): pass
