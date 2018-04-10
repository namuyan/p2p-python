#!/user/env python3
# -*- coding: utf-8 -*-


import time
import logging
import bjson
import os.path
import random
import copy
import queue
import collections
from hashlib import sha256
from threading import Thread
from nem_ed25519.base import Encryption
from .config import C, V, Debug, PeerToPeerError
from .core import Core
from .utils import is_reachable
from .tool.utils import StackDict, EventIgnition, JsonDataBase, QueueSystem
from .tool.upnpc import UpnpClient

LOCAL_IP = UpnpClient.get_localhost_ip()
GLOBAL_IP = UpnpClient.get_global_ip()


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
    f_stop = False
    f_finish = False
    f_running = False

    def __init__(self, listen=15, f_local=False):
        assert V.DATA_PATH is not None, 'Setup p2p params before PeerClientClass init.'
        self.p2p = Core(host='127.0.0.1' if f_local else '', listen=listen)
        self.broadcast_que = QueueSystem()  # BroadcastDataが流れてくる
        self.event = EventIgnition()  # DirectCmdを受け付ける窓口
        self.__broadcast_uuid = collections.deque(maxlen=listen*20)  # Broadcastされたuuid
        self.__user2user_route = StackDict()
        self.__waiting_result = StackDict()
        self.peers = JsonDataBase(path=os.path.join(V.DATA_PATH, 'peer.dat'))  # {(host, port): header,..}
        # recode traffic if f_debug true
        if Debug.F_RECODE_TRAFFIC:
            self.p2p.traffic.recode_dir = V.TMP_PATH

    def close(self):
        self.p2p.close()
        self.f_stop = True

    def start(self, f_stabilize=True):
        def processing():
            que = self.p2p.core_que.create()
            while not self.f_stop:
                user = msg_body = None
                try:
                    user, msg_body = que.get(timeout=1)
                    item = bjson.loads(msg_body)

                    if item['type'] == T_REQUEST:
                        self.type_request(user=user, item=item)
                    elif item['type'] == T_RESPONSE:
                        self.type_response(user=user, item=item)
                    elif item['type'] == T_ACK:
                        self.type_ack(user=user, item=item)
                    else:
                        logging.debug("Unknown type {}".format(item['type']))
                except bjson.BJsonBaseError:
                    self.p2p.remove_connection(user)
                    logging.debug("BJsonBaseError", exc_info=Debug.P_EXCEPTION)
                except queue.Empty:
                    pass
                except Exception as e:
                    logging.debug("Processing error, ({}, {}, {})"
                                  .format(user.name, msg_body, e), exc_info=Debug.P_EXCEPTION)
            self.f_finish = True
            self.f_running = False
            logging.info("Close process.")
        self.f_running = True
        self.p2p.start()
        if f_stabilize:
            Thread(target=self.stabilize, name='Stabilize', daemon=True).start()
        # Processing
        Thread(target=processing, name='Process', daemon=True).start()
        logging.info("start user, name is {}, port is {}".format(V.SERVER_NAME, V.P2P_PORT))

    def type_request(self, user, item):
        temperate = {
            'type': T_RESPONSE,
            'cmd': item['cmd'],
            'data': None,
            'time': time.time(),
            'uuid': item['uuid']}
        allow_list = list()
        deny_list = list()
        ack_list = list()

        if item['cmd'] == ClientCmd.PING_PONG:
            temperate['data'] = {
                'ping': item['data'],
                'pong': time.time()}
            allow_list.append(user)

        elif item['cmd'] == ClientCmd.BROADCAST:
            if item['uuid'] in self.__broadcast_uuid:
                return  # already get broadcast data
            elif self.__waiting_result.include(item['uuid']):
                return  # I'm broadcaster, get from ack
            elif not self.broadcast_check(item['data']):
                user.warn += 1
                self.__broadcast_uuid.append(item['uuid'])
                return  # not allowed broadcast data
            else:
                self.__broadcast_uuid.append(item['uuid'])
                self.broadcast_que.broadcast(item['data'])
                deny_list.append(user)
                allow_list = None
                # send ACK
                ack_list.append(user)
                # send Response
                temperate['type'] = T_REQUEST
                temperate['data'] = item['data']

        elif item['cmd'] == ClientCmd.GET_PEER_INFO:
            # [[(host,port), header],..]
            temperate['data'] = self.peers.data
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
                f_asked = self.__user2user_route.include(item['data']['uuid'])
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
                        logging.debug("Check file existence one by one, %s", e)
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
                        logging.debug("Asking, stop asking file.")
                        return
                    else:
                        hopeful = random.choice(candidates)  # 一番新しいのを候補

                logging.debug("Asking, Candidate={}, ask=>{}".format(len(candidates), hopeful.name))
                try:
                    data = {'hash': file_hash, 'asked': nears_name}
                    self.__user2user_route.put(uuid=item['uuid'], item=(user, hopeful))
                    from_client, data = self.send_command(ClientCmd.FILE_GET, data,
                                                          item['uuid'], user=hopeful, timeout=5)
                    temperate['data'] = data
                    if data is None:
                        logging.debug("Asking failed from {} {}".format(hopeful.name, file_hash))
                    else:
                        logging.debug("Asking success {} {}".format(hopeful.name, file_hash))
                except Exception as e:
                    logging.debug("Asking raised {} {} {}".format(hopeful.name, file_hash, e))
                    temperate['data'] = None
                temperate['type'] = T_RESPONSE
                count = self._send_msg(item=temperate, allows=[user], denys=list())
                logging.debug("Response file to {} {}({})".format(user.name, count, file_hash))
                return

            def sending():
                with open(file_path, mode='br') as f:
                    raw = f.read()
                temperate['type'] = T_RESPONSE
                temperate['data'] = raw
                self.__user2user_route.put(uuid=item['uuid'], item=(user, user))
                if 0 < self._send_msg(item=temperate, allows=[user], denys=list()):
                    logging.debug("Send file to {} {}".format(user.name, file_hash))
                else:
                    logging.debug("Failed send file to {} {}".format(user.name, file_hash))

            if self.__user2user_route.include(item['uuid']):
                return
            logging.debug("Asked file get by {}".format(user.name))
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

            if not(cert_start < int(time.time()) < cert_stop):
                return  # old signature
            elif master_pk not in C.MASTER_KEYS:
                return
            elif item['uuid'] in self.__broadcast_uuid:
                return  # already get broadcast data
            elif self.__waiting_result.include(item['uuid']):
                return  # I'm broadcaster, get from ack

            self.__broadcast_uuid.append(item['uuid'])
            cert_raw = bjson.dumps((master_pk, signer_pk, cert_start, cert_stop), compress=False)
            sign_raw = bjson.dumps((file_hash, item['uuid']), compress=False)
            deny_list.append(user)
            allow_list = None
            # send ACK
            ack_list.append(user)
            # send Response
            temperate['type'] = T_REQUEST
            temperate['data'] = item['data']
            # delete file check
            try:
                logging.debug("1:Delete request {}".format(file_hash))
                ecc = Encryption()
                ecc.pk = master_pk  # 署名者の署名者チェック
                ecc.verify(msg=cert_raw, signature=cert_sign)
                ecc.pk = signer_pk  # 署名者チェック
                ecc.verify(msg=sign_raw, signature=sign)
                if self.remove_file(file_hash):
                    logging.info("2:Delete request accepted!")
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
        send_count = self._send_msg(item=temperate, allows=allow_list, denys=deny_list)
        # send ack
        ack_count = 0
        if len(ack_list) > 0:
            temperate['type'] = T_ACK
            temperate['data'] = send_count
            ack_count = self._send_msg(item=temperate, allows=ack_list)
        # debug
        logging.debug("Reply to request {} All={}, Send={}, Ack={}"
                      .format(temperate['cmd'], len(self.p2p.user), send_count, ack_count))

    def type_response(self, user, item):
        cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']
        if cmd == ClientCmd.FILE_GET:
            # origin check
            if self.__user2user_route.include(uuid):
                ship_from, ship_to = self.__user2user_route.get(uuid)
                if ship_to != user:
                    logging.debug("Origin({}) differ from ({})".format(ship_to.name, user.name))
                    return
        if self.__waiting_result.include(uuid):
            que = self.__waiting_result.get(uuid)
            que.put((user, data))
            # logging.debug("Get response from {}, cmd={}, uuid={}".format(user.name, cmd, uuid))
            # logging.debug("2:Data is '{}'".format(trim_msg(str(data), 80)))

    def type_ack(self, user, item):
        cmd = item['cmd']
        data = item['data']
        uuid = item['uuid']

        if self.__waiting_result.include(uuid):
            que = self.__waiting_result.get(uuid)
            que.put((user, data))
            # logging.debug("Get ack from {}".format(user.name))

    def _send_msg(self, item, allows=None, denys=None):
        msg_body = bjson.dumps(item)
        if allows is None:
            allows = self.p2p.user
        if denys is None:
            denys = list()

        c = 0
        for user in allows:
            if user not in denys:
                try:
                    self.p2p.send_msg_body(msg_body=msg_body, user=user)
                except Exception as e:
                    logging.debug("Failed send msg to {}, {}".format(user.name, e))
                c += 1
        return c  # 送った送信先

    def send_command(self, cmd, data=None, uuid=None, user=None, timeout=10):
        uuid = uuid if uuid else random.randint(10, 0xffffffff)
        temperate = {
            'type': T_REQUEST,
            'cmd': cmd,
            'data': data,
            'time': time.time(),
            'uuid': uuid}
        if len(self.p2p.user) == 0:
            raise ConnectionError('No client connection.')
        elif cmd == ClientCmd.BROADCAST:
            allows = self.p2p.user
        elif cmd == ClientCmd.FILE_DELETE:
            allows = self.p2p.user
        elif cmd == ClientCmd.FILE_GET:
            user = user if user else random.choice(self.p2p.user)
            self.__user2user_route.put(uuid=uuid, item=(None, user))
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
        # ネットワークにメッセージを送信
        que = queue.LifoQueue()
        self.__waiting_result.put(uuid, que)
        self._send_msg(item=temperate, allows=allows)
        # 返事が返ってくるのを待つ
        try:
            user, item = que.get(timeout=timeout)
            user.warn = 0
        except queue.Empty:
            self.p2p.remove_connection(user)
            name = user.name if user else 'ManyUser({})'.format(len(allows))
            raise TimeoutError('command timeout {} {} {} {}'.format(cmd, uuid, name, data))

        if cmd == ClientCmd.BROADCAST:
            self.broadcast_que.broadcast(data)
        # Timeout時に raise queue.Empty
        return user, item

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
        assert len(data) <= C.MAX_RECEIVE_SIZE, "Your data({}kb) exceed MAX({}kb) size."\
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
            choose_users = copy.copy(self.p2p.user)
            random.shuffle(choose_users)
            for user in choose_users:
                dummy, msg = self.send_command(ClientCmd.FILE_CHECK, data={'hash': file_hash, 'uuid': 0}, user=user)
                if msg['have']:
                    hopeful = user
                    break
            else:
                hopeful = random.choice(self.p2p.user)

            asked_nears = [user.name for user in self.p2p.user]
            logging.debug("Ask file send to {}".format(hopeful.name))
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
        assert int(time.time()) < cert_start < cert_stop, 'wrong time setting of cert.'
        master_ecc = Encryption()
        master_ecc.sk = master_sk
        cert_raw = bjson.dumps((master_ecc.pk, signer_pk, cert_start, cert_stop), compress=False)
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
            sign_raw = bjson.dumps((file_hash, uuid), compress=False)
            send_data = {
                'signer': signer_ecc.pk,
                'sign': signer_ecc.sign(msg=sign_raw, encode='hex'),
                'cert': cert}
            dummy, result = self.send_command(ClientCmd.FILE_DELETE, send_data, uuid=uuid)
            logging.debug("File delete success.")
        except:
            logging.debug("Failed delete file.")
            pass

    def stabilize(self):
        time.sleep(5)
        logging.info("start stabilize.")
        ignore_peers = {
            (GLOBAL_IP, V.P2P_PORT),
            (LOCAL_IP, V.P2P_PORT),
            ('127.0.0.1', V.P2P_PORT)}
        if len(self.peers) == 0:
            logging.info("peer list is zero, need bootnode.")
        else:
            need = max(1, self.p2p.listen // 2)
            logging.info("Connect first nodes, min %d users." % need)
            peer_host_port = list(self.peers.keys())
            random.shuffle(peer_host_port)
            for host_port in peer_host_port:
                if host_port in ignore_peers:
                    del self.peers[host_port]
                    continue
                header = self.peers[host_port]
                if header['p2p_accept']:
                    if self.p2p.create_connection(host=host_port[0], port=host_port[1]):
                        need -= 1
                    else:
                        del self.peers[host_port]
                if need <= 0:
                    break
                else:
                    time.sleep(5)

        # Stabilize
        user_score = dict()
        count = 0
        need_connection = 3
        while not self.f_stop:
            count += 1
            if not (self.p2p.listen * 1 // 3 < len(self.p2p.user) < self.p2p.listen * 2 // 3):
                time.sleep(5)
            elif count < 5 and len(self.p2p.user) < need_connection:
                time.sleep(2)
            elif count % 24 == 1:
                time.sleep(5 * (1 + random.random()))
            else:
                time.sleep(5)
                continue
            try:
                if len(self.p2p.user) == 0 and len(self.peers) > 0:
                    host_port = random.choice(list(self.peers.keys()))
                    if host_port in ignore_peers:
                        del self.peers[host_port]
                        continue
                    if self.p2p.create_connection(host_port[0], host_port[1]):
                        time.sleep(5)
                    else:
                        del self.peers[host_port]
                        continue
                elif len(self.p2p.user) == 0 and len(self.peers) == 0:
                    time.sleep(10)
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
                    sorted_score = sorted(user_score.items(), key=lambda x: x[1])[:len(user_score)//3]
                    # 既接続のもののみを取得
                    sorted_score = [(host_port, score) for host_port, score in sorted_score
                                    if host_port in [user.get_host_port() for user in self.p2p.user]]
                    if len(sorted_score) == 0:
                        time.sleep(10)
                        continue
                    logging.debug("Remove Score {}".format(sorted_score))
                    host_port, score = random.choice(sorted_score)
                    user = self.p2p.host_port2user(host_port)
                    if user is None:
                        pass  # 既接続でない
                    elif len(user.neers) < need_connection:
                        pass  # 接続数が少なすぎるノード
                    elif self.p2p.remove_connection(user):
                        logging.debug("Remove connection %s:%d=%d" % (host_port[0], host_port[1], score))
                    else:
                        logging.debug("Failed remove connection. Already disconnected?")
                        del self.peers[host_port]
                        del user_score[host_port]

                elif len(self.p2p.user) < self.p2p.listen * 2 // 3:  # Join
                    # スコア上位半分を取得
                    sorted_score = sorted(user_score.items(), key=lambda x: x[1], reverse=True)[:len(user_score)//3]
                    # 既接続を除く
                    sorted_score = [(host_port, score) for host_port, score in sorted_score
                                    if host_port not in [user.get_host_port() for user in self.p2p.user]]
                    if len(sorted_score) == 0:
                        time.sleep(10)
                        continue
                    logging.debug("Join Score {}".format(sorted_score))
                    host_port, score = random.choice(sorted_score)
                    if self.p2p.host_port2user(host_port):
                        continue  # 既に接続済み
                    elif host_port in ignore_peers:
                        del self.peers[host_port]
                        continue
                    elif self.p2p.create_connection(host=host_port[0], port=host_port[1]):
                        logging.debug("New connection {}".format(host_port))
                    else:
                        logging.info("Failed connect, remove {}".format(host_port))
                        del self.peers[host_port]
                        del user_score[host_port]

                elif len(self.p2p.user) > self.p2p.listen // 2 and random.random() < 0.01:
                    # Mutation
                    logging.debug("Mutate Score {}".format(user_score))
                    user = random.choice(self.p2p.user)
                    self.p2p.remove_connection(user)
                    logging.debug("Mutate connection, close {}".format(user.name))

                else:
                    time.sleep(60)  # Do nothing
                    continue

            except TimeoutError as e:
                logging.info("Stabilize {}".format(e))
            except ConnectionError as e:
                logging.debug("ConnectionError {}".format(e))
            except Exception as e:
                logging.debug("Stabilize {}".format(e), exc_info=True)

    @staticmethod
    def broadcast_check(data):
        return False  # overwrite


class FileReceiveError(FileExistsError): pass
