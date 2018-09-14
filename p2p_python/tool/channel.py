#!/user/env python3
# -*- coding: utf-8 -*-


from threading import Thread, Timer, Lock
import queue
import collections
import bjson
import random
import time
import logging
import copy
from nem_ed25519.base import Encryption
from nem_ed25519.signature import verify
from .utils import StackDict, QueueSystem, AESCipher
from ..client import ClientCmd
from ..config import V, Debug

"""
1, 新規受け付けはMasterNodeのみ
2, MasterNodeがLeaveすると次点のNodeがMN化
3, MNが告知無しに消えた場合、次点が申請し2/3以上の賛同でMN化
"""

# Const
T_ECC = 'type/ecc'
T_AES = 'type/aes'
MAX_INT = 0xffffffff


class ChannelCmd:
    """ channel command """
    PING_PONG = 'cmd/ch/ping-pong'  # ping-pongを返す
    JOIN = 'cmd/ch/join'  # channelにJOINする
    LEAVE = 'cmd/ch/leave'  # channelからLEAVEする
    ADD_NEW_MEMBER = 'cmd/ch/add-new-member'  # channelにMemberを加える
    ADD_NEW_KEY = 'cmd/ch/add-new-key'  # channelの共通鍵を加える
    RUN_FOR_MASTER = 'cmd/ch/run-for-master'  # Masterがいない為、立候補する
    VOTE_CANDIDATE = 'cmd/ch/reject-candidate'  # 立候補者をランクが低い為拒否する
    MESSAGE = 'cmd/ch/message'  # channelにMessageを送る
    ACTION_RESULT = 'cmd/ch/action-result'  # cmdの結果を返す


class MemberList:
    def __init__(self):
        self.data = dict()  # {pk: rank,..}

    def put(self, user, item):
        if user in self.data:
            return
        else:
            self.data[user] = item

    def get(self, user):
        return self.data[user]

    def get_by_value(self, item):
        for k, v in self.data.items():
            if item == v:
                return k
        return None

    def remove(self, user):
        if user in self.data:
            del self.data[user]

    def include(self, user):
        return user in self.data

    def is_master(self, user):
        if user not in self.data:
            return False
        return self.data[user] == min(self.data.values())

    def make_master(self, user):
        if user not in self.data:
            return
        for sk in copy.copy(self.data):
            if self.data[sk] < self.data[user]:
                del self.data[sk]


class LockList:
    def __init__(self):
        self.data = list()
        self.lock = Lock()

    def append(self, data):
        with self.lock:
            if data not in self.data:
                self.data.append(data)

    def remove(self, data):
        with self.lock:
            if data in self.data:
                self.data.remove(data)

    def include(self, data):
        return data in self.data


class Channel(Thread):
    f_stop = False
    f_finish = False
    f_running = False
    f_failed_together = False  # ch内で分裂の恐れあり
    f_master = False
    f_debug_detail_print = False
    delay = 10.0  # 送受信時間ズレ
    ping_pong_span = 60 * 5  # ユーザー死活監視間隔

    def __init__(self, pc, ch, seed=None):
        super().__init__(name='1:Channel', daemon=True)
        self.pc = pc
        self.ch = str(ch)
        # 秘密鍵、公開鍵　チェック
        self.ecc = Encryption()
        self.ecc.secret_key(seed)
        self.ecc.public_key()
        # 変数
        self.members = MemberList()  # {pk: rank,..}
        self.aes_key = collections.deque(maxlen=5)
        self.__result = StackDict()
        self.message_que = QueueSystem()  # (f_private, signer, item)

    def cmd_send_ecc(self, cmd, data, pk, dummy_pk=None, uuid=None, wait=-1):
        logging.debug("send rsa cmd '{}'".format(cmd))
        uuid = uuid if uuid else random.randint(100, 0xffffffff)
        dummy_pk = dummy_pk if dummy_pk else hex(random.getrandbits(32*8))[2:]
        signer = self.ecc.pk
        raw = bjson.dumps((cmd, data, signer, uuid, self.ch, time.time()))
        sign = self.ecc.sign(raw, encode='raw')
        send_data = bjson.dumps((raw, sign))
        template = {
            'type': T_ECC,
            'data': self.ecc.encrypt(recipient_pk=pk, msg=send_data, encode='raw'),
            'ch': self.ch,
            'pk': dummy_pk}
        if Debug.F_SEND_CHANNEL_INFO:
            template['debug'] = (cmd, data, signer, uuid, self.ch, time.time())
        self.pc.send_command(ClientCmd.BROADCAST, data=template)
        if wait < 0:
            return uuid
        span = 0.005
        count = wait // span
        while count > 0:
            time.sleep(span)
            count -= 1
            if self.__result.include(uuid):
                return self.__result.get(uuid)
        raise TimeoutError('timeout cmd="{}" data="{}"'.format(cmd, data))

    def cmd_send_aes(self, cmd, data, uuid=None, aes_key=None, wait=-1):
        logging.debug("send aes cmd '{}'".format(cmd))
        uuid = uuid if uuid else random.randint(100, 0xffffffff)
        if aes_key:
            pass
        elif len(self.aes_key) > 0:
            aes_key = self.aes_key[-1]
        else:
            return
        rank = self.members.get(self.ecc.pk)
        raw = bjson.dumps((cmd, data, rank, uuid, self.ch, time.time()))
        sign = self.ecc.sign(raw, encode='raw')
        send_data = bjson.dumps((raw, sign))
        template = {
            'type': T_AES,
            'data': AESCipher.encrypt(aes_key, send_data),
            'ch': self.ch}
        if Debug.F_SEND_CHANNEL_INFO:
            template['debug'] = (cmd, data, rank, uuid, self.ch, time.time())
        self.pc.send_command(cmd=ClientCmd.BROADCAST, data=template)
        if wait < 0:
            return uuid
        span = 0.005
        count = wait // span
        while count > 0:
            time.sleep(span)
            count -= 1
            if self.__result.include(uuid):
                return self.__result.get(uuid)
        raise TimeoutError('timeout cmd="{}" data="{}"'.format(cmd, data))

    def run(self):
        broadcast_que = self.pc.broadcast_que.create()
        process_que = queue.LifoQueue()
        election_que = queue.LifoQueue()
        Thread(target=self._process, name='2:Channel', args=(process_que,), daemon=True).start()
        Thread(target=self._election, name='3:Channel', args=(election_que,), daemon=True).start()
        count = 0
        self.f_running = True
        while not self.f_stop:
            count += 1
            item = None
            try:
                item = broadcast_que.get(timeout=5)
                if 'type' not in item or 'data' not in item or 'ch' not in item:
                    continue
                if item['ch'] != self.ch:
                    continue

                # 各暗号形式に沿ってデクリプト
                if item['type'] == T_AES and len(self.aes_key) > 0:
                    index = 0
                    for key in self.aes_key.copy():
                        try:
                            b_data = AESCipher.decrypt(key, item['data'])
                            raw, sign = bjson.loads(b_data)
                        except:
                            index += 1
                            continue
                        cmd, item, rank, uuid, ch, send_time = bjson.loads(raw)
                        signer = self.members.get_by_value(rank)
                        f_type = T_AES
                        key_index = index
                        break
                    else:
                        # 見知らぬ鍵がある？ chの分裂か？要注意
                        self.f_failed_together = True
                        continue

                elif item['type'] == T_ECC:
                    for pk in self.members.data.copy():
                        try:
                            b_data = self.ecc.decrypt(sender_pk=pk, enc=item['data'])
                            raw, sign = bjson.loads(b_data)
                            break
                        except:
                            pass
                    else:
                        try:
                            b_data = self.ecc.decrypt(sender_pk=item['pk'], enc=item['data'])
                            raw, sign = bjson.loads(b_data)
                        except:
                            raise bjson.BJsonBaseError('cannot decrypt.')
                    cmd, item, signer, uuid, ch, send_time = bjson.loads(raw)
                    f_type, key_index = T_ECC, None
                else:
                    continue

                # 条件調査
                if ch != self.ch:
                    continue
                if abs(time.time() - send_time) > self.delay:
                    continue
                if f_type == T_AES and not self.members.include(signer):
                    continue  # member以外がAES通信を行うのは禁止

                # 署名検証
                verify(raw, sign, signer)

                if self.__result.include(uuid):
                    continue
                elif cmd == ChannelCmd.ACTION_RESULT:
                    self.__result.put(uuid, item=(signer, item, key_index))
                elif cmd == ChannelCmd.MESSAGE:
                    f_private = (f_type == T_ECC)
                    self.message_que.broadcast((f_private, signer, item))
                elif cmd == ChannelCmd.RUN_FOR_MASTER and f_type == T_AES:
                    election_que.put((cmd, item, signer, uuid))
                elif cmd == ChannelCmd.VOTE_CANDIDATE and f_type == T_AES:
                    election_que.put((cmd, item, signer, uuid))
                elif cmd == ChannelCmd.PING_PONG and f_type == T_AES:
                    election_que.put((cmd, item, signer, uuid))
                else:
                    process_que.put((cmd, item, signer, uuid, f_type, key_index))

            except queue.Empty:
                pass
            except ValueError:
                logging.debug("decrypt error", exc_info=Debug.P_EXCEPTION)
                pass  # decryption error
            except bjson.BJsonBaseError:
                # logging.debug("bjson error", exc_info=Debug.P_EXCEPTION)
                pass
            except Exception:
                logging.debug("general error", exc_info=Debug.P_EXCEPTION)
        self.f_finish = True
        self.f_running = False
        logging.info("Close main loop.")

    def _process(self, process_que):
        while not self.f_stop:
            try:
                cmd, data, signer, uuid, f_type, key_index = process_que.get(timeout=5)

                if cmd == ChannelCmd.JOIN and f_type == T_ECC:
                    # 新規メンバー追加
                    if self.join_condition_check(data=data):
                        new_aes = AESCipher.create_key()
                        new_signer = signer
                        new_rank = max(self.members.data.values()) + 1
                        self.members.put(user=new_signer, item=new_rank)
                        data = (True, new_aes, self.members.data, self.ping_pong_span)
                        self.cmd_send_ecc(ChannelCmd.ACTION_RESULT, data=data,
                                          pk=signer, dummy_pk=self.ecc.pk, uuid=uuid)
                        self.cmd_send_aes(ChannelCmd.ADD_NEW_MEMBER, (new_aes, new_signer, new_rank))
                        self.aes_key.append(new_aes)
                        logging.info("New user rank=%d" % new_rank)
                    else:
                        # 参加を拒否する場合
                        self.cmd_send_ecc(cmd=ChannelCmd.ACTION_RESULT, data=(False, None, None),
                                          pk=signer, dummy_pk=self.ecc.pk, uuid=uuid)
                        logging.debug("Reject user.")

                elif cmd == ChannelCmd.LEAVE and f_type == T_AES:
                    self.members.remove(signer)
                    if self.members.is_master(self.ecc.pk):
                        logging.info("Work as master.")

                elif cmd == ChannelCmd.ADD_NEW_KEY and f_type == T_ECC:
                    if not self.members.is_master(signer):
                        continue
                    self.aes_key.append(data)

                elif cmd == ChannelCmd.ADD_NEW_MEMBER and f_type == T_AES:
                    if not self.members.is_master(signer):
                        continue  # not a master request!
                    new_aes, new_signer, rank = data
                    if new_aes not in self.aes_key:
                        self.aes_key.append(new_aes)
                    self.members.put(new_signer, rank)

                else:
                    pass

            except queue.Empty:
                continue
            except Exception:
                import traceback
                traceback.print_exc()

        logging.info("Close channel process.")
        return

    def _master_work(self):
        self.f_master = True
        logging.info("start master work.")
        while not self.f_stop:
            time.sleep(self.ping_pong_span * (random.random() * 0.1 + 0.95))
            logging.debug("Send ping as master.")
            self.cmd_send_aes(cmd=ChannelCmd.PING_PONG, data=None)

    def _election(self, election_que):
        # 投票管理
        def _open(limit_time):
            # 有効票を纏める
            rank_time = {self.members.get(k): ping_pong[k] for k in ping_pong if ping_pong[k] > limit_time}
            # 自分より優先度の高いノードから票が無いか確かめる
            my_rank = self.members.get(self.ecc.pk)
            candidate_rank = min(rank_time.keys())
            logging.info("rank check My={}, Candidate={}".format(my_rank, candidate_rank))
            if my_rank > candidate_rank:
                # 優先度が低い為MSにならない
                logging.info("Find best node %d" % candidate_rank)
                self.members.make_master(self.members.get_by_value(candidate_rank))
            elif my_rank == candidate_rank:
                logging.info("Accept as MasterNode %d" % my_rank)
                self.members.make_master(self.ecc.pk)
                Thread(target=self._master_work, name='5:Channel', daemon=True).start()
                # AES-KEYを新しくする
                time.sleep(5)
                new_aes = AESCipher.create_key()
                for pk in self.members.data:
                    if pk == self.ecc.pk:
                        continue
                    self.cmd_send_ecc(cmd=ChannelCmd.ADD_NEW_KEY, data=new_aes, pk=pk)
                self.aes_key.append(new_aes)
            else:
                raise ChannelError('Unknown status')
            # 選挙終了
            f_election.pop()

        # 投票管理
        ping_pong = dict()
        f_election = list()
        while not self.f_stop:
            try:
                cmd, data, signer, uuid = election_que.get(timeout=5)
                if self.f_debug_detail_print:
                    logging.debug("receive {} from {} {}".format(cmd, signer, data))

                if not self.members.include(signer):
                    if self.f_debug_detail_print:
                        logging.debug("ignore {} from {}".format(cmd, signer))
                    continue

                if cmd == ChannelCmd.RUN_FOR_MASTER:
                    logging.debug("candidate master by %d" % self.members.get(signer))
                    run_for_span = 15
                    if not bool(f_election):
                        f_election.append(None)
                        t = Timer(run_for_span, _open, args=(time.time() - run_for_span,))
                        t.setName('Candidate')
                        t.start()
                        if self.ecc.pk not in ping_pong or ping_pong[self.ecc.pk] - 1 < time.time() - run_for_span:
                            self.cmd_send_aes(cmd=ChannelCmd.PING_PONG, data=None)

                elif cmd == ChannelCmd.PING_PONG:
                    ping_pong[signer] = time.time()
                    if self.members.is_master(signer) and not self.f_master:
                        logging.debug("Not master flag, send ping automatically.")
                        self.cmd_send_aes(cmd=ChannelCmd.PING_PONG, data=None)
                    else:
                        logging.debug("Update ping time of {}".format(signer))

            except queue.Empty:
                pass
            except Exception:
                import traceback
                traceback.print_exc()

            try:
                # ping-pong check
                # detect left user
                ping_min_time = min(ping_pong.values())
                if not bool(f_election) and ping_min_time < time.time() - self.ping_pong_span * 1.3:
                    # C_LEAVEせずに離れたユーザーがいる
                    left_user = list()
                    for pk in ping_pong:
                        if ping_pong[pk] < time.time() - self.ping_pong_span * 1.3:
                            if self.members.is_master(pk):
                                # master left
                                logging.info("Detect master left, run for master!")
                                self.cmd_send_aes(cmd=ChannelCmd.RUN_FOR_MASTER, data=None)
                                self.members.remove(pk)
                                left_user.clear()
                                break
                            else:
                                logging.info("Left suddenly {}".format(pk))
                                left_user.append(pk)
                    # no master left
                    for pk in left_user:
                        del ping_pong[pk]
                        if not self.members.include(pk):
                            continue
                        logging.info("Detect left user. %d" % self.members.get(pk))
                        self.members.remove(pk)
                elif ping_min_time < time.time() - self.ping_pong_span * 1.1:
                    logging.info("Ping warning, {}S".format(round(time.time()-ping_min_time), 1))

                # ping-pong前に入ったか、入れ替わりでC_LEAVEせず消えたか
                for pk in set(self.members.data) - set(ping_pong):
                    logging.debug("No ping user %d ,add time." % self.members.get(pk))
                    ping_pong[pk] = time.time()
                for pk in set(ping_pong) - set(self.members.data):
                    logging.debug("deleted user")
                    del ping_pong[pk]

            except TimeoutError:
                continue
            except ValueError:
                continue  # min() arg is an empty sequence
            except Exception:
                import traceback
                traceback.print_exc()
        logging.info("Close")

    def close(self):
        self.cmd_send_aes(cmd=ChannelCmd.LEAVE, data='Goodbye.')
        self.f_stop = True
        while not self.f_finish:
            time.sleep(1)
        self.members.data.clear()
        self.aes_key.clear()
        self.f_stop = self.f_finish = False

    @staticmethod
    def join_condition_check(data):
        return True  # overwrite

    """ user api """

    def create_channel(self):
        Thread(target=self._master_work, name='4:Channel', daemon=True).start()
        self.members.put(self.ecc.pk, 0)
        self.aes_key.clear()
        logging.info("Join as master.")

    def ask_join(self, pk, message):
        if self.f_finish:
            raise ChannelError('channel is close.')
        signer, data, key_index = self.cmd_send_ecc(ChannelCmd.JOIN, message, pk=pk, dummy_pk=self.ecc.pk, wait=10)
        ok, new_aes, members, ping_pong_span = data
        if not ok:
            raise ChannelError('Reject connection')
        self.aes_key.append(new_aes)
        self.members.data = members
        self.ping_pong_span = ping_pong_span
        logging.info("Join channel \"%s\"" % self.ch)

    def send_message(self, msg, pk=None):
        if pk is None:
            self.cmd_send_aes(cmd=ChannelCmd.MESSAGE, data=msg)
        elif self.members.include(pk):
            self.cmd_send_ecc(cmd=ChannelCmd.MESSAGE, data=msg, pk=pk)
        else:
            raise ChannelError('pk format is not correct.')


class ChannelError(Exception): pass
