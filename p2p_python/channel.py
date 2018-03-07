#!/user/env python3
# -*- coding: utf-8 -*-


import threading
import queue
import os.path
import collections
import bjson
import random
import time
import logging
import copy
from .encryption import EncryptRSA, AESCipher
from .utils import StackDict, QueueSystem
from .client import C_BROADCAST
from .channel_cmd import *

"""
1, 新規受け付けはMasterNodeのみ
2, MasterNodeがLeaveすると次点のNodeがMN化
3, MNが告知無しに消えた場合、次点が申請し2/3以上の賛同でMN化
"""

# Const
T_RSA = 'type/rsa'
T_AES = 'type/aes'
MAX_INT = 256 ** 4 - 1


class MemberList:
    def __init__(self):
        self.data = dict()

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
        self.lock = threading.Lock()

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


class Channel(threading.Thread):
    f_stop = False
    f_finish = False
    f_failed_together = False  # ch内で分裂の恐れあり
    f_master = False
    delay = 10.0  # 送受信時間ズレ
    ping_pong_span = 60 * 5  # ユーザー死活監視間隔

    def __init__(self, pc, ch, pwd=None):
        super().__init__(name='1:Channel', daemon=True)
        self.pc = pc
        self.ch = str(ch)
        self.pwd = pwd
        # 秘密鍵、公開鍵　チェック
        sk_path = os.path.join(self.pc.data_dir, 'secret.%s.pem' % self.ch)
        pk_path = os.path.join(self.pc.data_dir, 'public.%s.pem' % self.ch)
        if os.path.exists(sk_path):
            with open(sk_path, mode='r') as f:
                self.sk = f.read()
            with open(pk_path, mode='r') as f:
                self.pk = f.read()
        else:
            self.sk, self.pk = EncryptRSA.create_keypair(pwd=pwd)
            with open(sk_path, mode='w') as f:
                f.write(self.sk)
            with open(pk_path, mode='w') as f:
                f.write(self.pk)
        # 変数
        self.members = MemberList()
        self.aes_key = collections.deque(maxlen=5)
        self.result = StackDict()
        self.message = QueueSystem()

    def cmd_send_rsa(self, cmd, data, pk, uuid=None, wait=-1):
        logging.debug("send rsa cmd \"%s\"" % cmd)
        uuid = uuid if uuid else random.randint(100, MAX_INT)
        signer = self.pk
        raw = bjson.dumps((cmd, data, signer, uuid, self.ch, time.time()), False)
        sign = EncryptRSA.sign(self.sk, raw)
        send_data = bjson.dumps((raw, sign), True)
        template = {
            'type': T_RSA,
            'data': EncryptRSA.encrypt(pk, send_data),
            'ch': self.ch}
        self.pc.send_command(cmd=C_BROADCAST, data=template)
        if wait <= 0:
            return uuid
        span = 0.005
        count = wait // span
        while count > 0:
            time.sleep(span)
            count -= 1
            if self.result.include(uuid):
                return self.result.get(uuid)
        raise TimeoutError('timeout cmd=\"{}\" data=\"{}\"'.format(cmd, data))

    def cmd_send_aes(self, cmd, data, uuid=None, aes_key=None, wait=-1):
        logging.debug("send aes cmd \"%s\"" % cmd)
        uuid = uuid if uuid else random.randint(100, MAX_INT)
        if aes_key:
            pass
        elif len(self.aes_key) > 0:
            aes_key = self.aes_key[-1]
        else:
            return
        rank = self.members.get(self.pk)
        raw = bjson.dumps((cmd, data, rank, uuid, self.ch, time.time()), False)
        sign = EncryptRSA.sign(self.sk, raw)
        send_data = bjson.dumps((raw, sign), True)
        template = {
            'type': T_AES,
            'data': AESCipher.encrypt(aes_key, send_data, False),
            'ch': self.ch}
        self.pc.send_command(cmd=C_BROADCAST, data=template)
        if wait <= 0:
            return uuid
        span = 0.005
        count = wait // span
        while count > 0:
            time.sleep(span)
            count -= 1
            if self.result.include(uuid):
                return self.result.get(uuid)
        raise TimeoutError('timeout cmd=\"{}\" data=\"{}\"'.format(cmd, data))

    def run(self):
        broadcast_que = self.pc.broadcast_que.create()
        process_que = queue.LifoQueue()
        election_que = queue.LifoQueue()
        threading.Thread(target=self._process, name='2:Channel', args=(process_que,), daemon=True).start()
        threading.Thread(target=self._election, name='3:Channel', args=(election_que,), daemon=True).start()
        count = 0
        while not self.f_stop:
            count += 1
            try:
                client, item = broadcast_que.get(timeout=5)
                data = item['data']
                if 'type' not in data or\
                        'data' not in data or\
                        'ch' not in data:
                    continue
                if data['ch'] != self.ch:
                    continue

                # 各暗号形式に沿ってデクリプト
                if data['type'] == T_AES and len(self.aes_key) > 0:
                    index = 0
                    for key in self.aes_key:
                        try:
                            b_data = AESCipher.decrypt(key, data['data'], False)
                            raw, sign = bjson.loads(b_data)
                        except (ValueError, bjson.BJsonBaseError):
                            index += 1
                            continue
                        cmd, data, rank, uuid, ch, send_time = bjson.loads(raw)
                        signer = self.members.get_by_value(rank)
                        f_type = T_AES
                        key_index = index
                        break
                    else:
                        # 見知らぬ鍵がある？ chの分裂か？要注意
                        self.f_failed_together = True
                        continue

                elif data['type'] == T_RSA:
                    b_data = EncryptRSA.decrypt(self.sk, data['data'])
                    raw, sign = bjson.loads(b_data)
                    cmd, data, signer, uuid, ch, send_time = bjson.loads(raw)
                    f_type, key_index = T_RSA, None
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
                EncryptRSA.verify(signer, raw, sign)

                if self.result.include(uuid):
                    continue
                elif cmd == C_ACTION_RESULT:
                    self.result.put(uuid, item=(signer, data, key_index))
                elif cmd == C_MESSAGE:
                    f_private = (f_type == T_RSA)
                    self.message.broadcast((f_private, signer, data))
                elif cmd == C_RUN_FOR_MASTER and f_type == T_AES:
                    election_que.put((cmd, data, signer, uuid))
                elif cmd == C_VOTE_CANDIDATE and f_type == T_AES:
                    election_que.put((cmd, data, signer, uuid))
                elif cmd == C_PING_PONG and f_type == T_AES:
                    election_que.put((cmd, data, signer, uuid))
                else:
                    process_que.put((cmd, data, signer, uuid, f_type, key_index))

                # キャッシュクリア
                if len(self.result.uuid2data) > 50:
                    self.result.del_old()

            except queue.Empty:
                continue
            except ValueError:
                continue  # decryption error
            except bjson.BJsonBaseError:
                continue
            except Exception:
                import traceback
                traceback.print_exc()
                continue
        self.f_finish = True
        logging.info("Close 1P.")

    def _process(self, process_que):
        while not self.f_stop:
            try:
                cmd, data, signer, uuid, f_type, key_index = process_que.get(timeout=5)

                if cmd == C_JOIN and f_type == T_RSA:
                    # 新規メンバー追加
                    if self.join_condition_check(ch=self, data=data):
                        new_aes = AESCipher.create_key()
                        new_signer = signer
                        new_rank = max(self.members.data.values()) + 1
                        self.members.put(user=new_signer, item=new_rank)
                        self.cmd_send_rsa(C_ACTION_RESULT, (True, new_aes, self.members.data), signer, uuid=uuid)
                        self.cmd_send_aes(C_ADD_NEW_MEMBER, (new_aes, new_signer, new_rank))
                        self.aes_key.append(new_aes)
                        logging.info("New user rank=%d" % new_rank)
                    else:
                        # 参加を拒否する場合
                        self.cmd_send_rsa(cmd=C_ACTION_RESULT, data=(False, None, None), pk=signer, uuid=uuid)
                        logging.debug("Reject user.")

                elif cmd == C_LEAVE and f_type == T_AES:
                    self.members.remove(signer)
                    if self.members.is_master(self.pk):
                        logging.info("Work as master.")

                elif cmd == C_ADD_NEW_KEY and f_type == T_RSA:
                    if not self.members.is_master(signer):
                        continue
                    self.aes_key.append(data)

                elif cmd == C_ADD_NEW_MEMBER and f_type == T_AES:
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

        logging.info("Close 2P.")
        return

    def _master_work(self):
        self.f_master = True
        logging.info("start master work.")
        while not self.f_stop:
            time.sleep(self.ping_pong_span * (random.random() * 0.1 + 0.95))
            logging.debug("Send ping as master.")
            self.cmd_send_aes(cmd=C_PING_PONG, data=None)

    def _election(self, election_que):
        # 投票管理
        def _open(limit_time):
            # 有効票を纏める
            rank_time = {self.members.get(k): ping_pong[k] for k in ping_pong if ping_pong[k] > limit_time}
            # 自分より優先度の高いノードから票が無いか確かめる
            my_rank = self.members.get(self.pk)
            candidate_rank = min(rank_time.keys())
            logging.info("rank check My={}, Candidate={}".format(my_rank, candidate_rank))
            if my_rank > candidate_rank:
                # 優先度が低い為MSにならない
                logging.info("Find best node %d" % candidate_rank)
                self.members.make_master(self.members.get_by_value(candidate_rank))
            elif my_rank == candidate_rank:
                logging.info("Accept as MasterNode %d" % my_rank)
                self.members.make_master(self.pk)
                threading.Thread(target=self._master_work, name='5:Channel', daemon=True).start()
                # AES-KEYを新しくする
                time.sleep(5)
                new_aes = AESCipher.create_key()
                for pk in self.members.data:
                    if pk == self.pk:
                        continue
                    self.cmd_send_rsa(cmd=C_ADD_NEW_KEY, data=new_aes, pk=pk)
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

                if not self.members.include(signer):
                    continue

                if cmd == C_RUN_FOR_MASTER:
                    logging.debug("candidate master by %d" % self.members.get(signer))
                    run_for_span = 15
                    if not bool(f_election):
                        f_election.append(None)
                        t = threading.Timer(run_for_span, _open, args=(time.time() - run_for_span,))
                        t.setName('Candidate')
                        t.start()
                        if self.pk not in ping_pong or ping_pong[self.pk] - 1 < time.time() - run_for_span:
                            self.cmd_send_aes(cmd=C_PING_PONG, data=None)

                elif cmd == C_PING_PONG:
                    ping_pong[signer] = time.time()
                    if self.members.is_master(signer) and not self.f_master:
                        self.cmd_send_aes(cmd=C_PING_PONG, data=None)

            except queue.Empty:
                pass
            except Exception:
                import traceback
                traceback.print_exc()

            try:
                # ping-pong check
                # detect left user
                ping_min_time = min(ping_pong.values())
                if bool(f_election) is False and ping_min_time < time.time() - self.ping_pong_span * 1.3:
                    # C_LEAVEせずに離れたユーザーがいる
                    left_user = list()
                    for pk in ping_pong:
                        if ping_pong[pk] < time.time() - self.ping_pong_span * 1.3:
                            if self.members.is_master(pk):
                                logging.info("Detect master left, run for master!")
                                self.cmd_send_aes(cmd=C_RUN_FOR_MASTER, data=None)
                                self.members.remove(pk)
                                left_user.clear()
                                break
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
        self.f_stop = True
        self.cmd_send_aes(cmd=C_LEAVE, data='Goodbye.')
        self.members.data.clear()
        self.aes_key.clear()
        while not self.f_finish:
            time.sleep(1)

    @staticmethod
    def join_condition_check(ch, data):
        return True  # overwrite

    """ user api """

    def create_channel(self):
        threading.Thread(target=self._master_work, name='4:Channel', daemon=True).start()
        self.members.put(self.pk, 0)
        self.aes_key.clear()
        logging.info("Join as master.")

    def ask_join(self, pk, message):
        if self.f_finish:
            raise ChannelError('channel closed.')
        signer, data, key_index = self.cmd_send_rsa(cmd=C_JOIN, data=message, pk=pk, wait=10)
        ok, new_aes, members = data
        if not ok:
            raise ChannelError('Reject connection')
        self.aes_key.append(new_aes)
        self.members.data = members
        logging.info("Join channel \"%s\"" % self.ch)

    def send_message(self, msg, pk=None):
        if pk is None:
            self.cmd_send_aes(cmd=C_MESSAGE, data=msg)
        elif self.members.include(pk):
            self.cmd_send_rsa(cmd=C_MESSAGE, data=msg, pk=pk)
        else:
            raise ChannelError('pk format is not correct.')


class ChannelError(Exception): pass
