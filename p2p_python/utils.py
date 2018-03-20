#!/user/env python3
# -*- coding: utf-8 -*-

import os.path
import time
from threading import Thread, Lock
import queue
import random
import copy
import socket
import logging


def str2byte(s):
    return s if type(s) == bytes else s.encode()


def byte2str(b):
    return b if type(b) == str else b.decode()


def get_here_path(here):
    return os.path.dirname(os.path.abspath(here))


def get_data_path():
    return os.path.expanduser('~')


def is_reachable(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((socket.gethostbyname(host), port))
    if result == 0:
        return True
    else:
        return False


def trim_msg(item, num):
    str_item = str(item)
    return str_item[:num] + ('...' if len(str_item) > num else '')


class StackDict:
    def __init__(self):
        self.uuid2data = dict()
        self.lock = Lock()

    def get(self, uuid):
        return self.uuid2data[uuid][0]

    def put(self, uuid, item):
        with self.lock:
            self.uuid2data[uuid] = (item, time.time())

    def include(self, uuid):
        return uuid in self.uuid2data

    def remove(self, uuid):
        with self.lock:
            if uuid in self.uuid2data:
                del self.uuid2data[uuid]

    def del_old(self, percent=0.8):
        with self.lock:
            d = int(len(self.uuid2data) * percent)
            r = dict()
            for k, v in sorted(self.uuid2data.items(), key=lambda x: x[1][1], reverse=True):
                r[k] = v
                d -= 1
                if d <= 0:
                    self.uuid2data = r
                    return

    @staticmethod
    def get_uuid():
        return random.randint(10000000, 99999999)

    def get_data_list(self):
        return list(self.uuid2data.values())


class QueueSystem:
    def __init__(self):
        self.que = list()
        self.lock = Lock()

    def create(self):
        que = queue.LifoQueue(maxsize=10)
        with self.lock:
            self.que.append(que)
        return que

    def remove(self, que):
        with self.lock:
            if que in self.que:
                self.que.remove(que)

    def broadcast(self, item):
        with self.lock:
            for q in copy.copy(self.que):
                try:
                    q.put_nowait(item)
                except queue.Full:
                    self.que.remove(q)


class AsyncCommunication(Thread):
    """I2C通信みたいに複数のノード間を一本線で通信
    Example code

    ac0 = AsyncCommunication(name='user0')
    ac1 = AsyncCommunication(name='user1')
    ac2 = AsyncCommunication(name='user2')
    ac0.share_que(ac1)
    ac1.share_que(ac2)
    def receive_msg(ac, data):
        print(ac.name, data)
        return 'received!'
    ac0.add_event('msg0', receive_msg)
    ac1.add_event('msg1', receive_msg)
    ac2.add_event('msg2', receive_msg)
    ac0.start()
    ac1.start()
    ac2.start()
    print(ac0.send_cmd('msg1', 'hello world'))
    => user1 hello world  # ac0からac1にメッセージを送った
    => {'cmd': 'msg1', 'data': 'received!', 'type': 'reply', 'uuid': 1692124062}
    """
    f_stop = False
    f_finish = False
    f_running = False

    def __init__(self, name, limit=100):
        super().__init__(name=name, daemon=True)
        self.que = QueueSystem()
        self.lock = Lock()
        self.__result = dict()
        self.__limit = limit
        self.__event = dict()

    def stop(self):
        self.f_stop = True
        while not self.f_finish:
            time.sleep(1)
        self.f_stop = self.f_finish = False

    def run(self):
        self.f_running = True
        input_que = self.que.create()
        while not self.f_stop:
            try:
                data = input_que.get(timeout=1)
                if 'cmd' not in data or 'data' not in data:
                    pass
                elif 'type' not in data:
                    pass
                elif 'from' not in data or 'to' not in data:
                    pass
                elif 'uuid' not in data:
                    pass

                if data['to'] != '*' and data['to'] != self.name:
                    pass
                elif data['type'] == 'reply':
                    with self.lock:
                        self.__result[data['uuid']] = (time.time(), data['data'])
                elif data['type'] == 'ask':
                    if data['cmd'] in self.__event:
                        send_data = {'cmd': data['cmd'],
                                     'data': self.__event[data['cmd']](self, data['from'], data['data']),
                                     'from': self.name, 'to': data['from'], 'type': 'reply',
                                     'uuid': data['uuid']}
                        self.que.broadcast(send_data)
                else:
                    pass
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(e, exe_info=True)
        self.f_running = False
        self.f_finish = True

    def share_que(self, ac_object):
        assert not self.f_running, 'inner class is already running.'
        self.que = ac_object.que

    def send_cmd(self, cmd, data, to_name='*', uuid=None, timeout=10):
        # return {'cmd': cmd, 'data': data, 'uuid': uuid}
        uuid = uuid if uuid else random.randint(10, 4294967295)
        send_data = {'cmd': cmd, 'data': data, 'from': self.name, 'to': to_name, 'type': 'ask', 'uuid': uuid}
        self.que.broadcast(send_data)
        if timeout < 0:
            return uuid
        span = 0.002
        count = int(timeout / span)
        while count > 0:
            count -= 1
            time.sleep(span)
            if uuid in self.__result:
                with self.lock:
                    data = self.__result[uuid][1]
                break
        else:
            raise TimeoutError('timeout send cmd [{},{},{}]'.format(cmd, str(data), uuid))
        self.__refresh_result()
        return data

    def add_event(self, cmd, function):
        # function(from_name, data) => return data
        with self.lock:
            self.__event[cmd] = function

    def reply_to_cmd(self, cmd, data, to_name, uuid):
        send_data = {'cmd': cmd, 'data': data, 'from': self.name, 'to': to_name, 'type': 'reply', 'uuid': uuid}
        self.que.broadcast(send_data)

    def __refresh_result(self):
        if len(self.__result) < self.__limit:
            return
        with self.lock:
            new = dict()
            for uuid, (time_, data) in sorted(self.__result.items(), key=lambda x: x[1][0], reverse=True):
                new[uuid] = (time_, data)
                if len(new) > self.__limit // 2:
                    break
            self.__result = new
            return
