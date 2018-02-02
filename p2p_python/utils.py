#!/user/env python3
# -*- coding: utf-8 -*-

import os.path
import time
import threading
import queue
import random
import copy
import socket


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


class OrderDict:
    uuid2data = dict()
    lock = threading.Lock()

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
    que = list()
    lock = threading.Lock()

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


