#!/user/env python3
# -*- coding: utf-8 -*-

import logging
import threading
import time
import os.path


def get_logger(level=logging.DEBUG):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('[%(levelname)-6s] [%(threadName)-10s] [%(asctime)-24s] %(message)s')
    sh = logging.StreamHandler()
    sh.setLevel(level)
    sh.setFormatter(formatter)
    logger.addHandler(sh)


def console_printer(data):
    print("\r", data, "\n>> ", end='')


class Recode(threading.Thread):
    FILE = 'access.tsv'

    def __init__(self, pc):
        super().__init__(daemon=True)
        self.pc = pc
        if not os.path.exists(self.FILE):
            data = ['time', 'node', 'others']
            self.recode("\t".join(data))

    def recode(self, data):
        with open(self.FILE, mode='a') as f:
            f.write(data + "\n")

    def run(self):
        while True:
            time.sleep(30)
            u, cs = self.pc.p2p.header['name'], [client[3]['name'] for client in self.pc.p2p.client]
            data = "\t".join([str(int(time.time()))] + [u] + cs)
            self.recode(data)


class LookBroadcast(threading.Thread):
    def __init__(self, pc):
        super().__init__(daemon=True)
        self.que = pc.broadcast_que.create()

    def run(self):
        while True:
            client, msg = self.que.get()
            console_printer(msg['data'])
