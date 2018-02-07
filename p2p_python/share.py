#!/user/env python3
# -*- coding: utf-8 -*-

import threading
import time
import os.path
from hashlib import sha1, sha256
import bjson
import logging
import random
from binascii import hexlify
from .core import MAX_RECEIVE_SIZE
from .client import FileReceiveError
from .encryption import AESCipher


class FileShare:
    def __init__(self, pc, path):
        self.pc = pc
        self.name = os.path.split(path)[1]
        self.path = path
        self.element = list()
        self.content = dict()

    @staticmethod
    def create_ley():
        return AESCipher.create_key()

    def load_raw_file(self, pwd=None):
        raw = self._get_file(self.path)
        if pwd:
            raw = AESCipher.encrypt(key=pwd, raw=raw)
        h_list, self.element = self._split_maxsize(raw)
        self.content = {
            'name': self.name,
            'path': self.path,
            'size': len(raw) / 1000,
            'element': h_list,
            'hash': sha256(raw).hexdigest(),
            'signer': None,
            'sign': None,
            'date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'time': int(time.time())}

    def load_share_file(self):
        self.content = bjson.loads(self._get_file(self.path))
        self.element = [None] * len(self.content['element'])
        self.name = self.content['name']
        self.path = self.content['path']

    def recode_raw_file(self, recode_dir, pwd=None, overwrite=False):
        if not os.path.exists(recode_dir):
            raise FileNotFoundError('Not found recode dir.')
        recode_path = os.path.join(recode_dir, self.name)
        if os.path.exists(recode_path) and not overwrite:
            raise FileExistsError('You try to overwrite file.')
        check = self.check()
        if len(check) > 0:
            complete = str(round(len(check) / len(self.element) * 100, 2))
            raise FileNotFoundError('Isn\'t all file downloaded, ({}% complete)'.format(complete))
        with open(recode_path, mode='bw') as f:
            if pwd:
                raw = AESCipher.decrypt(key=pwd, enc=b''.join(self.element))
            else:
                raw = b''.join(self.element)
            f.write(raw)

    def recode_share_file(self, path=None, overwrite=False, compress=False):
        if path is None:
            path = self.path + '.share'
        if os.path.exists(path) and not overwrite:
            raise FileExistsError('You try to over write file.')
        with open(path, mode='bw') as f:
            bjson.dump(self.content, fp=f, compress=compress)

    def share_raw_by_p2p(self):
        for raw in self.element:
            self.pc.share_file(data=raw)

    def check(self):
        # return uncompleted element index
        return [i for i in range(len(self.element)) if self.element[i] is None]

    def remove_sharefile_related(self):
        for hash_bin in self.content['element']:
            self.pc.remove_file(hexlify(hash_bin).decode())

    def get_tmp_files(self):
        # return [(path, size, time), ...]
        files = list()
        for f in os.listdir(self.pc.tmp_dir):
            path = os.path.join(self.pc.tmp_dir, f)
            if not f.startswith('file.'):
                continue
            if not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            date = os.path.getmtime(path)
            files.append((path, size, date))
        return files

    def download(self, num=3, wait=True):
        if 'element' not in self.content:
            return False
        request = [i for i in range(len(self.content['element'])) if self.element[i] is None]
        lock = threading.Lock()
        threads = list()
        for n in range(num):
            t = threading.Thread(target=self._download, args=(request, lock), name='FileShare', daemon=True)
            t.start()
            threads.append(t)
            time.sleep(1)
        if wait:
            for t in threads:
                t.join()
        else:
            return request, threads

    def _download(self, request, lock):
        while True:
            with lock:
                try:
                    i = random.choice(request)
                    request.remove(i)
                except IndexError:
                    return
            hex_hash = hexlify(self.content['element'][i]).decode()
            logging.debug("Try %d=0x%s" % (i, hex_hash))
            retry = 5
            while True:
                try:
                    raw = self.pc.get_file(file_hash=hex_hash)
                    with lock:
                        self.element[i] = raw
                    logging.debug("Success %d=0x%s" % (i, hex_hash))
                    break
                except (FileReceiveError, TimeoutError) as e:
                    retry -= 1
                    if retry > 0:
                        time.sleep(1)
                        continue
                    else:
                        logging.debug("Failed %d=0x%s" % (i, hex_hash))
                        break

    @staticmethod
    def _get_file(path):
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, mode='br') as f:
            return f.read()

    @staticmethod
    def _split_maxsize(raw):
        e = list()
        h = list()
        index = 0
        while len(raw) > index:
            h.append(sha1(raw[index:index + MAX_RECEIVE_SIZE]).digest())
            e.append(raw[index:index + MAX_RECEIVE_SIZE])
            index += MAX_RECEIVE_SIZE
        return h, e
