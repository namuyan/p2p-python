#!/user/env python3
# -*- coding: utf-8 -*-

import threading
import time
import os.path
from hashlib import sha256
import bjson
import logging
import random
from binascii import hexlify
from ..config import C, V, PeerToPeerError
from ..client import FileReceiveError, ClientCmd
from .utils import AESCipher


class FileShare:
    def __init__(self, pc, path):
        self.pc = pc
        self.name = os.path.split(path)[1]
        self.path = path
        self.f_contain = list()
        self.content = dict()

    @staticmethod
    def create_ley():
        return AESCipher.create_key()

    def share_raw_file(self, pwd=None):
        if not os.path.exists(self.path):
            raise FileExistsError('Not found file.')
        if not os.path.isfile(self.path):
            raise Exception('It\'s a directory.')
        h_list = list()
        sha_hash = sha256()
        with open(self.path, mode='br') as f:
            while True:
                raw = f.read(C.MAX_RECEIVE_SIZE)
                if not raw:
                    break
                sha_hash.update(raw)
                if pwd:
                    raw = AESCipher.encrypt(key=pwd, raw=raw)
                h_list.append(sha256(raw).digest())
                self.pc.share_file(data=raw)
        self.content = {
            'name': self.name,
            'path': self.path,
            'size': os.path.getsize(self.path) / 1000,
            'element': h_list,
            'hash': sha_hash.hexdigest(),
            'signer': None,
            'sign': None,
            'date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'time': int(time.time())}

    def load_share_file(self):
        if len(self.content) != 0:
            raise Exception('Already loaded share file.')
        with open(self.path, mode='br') as f:
            self.content = bjson.load(fp=f)
        self.f_contain = [False] * len(self.content['element'])
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
            complete = str(round(len(check) / len(self.f_contain) * 100, 2))
            raise FileNotFoundError('Isn\'t all file downloaded, ({}% complete)'.format(complete))
        sha_hash = sha256()
        with open(recode_path, mode='ba') as f:
            for h in self.content['element']:
                raw = self.pc.get_file(file_hash=hexlify(h).decode())
                if pwd:
                    raw = AESCipher.decrypt(key=pwd, enc=raw)
                sha_hash.update(raw)
                f.write(raw)
        if sha_hash.hexdigest() != self.content['hash']:
            raise Exception('SHA256 hash don\'t match.')

    def recode_share_file(self, path=None, overwrite=False, compress=False):
        if path is None:
            path = self.path + '.share'
        if os.path.exists(path) and not overwrite:
            raise FileExistsError('You try to over write file.')
        with open(path, mode='bw') as f:
            bjson.dump(self.content, fp=f, compress=compress)

    def get_all_binary(self, pwd=None):
        result = b''
        check = self.check()
        sha_hash = sha256()
        if len(check) > 0:
            complete = str(round(len(check) / len(self.f_contain) * 100, 2))
            raise FileNotFoundError('Isn\'t all file downloaded, ({}% complete)'.format(complete))
        for h in self.content['element']:
            raw = self.pc.get_file(file_hash=hexlify(h).decode())
            if pwd:
                raw = AESCipher.decrypt(key=pwd, enc=raw)
            sha_hash.update(raw)
            result += raw
        if sha_hash.hexdigest() != self.content['hash']:
            raise Exception('SHA256 hash don\'t match.')
        return result

    def check(self):
        # return uncompleted element index
        return [i for i in range(len(self.f_contain)) if not self.f_contain[i]]

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
        request = [i for i in range(len(self.content['element'])) if not self.f_contain[i]]
        lock = threading.Lock()
        threads = list()
        f_finish = [None] * num
        for n in range(num):
            t = threading.Thread(target=self.__download, args=(request, f_finish, lock), name='FileShare', daemon=True)
            t.start()
            threads.append(t)
            time.sleep(1)
        if wait:
            for t in threads:
                t.join()
        else:
            return request, f_finish

    def __download(self, request, f_finish, lock):
        allow_fail = max(5, len(request) // 1000)
        while True:
            # check retry counts
            if allow_fail < 0:
                f_finish.pop()
                return
            # get index, hash to try
            with lock:
                try:
                    i = random.choice(request)
                    request.remove(i)
                except IndexError:
                    f_finish.pop()
                    return
            hex_hash = hexlify(self.content['element'][i]).decode()
            logging.debug("Try %d=0x%s" % (i, hex_hash))
            retry = 5
            while True:
                try:
                    raw = self.pc.get_file(file_hash=hex_hash, only_check=False)
                    if raw:
                        with lock:
                            self.f_contain[i] = True
                        logging.debug("Success %d=0x%s" % (i, hex_hash))
                        break
                    else:
                        raise FileReceiveError('Failed get file, retry')
                except (FileReceiveError, TimeoutError) as e:
                    retry -= 1
                    if retry > 0:
                        time.sleep(5)
                        continue
                    else:
                        logging.info("Failed %d=0x%s" % (i, hex_hash))
                        import traceback
                        traceback.print_exc()
                        allow_fail -= 1
                        break

