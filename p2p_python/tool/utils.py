from threading import Thread, Lock
import queue
import copy
import time
import random
import bjson
import atexit
import logging
import os

# For AES
from Cryptodome.Cipher import AES
from Cryptodome import Random
from base64 import b64encode, b64decode


class StackDict:
    def __init__(self, limit=100):
        self.uuid2data = dict()
        self.lock = Lock()
        self.limit = limit

    def get(self, uuid):
        return self.uuid2data[uuid][0]

    def put(self, uuid, item):
        with self.lock:
            self.uuid2data[uuid] = (item, time.time())
        if len(self.uuid2data) > self.limit:
            self.__refresh()

    def include(self, uuid):
        return uuid in self.uuid2data

    def remove(self, uuid):
        with self.lock:
            if uuid in self.uuid2data:
                del self.uuid2data[uuid]

    def __refresh(self):
        with self.lock:
            new = dict()
            for k, v in sorted(self.uuid2data.items(), key=lambda x: x[1][1], reverse=True):
                new[k] = v
                if len(new) > self.limit // 2:
                    break
            logging.debug("StackDict refresh now.")
            self.uuid2data = new

    def get_data_list(self):
        return list(self.uuid2data.values())


class QueueSystem:
    def __init__(self, maxsize=100):
        self.maxsize = maxsize
        self.que = list()
        self.lock = Lock()

    def create(self):
        que = queue.LifoQueue(maxsize=self.maxsize)
        with self.lock:
            self.que.append(que)
        return que

    def remove(self, que):
        with self.lock:
            if que in self.que:
                self.que.remove(que)

    def broadcast(self, item):
        pile = 0
        for que in copy.copy(self.que):
            try:
                que.put_nowait(item)
                pile = max(pile, que.qsize())
            except queue.Full:
                logging.info("QueueSystem find full queue, removed.")
                self.remove(que)
        if pile > self.maxsize // 2:
            logging.warning("QueueSystem piled {}, check code.".format(pile))


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

    def __init__(self, name, limit=200):
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

                print("0", self.name, data)
                if data['to'] not in ('*', self.name):
                    pass
                elif data['type'] == 'reply':
                    with self.lock:
                        self.__result[data['uuid']] = (time.time(), data['data'])
                elif data['type'] == 'ask':
                    if data['cmd'] in self.__event:
                        send_data = {'cmd': data['cmd'],
                                     'data': self.__event[data['cmd']](data['from'], data['data']),
                                     'from': self.name,
                                     'to': data['from'],
                                     'type': 'reply',
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
        assert self.f_running, 'Not running ac core.'
        uuid = uuid if uuid else random.randint(10, 0xffffffff)
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
            raise TimeoutError('timeout send cmd [{} {} {}]'.format(cmd, str(data), uuid))
        self.__refresh_result()
        return data

    def add_event(self, cmd, function):
        # function(from_name, data) => return data
        with self.lock:
            self.__event[cmd] = function

    def reply_to_cmd(self, cmd, data, to_name='*', uuid=None):
        uuid = uuid if uuid else random.randint(10, 4294967295)
        send_data = {'cmd': cmd, 'data': data, 'from': self.name, 'to': to_name, 'type': 'reply', 'uuid': uuid}
        self.que.broadcast(send_data)

    def wait_for_cmd(self, cmd, uuid, timeout=10):
        span = 0.002
        count = int(timeout // span)
        while count > 0:
            count -= 1
            time.sleep(span)
            if uuid in self.__result:
                data = self.__result[uuid]
                break
        else:
            raise TimeoutError('AsyncCommunicationTimeout {} {}'.format(cmd, uuid))
        self.__refresh_result()
        return data

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


class EventIgnition:
    def __init__(self):
        self.event = dict()

    def addevent(self, cmd, f):
        self.event[cmd] = f

    def removevent(self, cmd):
        if cmd in self.event:
            del self.event[cmd]

    def __contains__(self, item):
        return item in self.event

    def work(self, cmd, data):
        if cmd in self.event:
            return self.event[cmd](data)
        else:
            raise KeyError('Not found cmd "{}"'.format(cmd))


class AESCipher:
    @staticmethod
    def create_key():
        return b64encode(os.urandom(AES.block_size)).decode()

    @staticmethod
    def is_aes_key(key):
        try:
            return len(b64decode(key.encode())) == AES.block_size
        except:
            return False

    @staticmethod
    def encrypt(key, raw):
        assert type(raw) == bytes, "input data is bytes"
        key = b64decode(key.encode())
        raw = AESCipher._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    @staticmethod
    def decrypt(key, enc):
        assert type(enc) == bytes, 'Encrypt data is bytes'
        key = b64decode(key.encode())
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw = AESCipher._unpad(cipher.decrypt(enc[AES.block_size:]))
        if len(raw) == 0:
            raise ValueError("AES decryption error, not correct key.")
        return raw

    @staticmethod
    def _pad(s):
        pad = AES.block_size - len(s) % AES.block_size
        add = AES.block_size - len(s) % AES.block_size
        return s + add * pad.to_bytes(1, 'big')

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class JsonDataBase:
    """
    まるでDictのように扱えて自動的にSaveしてくれる
    """
    def __init__(self, path):
        self.path = path
        self.data = dict()
        self.load()
        atexit.register(self.save)
        self.lock = Lock()

    def save(self):
        with open(self.path, mode='bw') as fp:
            bjson.dump(self.data, fp=fp)
        logging.info("JsonDataBase saved to {}".format(os.path.split(self.path)[1]))

    def load(self):
        try:
            with open(self.path, mode='br') as fp:
                self.data = bjson.load(fp=fp)
        except:
            with open(self.path, mode='bw') as fp:
                bjson.dump(self.data, fp=fp)
        logging.info("JsonDataBase load from {}".format(os.path.split(self.path)[1]))

    def keys(self):
        return self.data.keys()

    def values(self):
        return self.data.values()

    def __len__(self):
        return len(self.data)

    def __contains__(self, item):
        return item in self.data

    def __setitem__(self, key, value):
        with self.lock:
            self.data[key] = value

    def __getitem__(self, key):
        with self.lock:
            if key in self.data:
                return self.data[key]
        return None

    def __delitem__(self, key):
        with self.lock:
            if key in self.data:
                del self.data[key]
