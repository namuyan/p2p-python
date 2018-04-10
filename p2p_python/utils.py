import socket
import os
import random
from tempfile import gettempdir
from .config import V, Debug


def get_version():
    if Debug.P_EXCEPTION:
        return 'debug'
    hear = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(hear, '__init__.py'), mode='r') as fp:
        for word in fp.readlines():
            if word.startswith('__version__'):
                return word.replace('"', "'").split("'")[-2]
    return 'dev'


def get_name():
    hear = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(hear, 'name_list.txt')) as fp:
        name = fp.read().split()
    return "{}:{}".format(random.choice(name), random.randint(10000, 99999))


def setup_p2p_params(network_ver, p2p_port, p2p_accept=True, sub_dir=None, f_debug=False):
    if f_debug:
        Debug.P_EXCEPTION = True
        Debug.P_RECEIVE_MSG_INFO = True
    # directory params
    if V.DATA_PATH is not None:
        raise BaseException('Already setup params.')
    V.DATA_PATH = os.path.join(os.path.expanduser('~'), 'p2p-python')
    V.TMP_PATH = os.path.join(gettempdir(), 'p2p-python')
    if not os.path.exists(V.DATA_PATH):
        os.makedirs(V.DATA_PATH)
    if not os.path.exists(V.TMP_PATH):
        os.makedirs(V.TMP_PATH)
    if sub_dir:
        V.DATA_PATH = os.path.join(V.DATA_PATH, sub_dir)
        V.TMP_PATH = os.path.join(V.TMP_PATH, sub_dir)
    if not os.path.exists(V.DATA_PATH):
        os.makedirs(V.DATA_PATH)
    if not os.path.exists(V.TMP_PATH):
        os.makedirs(V.TMP_PATH)
    # Network params
    V.CLIENT_VER = get_version()
    V.SERVER_NAME = get_name()
    V.NETWORK_VER = network_ver
    V.P2P_PORT = p2p_port
    V.P2P_ACCEPT = p2p_accept


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
