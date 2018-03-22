

class C:
    # 一度に受け取れる最大データ量(260kBytes)
    MAX_RECEIVE_SIZE = 260000

    # type
    T_SERVER = 'type/server'
    T_CLIENT = 'type/client'

    # Master key
    MASTER_KEYS = []


class V:
    # path
    DATA_PATH = None
    TMP_PATH = None

    # info
    CLIENT_VER = None
    SERVER_NAME = None
    NETWORK_VER = None
    P2P_PORT = None
    P2P_ACCEPT = None

    # debug
    F_DEBUG = False
    F_FILE_CONTINUE_ASKING = False


class PeerToPeerError(Exception):
    pass
