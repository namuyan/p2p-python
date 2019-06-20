

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
    P2P_UDP_ACCEPT = None

    # setting
    TOR_CONNECTION = None  # proxy (host, port)


class Debug:
    P_MAX_RECEIVE_SIZE = 50 * 1000 * 1000  # 一度に受け取れる最大データ量(50MBytes)
    P_PRINT_EXCEPTION = False  # print exception info
    P_SEND_RECEIVE_DETAIL = False  # print receive msg info
    F_RECODE_TRAFFIC = False  # recode traffic to file
    F_SEND_CHANNEL_INFO = False  # send to details with channel fnc
    F_LONG_MSG_INFO = False  # long message info


class PeerToPeerError(Exception):
    pass


__all__ = [
    "V",
    "Debug",
    "PeerToPeerError",
]
