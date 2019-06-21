

class V:
    # path
    DATA_PATH = None

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
    P_PRINT_EXCEPTION = False  # print exception info
    P_SEND_RECEIVE_DETAIL = False  # print receive msg info
    F_RECODE_TRAFFIC = False  # recode traffic to file


class PeerToPeerError(Exception):
    pass


__all__ = [
    "V",
    "Debug",
    "PeerToPeerError",
]
