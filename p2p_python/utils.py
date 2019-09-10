from p2p_python.config import V, Debug
import logging
import socket
import random
import asyncio
import os


loop = asyncio.get_event_loop()


NAMES = (
    "Angle", "Ant", "Apple", "Arch", "Arm", "Army", "Baby", "Bag", "Ball", "Band", "Basin", "Bath", "Bed",
    "Bee", "Bell", "Berry", "Bird", "Blade", "Board", "Boat", "Bone", "Book", "Boot", "Box", "Boy", "Brain",
    "Brake", "Brick", "Brush", "Bulb", "Cake", "Card", "Cart", "Cat", "Chain", "Chest", "Chin", "Clock",
    "Cloud", "Coat", "Comb", "Cord", "Cow", "Cup", "Dog", "Door", "Drain", "Dress", "Drop", "Ear", "Egg",
    "Eye", "Face", "Farm", "Fish", "Flag", "Floor", "Fly", "Foot", "Fork", "Fowl", "Frame", "Girl", "Glove",
    "Goat", "Gun", "Hair", "Hand", "Hat", "Head", "Heart", "Hook", "Horn", "Horse", "House", "Jewel", "Key",
    "Knee", "Knife", "Knot", "Leaf", "Leg", "Line", "Lip", "Lock", "Map", "Match", "Moon", "Mouth", "Nail",
    "Neck", "Nerve", "Net", "Nose", "Nut", "Oven", "Pen", "Pig", "Pin", "Pipe", "Plane", "Plate", "Pot",
    "Pump", "Rail", "Rat", "Ring", "Rod", "Roof", "Root", "Sail", "Screw", "Seed", "Sheep", "Shelf", "Ship",
    "Shirt", "Shoe", "Skin", "Skirt", "Snake", "Sock", "Spade", "Spoon", "Stamp", "Star", "Stem", "Stick",
    "Store", "Sun", "Table", "Tail", "Thumb", "Toe", "Tooth", "Town", "Train", "Tray", "Tree", "Wall",
    "Watch", "Wheel", "Whip", "Wing", "Wire", "Worm"
)


def get_version():
    """get program version string"""
    if Debug.P_PRINT_EXCEPTION:
        return 'debug'

    # read version from code
    try:
        from p2p_python import __version__
        return __version__
    except Exception:
        pass

    # read version from file
    try:
        hear = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(hear, '__init__.py'), mode='r') as fp:
            for word in fp.readlines():
                if word.startswith('__version__'):
                    return word.replace('"', "'").split("'")[-2]
    except Exception:
        pass
    return 'unknown'


def get_name():
    """get random name for identify from others"""
    return "{}:{}".format(random.choice(NAMES), random.randint(10000, 99999))


def setup_p2p_params(network_ver, p2p_port, p2p_accept=True, p2p_udp_accept=True, sub_dir=None):
    """ setup general connection setting """
    # directory params
    if V.DATA_PATH is not None:
        raise Exception('Already setup params.')
    root_data_dir = os.path.join(os.path.expanduser('~'), 'p2p-python')
    if not os.path.exists(root_data_dir):
        os.makedirs(root_data_dir)
    V.DATA_PATH = os.path.join(root_data_dir, str(p2p_port))
    if not os.path.exists(V.DATA_PATH):
        os.makedirs(V.DATA_PATH)
    if sub_dir:
        V.DATA_PATH = os.path.join(V.DATA_PATH, sub_dir)
        if not os.path.exists(V.DATA_PATH):
            os.makedirs(V.DATA_PATH)
    # network params
    V.CLIENT_VER = get_version()
    V.SERVER_NAME = get_name()
    V.NETWORK_VER = network_ver
    V.P2P_PORT = p2p_port
    V.P2P_ACCEPT = p2p_accept
    V.P2P_UDP_ACCEPT = p2p_udp_accept


def setup_tor_connection(proxy_host='127.0.0.1', port=9150, f_raise_error=True):
    """ client connection to onion router """
    # Typically, Tor listens for SOCKS connections on port 9050.
    # Tor-browser listens on port 9150.
    host_port = (proxy_host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if V.P2P_ACCEPT or V.P2P_UDP_ACCEPT:
        raise ConnectionError('P2P socket accept enable? tcp={} udp={}'.format(
            V.P2P_ACCEPT, V.P2P_UDP_ACCEPT))
    if 0 != sock.connect_ex(host_port):
        if f_raise_error:
            raise ConnectionError('Cannot connect proxy by test.')
    else:
        V.TOR_CONNECTION = host_port
    sock.close()


async def is_reachable(host, port):
    """check a port is opened, finish in 2s"""
    future = loop.run_in_executor(
        None, socket.getaddrinfo, host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    try:
        await asyncio.wait_for(future, 10.0)
    except socket.gaierror:
        return False
    for af, socktype, proto, canonname, host_port in future.result():
        try:
            sock = socket.socket(af, socktype, proto)
        except OSError:
            continue
        sock.settimeout(2.0)
        future = loop.run_in_executor(None, sock.connect_ex, host_port)
        await asyncio.wait_for(future, 3.0)
        result = future.result()
        loop.run_in_executor(None, sock.close)
        if result == 0:
            return True
    else:
        # create no connection
        return False


def is_unbind_port(port, family=socket.AF_INET, protocol=socket.SOCK_STREAM):
    """check is bind port by server"""
    try:
        with socket.socket(family, protocol) as sock:
            sock.bind(("127.0.0.1", port))
        return True
    except socket.error:
        return False


def setup_logger(level=logging.DEBUG, format_str='[%(levelname)-6s] [%(threadName)-10s] [%(asctime)-24s] %(message)s'):
    """setup basic logging handler"""
    logger = logging.getLogger()
    for sh in logger.handlers:
        logger.removeHandler(sh)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(format_str)
    sh = logging.StreamHandler()
    sh.setLevel(level)
    sh.setFormatter(formatter)
    logger.addHandler(sh)


__all__ = [
    "NAMES",
    "get_version",
    "get_name",
    "is_reachable",
    "is_unbind_port",
    "setup_tor_connection",
    "setup_p2p_params",
    "setup_logger",
]
