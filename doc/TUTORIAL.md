Tutorial
========
I make a simple example code for tutorial.  
You can know how it works.


setup inner parameters
----------------------
Two ways.  
`setup_p2p_params` enables you setup at once.

```python
from p2p_python.utils import setup_p2p_params
# user1
setup_p2p_params(
    network_ver=1000,
    p2p_port=4000,
    p2p_accept=True,
    sub_dir='user1',
    f_debug=True)
```

or setup one by one. (not recommend)  
Please look at code, most of params is used for debug.

```python
from p2p_python.config import V, Debug
V.CLIENT_VER
V.DATA_PATH
V.F_FILE_CONTINUE_ASKING
V.NETWORK_VER
V.P2P_ACCEPT
V.P2P_PORT
V.SERVER_NAME
V.TMP_PATH
Debug.F_RECODE_TRAFFIC
Debug.F_SEND_CHANNEL_INFO
Debug.P_EXCEPTION
Debug.P_RECEIVE_MSG_INFO
```

start PeerClient
----------------
Start p2p server and client on port 2000.  
`f_local` limit connection on `127.0.0.1`.  
`f_stabilize` search another node automatically.  
Please check server status by `print(pc.p2p.get_server_header())`.

```python
from p2p_python.client import PeerClient
pc = PeerClient(f_local=True)
pc.start(f_stabilize=True)
```

Connect another client
----------------------
Before connect, please open two or three python console and setup PeerClient.
**I design PeerClient work on only one process.**  
Check connection status by `print(pc.p2p.user)`.
```python
# user2
setup_p2p_params(
    network_ver=1000,
    p2p_port=4001,
    p2p_accept=True,
    sub_dir='user2',
    f_debug=True)
pc = PeerClient(f_local=True)
pc.start(f_stabilize=True)
# try to connect user1
pc.p2p.create_connection(host='127.0.0.1', port=4000)
```

Look more client connection info
--------------------------------
`pc.p2p.user` contains user connection object.  
`aeskey` users communicate with each other by AES-128 encrypt.

```python
user = pc.p2p.user[0]
print(user.getinfo())
# {'aeskey': '20K2Fnyjrap4bypLw2Wb3w==',
# 'header': {
#    'client_ver': 'debug',
#    'name': 'Flag:58990',
#    'network_ver': 1000,
#    'p2p_accept': True,
#    'p2p_port': 4001,
#    'start_time': 1526195219},
# 'host_port': ('127.0.0.1', 50900),
# 'neers': {
#     ('127.0.0.1', 4000): {
#         'client_ver': 'debug',
#         'name': 'Hair:40340',
#         'network_ver': 1000,
#         'p2p_accept': True,
#         'p2p_port': 4000,
#         'start_time': 1526195180}},
# 'number': 0,
# 'sock': "<socket.socket fd=1532, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 4000), raddr=('127.0.0.1', 50900)>",
# 'sock_type': 'type/server'}
```
