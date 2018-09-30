Basic usage
===========
For general users.

Settings
--------
Setup inner params.
```python
from p2p_python.utils import setup_p2p_params
 
network_ver = 123456  # network version, to avoid crosstalk with other P2P network
p2p_port = 2000  # P2P connect/accept port
p2p_accept = True  # allow connection from outside, recommend
p2p_udp_accept = True  # allow connection from outside by UDP
sub_dir = 'test'  # option, recode to sub directory
setup_p2p_params(network_ver=network_ver, p2p_accept=p2p_accept, p2p_udp_accept=p2p_udp_accept, sub_dir=sub_dir)
```

Start P2P
---------
Start server and control connection automatically.
```python
from p2p_python.client import PeerClient, ClientCmd
from socket import AF_INET, AF_INET6, AF_UNSPEC
 
f_stabilize = True  # Create best P2P network automatically
s_family = AF_INET  # ServerMode, AF_INET:ipv4 only, AF_INET6:ipv6 only, AF_UNSPEC:ipv4/6 hybrid
 
pc = PeerClient()
pc.start(s_family=s_family, f_stabilize=f_stabilize)
pc.p2p.create_connection('your-site.sdocuhnov.com', 7890)  # connect first node
```

