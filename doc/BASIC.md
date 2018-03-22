Basic usage
===========
For general users.

Settings
--------
Setup inner params.
```python
from p2p_python.utils import setup_p2p_params
 
network_ver = 123456  # network version, to avoid crosstalk other P2P
p2p_port = 2000  # P2P connect/accept port
p2p_accept = True  # allow connection from outside, recommend
sub_dir = 'test'  # option, recode to sub directory
setup_p2p_params(network_ver, p2p_port, p2p_accept, sub_dir)
```

Start P2P
---------
Start server and control connection automatically.
```python
from p2p_python.client import PeerClient, ClientCmd
 
pc = PeerClient()
pc.start()
```

