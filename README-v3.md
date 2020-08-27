p2p-python
==========
I seek a library that can make a simple P2P network.  
This library enables you create P2P application.

## Specification
* Asynchronous IO
* Pure Python code
* TCP and UDP connection
* Automatic network build
* Python**3.6+**

## How to install
warning: **Destructive change from 3.0.0**
```commandline
pip3 install --user p2p-python>=3.0.0
```

## How to use
basic usage with debug tool `aiomonitor`.  
install by `pip3 install --user aiomonitor`.  
```python
from p2p_python.utils import setup_p2p_params, setup_logger
from p2p_python.server import Peer2Peer, Peer2PeerCmd
import logging
import asyncio
import aiomonitor
import time
 
loop = asyncio.get_event_loop()
log = logging.getLogger(__name__)
 
setup_logger(logging.INFO)
 
# setup Peer2Peer
setup_p2p_params(
    network_ver=11111,  # (int) identify other network
    p2p_port=2000, # (int) P2P listen port
    p2p_accept=True, # (bool) switch on TCP server
    p2p_udp_accept=True, # (bool) switch on UDP server
)
p2p = Peer2Peer(listen=100)  # allow 100 connection
p2p.setup()
 
# close method example
def close():
    p2p.close()
    loop.call_later(1.0, loop.stop)
 
# You can setup DirectDmd method
class DirectCmd(object):
 
    @staticmethod
    async def what_is_your_name(user, data):
        print("what_is_your_name", user, data)
        return {"you return": time.time()}
 
    @staticmethod
    async def get_time_now(user, data):
        print("get_time_now", user, data)
        return {"get time now": time.time()}
 
# register methods for DirectCmd
p2p.event.setup_events_from_class(DirectCmd)
# throw cmd by `await p2p.send_direct_cmd(DirectCmd.what_is_your_name, 'kelly')`
# or `await p2p.send_direct_cmd('what_is_your_name', 'kelly')`
 
# You can setup broadcast policy (default disabled)
# WARNING: You must set strict policy or will be broken by users
async def broadcast_check_normal(user, data):
    return True
 
# overwrite method
p2p.broadcast_check = broadcast_check_normal
 
# setup netcat monitor
local = locals().copy()
local.update({k: v for k, v in globals().items() if not k.startswith('__')})
log.info('local', list(local.keys()))
aiomonitor.start_monitor(loop, port=3000, locals=local)
log.info(f"you can connect by `nc 127.0.0.1 3000`")
 
# start event loop
# close by `close()` on netcat console
try:
    loop.run_forever()
except KeyboardInterrupt:
    log.info("closing")
loop.close()
```

## Documents
* [about inner commands](doc/COMMANDS.md)
* [for debug](doc/FOR_DEBUG.md)
* [how to work p2p-python? (OLD and JP)](https://ameblo.jp/namuyan/entry-12398575560.html)

## Author
[@namuyan_mine](http://twitter.com/namuyan_mine/)

## Licence
[MIT](LICENSE)
