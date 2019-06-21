Another commands
================
Used for network stabilize.  
Please import commands by `from p2p_python.server import Peer2PeerCmd`.  

commands
----------------
**ping-pong**
```text
# check delay your node to a peer
 
<<< await p2p.send_command(Peer2PeerCmd.PING_PONG, data=time.time())
 
>>> (<User Key:12027 open 23m 127.0.0.1:2001 0/0>, {'ping': None, 'pong': 1561109423.2927444})
```

**get-peer-info**
```text
# find a peer's peer list
 
<<< await p2p.send_command(Peer2PeerCmd.GET_PEER_INFO)
 
>>> (<User Army:54510 open 26m 127.0.0.1:2002 0/0>, [[['127.0.0.1', 2000], {'name': 'Army:54510', 'client_ver': '3.0.0', 'network_ver': 12345, 'p2p_accept': True, 'p2p_udp_accept': True, 'p2p_port': 2000, 'start_time': 1561107522, 'last_seen': 1561109616}]])
```

**get-nears**
```text
# for : get peer's connection info
 
<<< await p2p.send_command(Peer2PeerCmd.GET_NEARS)
 
>>> (<User Table:48590 open 24m 127.0.0.1:2002 0/0>, [[['127.0.0.1', 2000], {'name': 'Army:54510', 'client_ver': '3.0.0', 'network_ver': 12345, 'p2p_accept': True, 'p2p_udp_accept': True, 'p2p_port': 2000, 'start_time': 1561107522, 'last_seen': 1561109473}]])
```

**check-reachable**
```text
# check PORT connection reachable from outside
 
<<< await p2p.send_command(Peer2PeerCmd.CHECK_REACHABLE, data={'port': 1000})
 
>>> (<User Key:12027 open 28m 127.0.0.1:2001 0/0>, False)
```

**direct-cmd**
```text
# You can define any command like README.md
# warning: do not forget check data format is can convert json
 
 <<< await p2p.send_direct_cmd(DirectCmd.what_is_your_name, data='kelly')
 
 >>> (<User Table:48590 open 44m 127.0.0.1:2002 0/0>, {"you return": 1561110.0})
```

note
----
I checked by netcat console.

