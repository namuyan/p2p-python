Another commands
================
Used internally.  
We do **not** design for general user.

network commands
----------------
**ping-pong**
```pydocstring
# for : check delay your node to a peer.
# user => <p2p_python.user.User object at 0x00000239DE12F390>
# data => {'ping': 1321537642.6184988, 'pong': 1321537643.7097583}
user, data = pc.send_command(ClientCmd.PING_PONG, data=time.time())
```

**get-peer-info**
```pydocstring
# for : find a peer's peer list.
# data => [[['127.0.0.1', 2000], header],..]
# header => {'name': 'Baby:76524', 'client_ver': '1.0.0', 'network_ver': 12345, 'p2p_accept': True, 'p2p_port': 2222, 'start_time': 1521538244}
user, data = pc.send_command(ClientCmd.GET_PEER_INFO)
```

**get-nears**
```pydocstring
# for : get peer's connection info.
# data =>  [[['127.0.0.1', 2000], header],..]
user, data = pc.send_command(ClientCmd.GET_NEARS)
```

**check-reachable**
```pydocstring
# for : check PORT connection reachable from outside.
# input : port is option. default p2p_port.
# data => True or False
user, data = pc.send_command(ClientCmd.CHECK_REACHABLE, data={'port': 12345})
```
