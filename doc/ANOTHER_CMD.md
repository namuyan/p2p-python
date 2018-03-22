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
# data => {('127.0.0.1', 2000): header,..}
# header => {'name': 'Baby:76524', 'client_ver': '1.0.0', 'network_ver': 12345, 'p2p_accept': True, 'p2p_port': 2222, 'start_time': 1521538244}
user, data = pc.send_command(ClientCmd.GET_PEER_INFO)
```

**get-nears**
```pydocstring
# for : get peer's connection info.
# data =>  {('127.0.0.1', 2222): header,...}
user, data = pc.send_command(ClientCmd.GET_NEARS)
```

**check-reachable**
```pydocstring
# for : check PORT connection reachable from outside.
# input : port is option. default p2p_port.
# data => True or False
user, data = pc.send_command(ClientCmd.CHECK_REACHABLE, data={'port': 12345})
```

File share commands
------------------
**file-check**
```pydocstring
# for : ask inner storage have a file by hash.
# input : uuid is option, Ask ClientCmd.FILE_GET used before.
# data => {'asked': False, 'have': False}
user, data = pc.send_command(ClientCmd.FILE_CHECK, data={'hash': '1187d138a1e37de92d0904e6fd408384051bf24f0a4e1a66e535d0490e8df816', 'uuid': 124})
```

**file-get**
```pydocstring
# for : ask a peer to send file binary.
# input : asked is already asked user name.
user, data = pc.send_command(ClientCmd.FILE_GET, data={'hash': '1187d138a1e37de92d0904e6fd408384051bf24f0a4e1a66e535d0490e8df816', 'asked': ['Thumb:29727', 'Angle:87139']})
```

**file-delete**
```pydocstring
# for : delete file with certification file.
cert = {'sign': '246d62dbe6591ab72832a0c0cc1c31512b01a0756cef386a565ae3c561a58152246d62dbe6591ab72832a0c0cc1c31512b01a0756cef386a565ae3c561a58152',
        'master': '16339f06967e3d5c2ad606f408363b528f2b34b27027fe47448c9d0d4bc3de66',
        'start': '1521539558',
        'stop': '1521543158'}
input_data = {'hash': 'fc75d1ec7c59cf8ecf2cfd60770562519506682c0018b931faa859b86b8e0617',
            'signer': 'a600fc4ab3fbbdcc570fc239bed0cab703a37b6d2fb15ca2616443c38e5ff0de',
            'sign': '5c71a5964aab604a123371777fe92174b967c2f7090a48c671263400356bad7d5c71a5964aab604a123371777fe92174b967c2f7090a48c671263400356bad7d',
            'cert': cert}
pc.send_command(ClientCmd.FILE_DELETE, data=input_data)
```
