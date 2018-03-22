Broadcast command
=================
Broadcast is default **disable** because of spam.  
You must set strict rules for cast data.

Simple setup example.  
Overwrite `broadcast_check`, and returns bool.  
`True` = allow transmit, `False` = stop transmit

Caution! : Must not block broadcast_check process.
```python
from p2p_python.client import PeerClient, ClientCmd
 
def broadcast_check(data):
    print("get broadcast data =>", data)
    return True
 
pc = PeerClient()
pc.start()
pc.broadcast_check = broadcast_check
 
dummy, data = pc.send_command(ClientCmd.BROADCAST, data='hello world!')
print(data)
```