Direct command
==============
You can directly send command at user level.

**User1**
```python
from p2p_python.client import PeerClient
 
def hello(data):
    print('receive msg', data)
    return 'nice to meet you!'
 
pc = PeerClient()
pc.start()  # work as port 2001
pc.event.addevent(cmd='message', f=hello)
 
# connect user2
 
receive = pc.send_direct_cmd(cmd='message', data='I\'m User1.')
print(receive)
```

**User2**
```python
from p2p_python.client import PeerClient
 
def welcome(data):
    print('receive msg', data)
    return 'you are welcome!'
 
pc = PeerClient()
pc.start()  # work as port 2002
pc.event.addevent(cmd='message', f=welcome)
 
# connect user1
 
receive = pc.send_direct_cmd(cmd='message', data='I\'m User2.')
print(receive)
```
