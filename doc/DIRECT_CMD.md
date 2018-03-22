Direct command
==============
You can directly send command at user level by `AsyncCommunication` class.  
AsyncCommunication enables you connect many user.

**User1**
```python
from p2p_python.client import PeerClient, ClientCmd
from p2p_python.tool.utils import AsyncCommunication
 
def hello(from_user, data):
    print('receive msg', data)
    return 'nice to meet you!'
 
pc = PeerClient()
pc.start()  # work as port 2001
user_ac = AsyncCommunication('user1')
user_ac.share_que(pc.direct_ac)
user_ac.add_event('hello', hello)
user_ac.start()
 
# connect user2
 
receive = pc.send_direct_cmd(cmd='welcome', data='I\'m User1.', to_name='user2')
print(receive)
```

**User2**
```python
from p2p_python.client import PeerClient, ClientCmd
from p2p_python.tool.utils import AsyncCommunication
 
def welcome(from_user, data):
    print('receive msg', data)
    return 'you are welcome!'
 
pc = PeerClient()
pc.start()  # work as port 2002
user_ac = AsyncCommunication('user2')
user_ac.share_que(pc.direct_ac)
user_ac.add_event('welcome', welcome)
user_ac.start()
 
# connect user1
 
receive = pc.send_direct_cmd(cmd='hello', data='I\'m User2.', to_name='user1')
print(receive)
```
