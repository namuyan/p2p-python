p2p-python
==========
This library enables you create P2P application.

## Require
* Python3 (>=3.5)
* [bin-json](https://github.com/namuyan/bin-json)

## How to use
```python
from p2p_python.client import PeerClient
port, net_ver = 1200, 123456789
pc = PeerClient(port, net_ver)
pc.p2p.f_tor = False  # Do not use tor.
pc.start(f_server=True, f_stabilize=True)
```

## Simple example
Please look test dir.   
Simple chat program [simple_chat.py](test/simple_chat.py).

Uer test1
```commandline
python3 test/simple_chat.py
name >> test1
Create port 2001
Join "test2"
[01-01-01-01][test2      ] hello world
>> 
```

Another user test2
```commandline
python3 test/simple_chat.py
name >> test2
>> /join 2001
Create port 2002
Join "test2"
>> hello world
[01-01-01-01][test2      ] hello world
>> 
```

## Author
[@namuyan_mine](http://twitter.com/namuyan_mine/)

## Licence
MIT