p2p-python
==========
I seek a library that can make a simple P2P network.  
This library enables you create P2P application.

## Require
* Python3 (>=3.5)
* [bin-json](https://github.com/namuyan/bin-json)

## How to install
```commandline
pip install git+https://github.com/namuyan/p2p-python.git
```
Look => [HOWTOUSE.md](HOWTOUSE.md)

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


## Author
[@namuyan_mine](http://twitter.com/namuyan_mine/)

## Licence
MIT