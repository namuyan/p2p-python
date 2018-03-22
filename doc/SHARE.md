share tool
==========
You can easily share file.

Sample code
-----------
`V.F_FILE_CONTINUE_ASKING` is a flag "Allow your node to ask another node when asked but don't have a file."
The flag is default disable because it's week to spam. 

**Work as server**
```python
from p2p_python.config import V
from p2p_python.utils import setup_p2p_params
from p2p_python.client import PeerClient
from p2p_python.tool.share import FileShare
from test.tool import get_logger
import logging
 
get_logger(level=logging.DEBUG)
setup_p2p_params(network_ver=12345, p2p_port=2000, p2p_accept=True, sub_dir='server')
V.F_DEBUG = True
V.F_FILE_CONTINUE_ASKING = True
 
pc = PeerClient()
pc.start()
 
fs = FileShare(pc, path='path/to/sample.png')  # setup path.
fs.share_raw_file()  # share on local storage.
fs.recode_share_file()  # recode share format file to data path.
```

**Work as client**
```python
from p2p_python.config import V
from p2p_python.utils import setup_p2p_params
from p2p_python.client import PeerClient
from p2p_python.tool.share import FileShare
from test.tool import get_logger
import time
import logging
 
get_logger(level=logging.DEBUG)
setup_p2p_params(network_ver=12345, p2p_port=2001, p2p_accept=True, sub_dir='client')
V.F_DEBUG = True
V.F_FILE_CONTINUE_ASKING = True
 
pc = PeerClient()
pc.start()
 
pc.p2p.create_connection(host='127.0.0.1', port=2000)
time.sleep(10)
 
fs = FileShare(pc, path='path/to/sample.png.share')
fs.load_share_file()
fs.download()
fs.recode_raw_file(V.DATA_PATH)
```


Function
-------

```pydocstring
def get_logger(level=logging.DEBUG):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('[%(levelname)-6s] [%(threadName)-10s] [%(asctime)-24s] %(message)s')
    sh = logging.StreamHandler()
    sh.setLevel(level)
    sh.setFormatter(formatter)
    logger.addHandler(sh)
```