import collections
from threading import Thread
import time
import os.path
from logging import getLogger

log = getLogger(__name__)


class Traffic(Thread):
    f_stop = False
    f_finish = False

    def __init__(self, recode_dir=None, span=300, max_hours=24):
        super().__init__(name='Traffic', daemon=True)
        self.data = collections.deque(maxlen=int(3600 * max_hours // span))
        self.recode_dir = recode_dir if recode_dir and os.path.exists(recode_dir) else None
        self.span = span  # 5min
        self.traffic_up = list()
        self.traffic_down = list()

    def close(self):
        self.f_stop = True
        log.debug("traffic close")

    def run(self):
        count = 0
        while True:
            time.sleep(self.span)
            if self.f_stop:
                break
            count += 1
            time_, up, down = int(time.time()), sum(self.traffic_up), sum(self.traffic_down)
            self.data.append((time_, up, down))
            self.traffic_up = list()
            self.traffic_down = list()
            # recode
            if self.recode_dir is None:
                continue
            date = time.strftime('%y-%m-%d')
            recode_path = os.path.join(self.recode_dir, 'traffic.%s.csv' % date)
            try:
                f_first = os.path.exists(recode_path)
                with open(recode_path, mode='a') as f:
                    if not f_first:
                        f.write("unix time,date,up (kb),down (kb)\n")
                    f.write("{},{},{},{}\n".format(time_, time.strftime('%Hh%Mm', time.gmtime(time_)),
                                                   round(up / 1000, 3), round(down / 1000, 3)))
            except Exception as e:
                log.debug(e)
        self.f_finish = True

    def put_traffic_up(self, b):
        self.traffic_up.append(len(b))

    def put_traffic_down(self, b):
        self.traffic_down.append(len(b))


__all__ = [
    "Traffic",
]
