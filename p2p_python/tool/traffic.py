from logging import getLogger
import collections
import os.path
import asyncio
import time

loop = asyncio.get_event_loop()
log = getLogger(__name__)


class Traffic(object):
    f_stop = False
    f_finish = False

    def __init__(self, recode_dir=None, span=300, max_hours=24):
        self.data = collections.deque(maxlen=int(3600 * max_hours // span))
        self.recode_dir = recode_dir if recode_dir and os.path.exists(recode_dir) else None
        self.span = span  # 5min
        self.traffic_up = list()
        self.traffic_down = list()
        self._future = asyncio.ensure_future(self.loop())

    def close(self):
        self.f_stop = True
        self._future.cancel()
        log.debug("traffic recoder close")

    async def loop(self):
        count = 0
        while True:
            try:
                wait_time = self.span
                while not self.f_stop and 0.0 < wait_time:
                    await asyncio.sleep(0.5)
                    wait_time -= 0.5

                count += 1
                ntime, up, down = int(time.time()), sum(self.traffic_up), sum(self.traffic_down)
                self.data.append((ntime, up, down))
                self.traffic_up.clear()
                self.traffic_down.clear()
                # recode
                if self.recode_dir is None:
                    continue
                date = time.strftime('%y-%m-%d')
                recode_path = os.path.join(self.recode_dir, 'traffic.%s.csv' % date)

                f_first = os.path.exists(recode_path)
                with open(recode_path, mode='a') as f:
                    if not f_first:
                        f.write("unix time,date,up (kb),down (kb)\n")
                    f.write("{},{},{},{}\n".format(ntime, time.strftime('%Hh%Mm', time.gmtime(ntime)),
                                                   round(up / 1000, 3), round(down / 1000, 3)))
            except asyncio.CancelledError:
                break
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
