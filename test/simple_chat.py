#!/user/env python3
# -*- coding: utf-8 -*-

from p2p_python.client import PeerClient, C_BROADCAST
from test.utils import LookBroadcast
import random
import time


def get_name(cs):
    return {n[3]['p2p_port'] for n in cs}


def check_client(pc):
    return [get_name(c) for c in pc.p2p.client]


def chat(name):
    port = random.randint(2000, 2100)
    pc = PeerClient(port=port, net_ver=10000, listen=10)
    pc.start(f_server=True, f_stabilize=True)
    lb = LookBroadcast(pc=pc)
    lb.start()
    print("Create port ", port)

    while True:
        try:
            cmd = input(">>")
            if cmd.startswith('/'):
                cmds = cmd[1:].split()
                if cmds[0] == 'join':
                    host, port = ('127.0.0.1', int(cmds[1])) if len(cmds) == 2 else (cmds[1], int(cmds[2]))
                    if pc.p2p.create_connection(host, port):
                        print("Joined")
                        pc.send_command(cmd=C_BROADCAST, data='Join \"%s\"' % name)
                    else:
                        print("Failed")

                elif cmds[0] == 'exc':
                    exec('print(' + input('>> ') + ')')

                else:
                    print("Not found cmd", cmds)
            else:
                data = '[{}][{:10}] {}'.format(time.strftime('%d-%H-%M-%S'), name, cmd)
                pc.send_command(cmd=C_BROADCAST, data=data)

        except KeyboardInterrupt:
            break
        except ConnectionError:
            print("Error, No members")
        except Exception as e:
            print("Error", e)

    pc.send_command(cmd=C_BROADCAST, data='Leave \"%s\"' % name)


if __name__ == '__main__':
    your_name = input("name >> ")
    chat(your_name)
"""
/join 2084
/exc
"""