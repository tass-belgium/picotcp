#!/usr/bin/python
#

from  topology import *

T = Topology()
net1 = Network(T,"udp0")
echo = Host(T, net1, args="udpecho:172.16.1.2:7770:7770:1400:")


sleep(1)
raw_input("Press enter to continue ...")

start(T)
wait(echo)
cleanup()
