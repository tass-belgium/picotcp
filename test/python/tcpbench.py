#!/usr/bin/python
#

from  topology import *

T = Topology()
net1 = Network(T)
send1 = Host(T, net1, args="tcpbench:t:172.16.1.2:")
recv1 = Host(T, net1, args="tcpbench:r:")


sleep(1)
start(T)
wait(send1)
cleanup()
