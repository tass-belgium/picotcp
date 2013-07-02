#!/usr/bin/python
#

from  topology import *

T = Topology()
net1 = Network(T, "pyt0")
send1 = Host(T, net1, args="tcpbench:t:172.16.1.3:7770:")
recv1 = Host(T, net1, args="tcpbench:r:7770:")


sleep(1)
raw_input("Press enter to continue ...")

start(T)
wait(send1)
cleanup()
