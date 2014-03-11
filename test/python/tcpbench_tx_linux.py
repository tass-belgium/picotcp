#!/usr/bin/python
from  topology import *

T = Topology()
net1 = Network(T, "pyt0")

#h1 = Host(T, net1)
h3 = Host(T, net1, args="tcpbench:t:172.16.1.1:6660:")

sleep(1)
raw_input("Press enter to continue ...")
start(T)

wait(h3)
cleanup()
