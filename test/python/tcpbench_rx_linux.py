#!/usr/bin/python
from  topology import *

T = Topology()
net1 = Network(T, "pyt0")

h2 = Host(T, net1, args="tcpbench:r:6660:")

sleep(1)
start(T)

wait(h2)
cleanup()
