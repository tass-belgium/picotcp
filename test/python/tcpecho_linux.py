#!/usr/bin/python
from  topology import *

T = Topology()
net1 = Network(T, "pyt0")

#h1 = Host(T, net1)
h2 = Host(T, net1, args="tcpecho:8888", delay1="20", loss1="0.01")
#h3 = Host(T, net1, args="tcpbench:t:172.16.1.1:")

sleep(1)
start(T)

#wait(h3)
wait(h2)
cleanup()
