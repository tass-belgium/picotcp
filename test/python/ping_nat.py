#!/usr/bin/python
from  topology import *

T = Topology()
net1 = Network(T, 'nat0')
net2 = Network(T)


h1 = Host(T, net1, args="ping:172.16.2.1:")
h2 = Host(T, net2)
router1 = Host(T, net1, net2, args="natbox:172.16.2.2:")

sleep(1)
start(T)

wait(h1)
cleanup()
