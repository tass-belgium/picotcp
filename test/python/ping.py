#!/usr/bin/python
from  topology import *

T = Topology()
net1 = Network(T)

h1 = Host(T, net1)
h2 = Host(T, net1, args="ping:172.16.1.1:")

sleep(1)
start(T)

wait(h2)
cleanup()
