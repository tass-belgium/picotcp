#!/usr/bin/python
# fairness.py
# A complex test for butterly-like topology,
# using 3 TCP connections and 3 ping flows.
#
# s1---.                 .---r1
# s2----\               /
# s3-----\__.R1---R2.__/__.--r2
# s4-----/             \
# s5----/               \_.--r3
# s6---^
#

from  topology import *

T = Topology()
net1 = Network(T)
net2 = Network(T)
net3 = Network(T)

#router1 = Host(T, net1, net2, "natbox:172.16.2.1:")
#router2 = Host(T, net2, net3, "natbox:172.16.3.1:")
router1 = Host(T, net1, net2)
router2 = Host(T, net2, net3)

send1 = Host(T, net1, args="tcpbench:t:172.16.3.2:")
send2 = Host(T, net1, args="tcpbench:t:172.16.3.3:")
send3 = Host(T, net1, args="tcpbench:t:172.16.3.4:")

send4 = Host(T, net1, args="ping:172.16.3.2:")
send5 = Host(T, net1, args="ping:172.16.3.3:")
send6 = Host(T, net1, args="ping:172.16.3.4:")


recv1 = Host(T, net3, args="tcpbench:r:")
recv2 = Host(T, net3, args="tcpbench:r:")
recv3 = Host(T, net3, args="tcpbench:r:")
recv4 = Host(T, net3, args="tcpbench:r:")


sleep(1)
start(T)

wait(send1)
wait(send2)
wait(send3)

cleanup()
