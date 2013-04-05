#!/usr/bin/python
# fairness.py
# A complex test for butterly-like topology,
# using 3 TCP connections and 3 ping flows.
#
# Bottleneck of 4 Mbit/300 ms overall delay is added.
#
# s1---.                 .---r1
# s2----\               /
# s3-----\__. DHCP  .__/__.--r2
# s4-----/             \
# s5----/               \_.--r3
# s6---^
#

from  topology import *

T = Topology()
net1 = Network(T, "pyt0")
net2 = Network(T)

server = Host(T, net1, args="dhcpserver:eth1:172.16.1.2:255.255.255.0:64:128")

client1 = Host(T, net1, args="dhcpclient:eth1")
client2 = Host(T, net1, args="dhcpclient:eth1")
client3 = Host(T, net1, args="dhcpclient:eth1")
client4 = Host(T, net1, args="dhcpclient:eth1")
client5 = Host(T, net1, args="dhcpclient:eth1")
client6 = Host(T, net1, args="dhcpclient:eth1")

raw_input("Press enter to continue ...")
start(T)

wait(server)

cleanup()
