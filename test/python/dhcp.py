#!/usr/bin/python
# dhcp.py
# Butterfly-like topology test for dhcp
# One DHCP server, serving on two interface
# Eigth DHCP clients, four on each network
#
# s1----@            @----r1
# s2-----\__ DHCP __/-----r2
# s3-----/          \-----r3
# s4----@            @----r4
#


from  topology import *

T = Topology()
net1 = Network(T, "pyt1")
net2 = Network(T, "pyt2")

server = Host(T, net1, net2, args="dhcpserver:eth1:172.16.1.2:255.255.255.0:64:128:eth2:172.16.2.2:255.255.255.0:64:128")

s1 = Host(T, net1, args="dhcpclient:eth1")
s2 = Host(T, net1, args="dhcpclient:eth1")
s3 = Host(T, net1, args="dhcpclient:eth1")
s4 = Host(T, net1, args="dhcpclient:eth1")
r1 = Host(T, net2, args="dhcpclient:eth1")
r2 = Host(T, net2, args="dhcpclient:eth1")
r3 = Host(T, net2, args="dhcpclient:eth1")
r4 = Host(T, net2, args="dhcpclient:eth1")

raw_input("Press enter to continue ...")
start(T)

wait(server)

cleanup()
