#!/usr/bin/python
from  topology import *

'''
Add route to 172.16.0.0/16 gw 172.16.1.2 on your host machine.

Should result in something like:
~$ traceroute 172.16.8.2
traceroute to 172.16.8.2 (172.16.8.2), 30 hops max, 60 byte packets
 1  172.16.1.2 (172.16.1.2)  0.481 ms  0.473 ms  0.467 ms
 2  172.16.2.2 (172.16.2.2)  4.680 ms  4.702 ms  4.700 ms
 3  172.16.3.2 (172.16.3.2)  8.759 ms  8.768 ms  8.766 ms
 4  172.16.4.2 (172.16.4.2)  10.791 ms  10.789 ms  10.786 ms
 5  172.16.5.2 (172.16.5.2)  12.826 ms  12.825 ms  12.821 ms
 6  172.16.6.2 (172.16.6.2)  14.844 ms  17.858 ms  17.857 ms
 7  172.16.7.2 (172.16.7.2)  17.858 ms  14.000 ms  13.999 ms
 8  172.16.8.2 (172.16.8.2)  18.032 ms  18.029 ms  18.023 ms

'''


T = Topology()
net1 = Network(T, 'nat0')
net2 = Network(T)
net3 = Network(T)
net4 = Network(T)
net5 = Network(T)
net6 = Network(T)
net7 = Network(T)
net8 = Network(T)

router1 = Host(T, net1, net2, args="natbox:172.16.2.1")
router2 = Host(T, net2, net3, args="natbox:172.16.3.1")
router3 = Host(T, net3, net4, args="natbox:172.16.4.1")
router4 = Host(T, net4, net5, args="natbox:172.16.5.1")
router5 = Host(T, net5, net6, args="natbox:172.16.6.1")
router6 = Host(T, net6, net7, args="natbox:172.16.7.1")
router7 = Host(T, net7, net8, args="natbox:172.16.8.1")

h1 = Host(T, net8)

sleep(1)
start(T)
loop()
cleanup()
