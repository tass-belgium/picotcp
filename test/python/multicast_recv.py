#!/usr/bin/python
# multicast_recv.py
#
# Multicast test with PicoTCP receiving and Linux sending
#
# (sender)                         (Receiver)
# Linux   ------------------------ PicoTCP
#            mcast to 224.7.7.7
#
from  topology import *
import socket, random, string

IF_ADDR = '172.16.1.1'
LINK_ADDR = '172.16.1.2'
MCAST_ADDR = '224.7.7.7'
SRC_PORT = 5555
LISTEN_PORT = 6667
SENDTO_PORT = 6667
MCASTRECV = "mcastreceive:" + str(LINK_ADDR) + ":" + str(MCAST_ADDR) + ":" + str(LISTEN_PORT) + ":" + str(SENDTO_PORT)

print MCASTRECV

T = Topology()
net1 = Network(T, "pyt0")
h1 = Host(T, net1, args=MCASTRECV)

# sending socket
s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_udp.bind((IF_ADDR, SRC_PORT))
s_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s_udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
s_udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(str(IF_ADDR)))

# receiving socket
s_udp_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_udp_recv.bind((IF_ADDR, LISTEN_PORT))
s_udp_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s_udp_recv.settimeout(5);

raw_input("Press enter to continue ...")
start(T)
sleep(1)

while True:
  s_udp.sendto("multicast test succeeded", (str(MCAST_ADDR), LISTEN_PORT))
  data = s_udp_recv.recv(4096)
  #print data
  if 'succeeded' in data:
    print '\n\n'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '+++++ multicast_recv test IS successful +++++'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '\n\n'
    cleanup()
    exit(0)

print '\n\n'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '+++++ multicast_recv test NOT successful ++++'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '\n\n'
cleanup()
exit(1)

