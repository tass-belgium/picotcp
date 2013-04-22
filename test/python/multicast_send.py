#!/usr/bin/python
#
# multicast_send.py
#
# Multicast test with PicoTCP sending and Linux receiving
#
# (sender)                         (Receiver)
# PicoTCP ------------------------ Linux
#            mcast to 224.7.7.7
#

from  topology import *
import socket, random, string, struct

IF_ADDR = '172.16.1.1'
LINK_ADDR = '172.16.1.2'
MCAST_ADDR = '224.7.7.7'
LISTEN_PORT = 6667
SENDTO_PORT = 6667
MCASTSEND = "mcastsend:" + str(LINK_ADDR) + ":" + str(MCAST_ADDR) + ":" + str(SENDTO_PORT) + ":" + str(LISTEN_PORT)

print MCASTSEND

T = Topology()
net1 = Network(T, "pyt0")
h1 = Host(T, net1, args=MCASTSEND)

s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_udp.bind((MCAST_ADDR, LISTEN_PORT))
s_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s_udp.settimeout(5);

mreq = struct.pack("=4s4s", socket.inet_aton(str(MCAST_ADDR)), socket.inet_aton(str(IF_ADDR)))
s_udp.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

raw_input("Press enter to continue ...")
start(T)
sleep(1)

while True:
  data = s_udp.recv(4096)
  #print data
  if 'end' in data:
    print '\n\n'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '+++++ multicast_send test IS successful +++++'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '\n\n'
    cleanup()
    exit(0)

print '\n\n'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '+++++ multicast_send test NOT successful ++++'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '\n\n'
cleanup()
exit(1)
