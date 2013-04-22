#!/usr/bin/python
#
# fragmentation.py
#
# Fragmentation test with PicoTCP sending and Linux receiving
#
# (sender)                         (Receiver)
# PicoTCP ------------------------ Linux
#
# An udpclient is started which will give DATASIZE bytes in one go
# to the socket. This data will be fragmented and send over to the
# Linux, where it is reassembled and received in one piece.
#

from  topology import *
import socket, random, string

SRC_ADDR = ''
DST_ADDR = '172.16.1.1'
SRC_PORT = 6667
SENDTO_PORT = 6667
LISTEN_PORT = 6667
DATASIZE = 4000
LOOPS = 4
SUBLOOPS = 1
UDPCLIENT = "udpclient:" + str(DST_ADDR) + ":" + str(SENDTO_PORT) + ":"  + str(LISTEN_PORT) + ":" + str(DATASIZE) + ":" + str(LOOPS) + ":" + str(SUBLOOPS)

print UDPCLIENT

T = Topology()
net1 = Network(T, "pyt0")
h1 = Host(T, net1, args=UDPCLIENT)

s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_udp.bind((SRC_ADDR, SRC_PORT))
s_udp.settimeout(5);

raw_input("Press enter to continue ...")
start(T)

while True:
  data, addr = s_udp.recvfrom(DATASIZE)
  #print data
  if len(data) == DATASIZE:
    print '\n\n'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '+++++ fragmentation test IS successful +++++'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '\n\n'
    cleanup()
    exit(0)

print '\n\n'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '+++++ fragmentation test NOT successful ++++'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '\n\n'
cleanup()
exit(1)

