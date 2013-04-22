#!/usr/bin/python
#
# reassemby.py
#
# Reassemly test with PicoTCP receiving and Linux sending
#
# (receiver)                       (Sender)
# PicoTCP ------------------------ Linux
#
# An udpecho is started which will receive DATASIZE bytes in one go
# from the socket. The Linux will send DATASIZE bytes in one go to the
# udpecho, this data will be sent fragmented. The udpecho is to reassemble
# this data and echo it back.
#

from  topology import *
import socket, random, string

SRC_ADDR = ''
LINK_ADDR = '172.16.1.2'
SRC_PORT = 5555
LISTEN_PORT = 6667
SENDTO_PORT = 5555
DATASIZE = 3400
UDPECHO = "udpecho:" + str(LINK_ADDR) + ":" + str(LISTEN_PORT) + ":" + str(SENDTO_PORT) + ":" + str(DATASIZE)

print UDPECHO

T = Topology()
net1 = Network(T, "pyt0")
h1 = Host(T, net1, args=UDPECHO)

str_send = ''.join(random.choice(string.ascii_lowercase) for x in range(DATASIZE))
#print str_send
s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_udp.bind((SRC_ADDR, SRC_PORT))
s_udp.settimeout(5);

raw_input("Press enter to continue ...")
start(T)

while True:
  s_udp.sendto(str_send, (LINK_ADDR, LISTEN_PORT))
  data = s_udp.recv(DATASIZE)
  #print len(data)
  if len(data) == DATASIZE:
    print '\n\n'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '+++++ reassembly test IS successful +++++'
    print '+++++++++++++++++++++++++++++++++++++++++++++'
    print '\n\n'
    cleanup()
    exit(0)

print '\n\n'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '+++++ reassembly test NOT successful ++++'
print '+++++++++++++++++++++++++++++++++++++++++++++'
print '\n\n'
cleanup()
exit(1)

