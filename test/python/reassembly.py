#!/usr/bin/python
from  topology import *
import socket, random, string

IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0  # Never send DF frames.
IP_PMTUDISC_WANT = 1  # Use per route hints.
IP_PMTUDISC_DO = 2  # Always DF.
IP_PMTUDISC_PROBE = 3  # Ignore dst pmtu.

SRC_IP_UDP = ''
DST_IP_UDP = '172.16.1.2'
SRC_PORT_UDP = 6667
DST_PORT_UDP = 8888
SRC_IP_TCP = ''
DST_IP_TCP = '172.16.1.3'
SRC_PORT_TCP = 8889 
DST_PORT_TCP = 8889
STRLEN = 3400
UDPECHO = "udpecho:" + str(DST_PORT_UDP) + ":" + str(STRLEN)
TCPECHO = "tcpecho:" + str(DST_PORT_TCP)

T = Topology()
net1 = Network(T, "pyt0")

h1 = Host(T, net1, args=UDPECHO)
h2 = Host(T, net1, args=TCPECHO)

sleep(1)
start(T)
sleep(1)

# UDP test
raw_input("PYTH: press enter to perform UDP test ...")
str_send = ''.join(random.choice(string.ascii_lowercase) for x in range(STRLEN))
print "\nPYTH: SENDING STRING\n%s\n" % (str_send)
s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_udp.setblocking(0)
s_udp.bind((SRC_IP_UDP, SRC_PORT_UDP))
s_udp.sendto(str_send, (DST_IP_UDP, DST_PORT_UDP))
data = ''
__data = ''
r = 0
while True:
  __data=''
  sleep(1)
  __data = s_udp.recv(65565)
  print "PYTH: recv %d bytes" % (len(__data))
  r += len(__data)
  data += __data
  if r >= STRLEN:
    print "PYTH: received total of %d bytes" % (r)
    break

print "\nPYTH > RECEIVED STRING\n%s\n" % (data)

if data == str_send:
  print "\nPYTH > SUCCESS!\n"
else:
  print "\nPYTH > FAILURE!\n"
# end of UDP test

# TCP test
raw_input("PYTH: press enter to perform TCP test ...")
s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_tcp.setsockopt(socket.SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
s_tcp.connect((DST_IP_TCP, DST_PORT_TCP))
print "\nPYTH: SENDING STRING\n%s\n" % (str_send)
s_tcp.sendall(str_send)
sleep(1)
data = s_tcp.recv(65565)
s_tcp.close()
print "\nPYTH > RECEIVED STRING len = %d\n%s\n" % (len(data), data)

if data == str_send:
  print "\nPYTH > SUCCESS!\n"
else:
  print "\nPYTH > FAILURE!\n"
# end of TCP test

cleanup()
