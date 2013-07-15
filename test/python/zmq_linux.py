#!/usr/bin/python
from  topology import *
import zmq
import sys

T = Topology()
net1 = Network(T, "pyt0")

#h1 = Host(T, net1)
h2 = Host(T, net1, args="zeromq_prod:")

sleep(1)
raw_input("Press enter to continue ...")
start(T)

# Zeromq part
ctx = zmq.Context()
z = ctx.socket(zmq.SUB)
z.setsockopt(zmq.SUBSCRIBE, "")
z.connect("tcp://172.16.1.2:1207")
print "In the loop..."
for i in range(20):
  if z.poll(20000) == 0:
    print "Timeout!!!"
    cleanup()
    sys.exit(1)
  else:
    msg = z.recv()
    print "Recvd msg len=%d content: %s" % (len(msg), msg)
  



cleanup()
