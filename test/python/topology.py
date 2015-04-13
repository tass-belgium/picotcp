#!/usr/bin/python
# Python classes definition for the picoTCP
# topology test environment
#
# Copyright (c) 2013-2015 Altran Intelligent Systems. See LICENSE for usage.

import  sys, os, subprocess, time, re

def test_tuntap():
  if not os.geteuid()==0:
    sys.exit("\nOnly root can use real devices contained in this script\n")

class Topology:
  def __init__(self):
    self.nets = []
    self.nodes = []
    self.nextn = 1
    self.hosts = []


class Network:
  def __init__(self, topology, real=''):
    self.n = topology.nextn
    topology.nextn += 1
    self.nodes = []
    self.topology = topology
    self.topology.nets.append(self)
    self.sock = "/tmp/topology/net"+`self.n`
    self.nextn = 1
    vdecmd = ["vde_switch", "-x" , "-s", self.sock, "-m", self.sock+".mgmt"]
    if real != '':
      test_tuntap()
      vdecmd.append('-t')
      vdecmd.append(real)
      vdecmd.append('-x')
    self.pop = subprocess.Popen(vdecmd, stdin=subprocess.PIPE)
    self.hosts = []
    print ""
    print vdecmd
    print "Created network "+self.sock
    if real != '':
      subprocess.call(["ifconfig",real,"172.16."+`self.n`+".1", "netmask", "255.255.255.0", "up"])
      self.nextn = 2

class Node:
  def __init__(self,topology, network = None):
    if (network is None):
      network = Network(topology)
    self.net = network
    self.n = network.nextn
    network.nextn += 1
    self.net.nodes.append(self)
    self.topology = topology
    self.topology.nodes.append(self)

class Host:
  def add_routes(self, topology):
    for eth in [self.eth1, self.eth2]:
      if eth and not self.args.startswith("dhcpclient"):
        net = eth.net
        for h in topology.hosts:
          if h.eth1 and h.eth2:
            dst=""
            gw=""
            routing=False
            if (h.eth2.net.n == net.n) and (self not in h.eth1.net.hosts):
              if h.eth1.net.n > net.n or h.nat == False:
                print "FOUND route to net "+`h.eth1.net.n`
                dst_net = h.eth1.net.n
                gw_net = h.eth2.net.n
                gw_n = h.eth2.n
                routing=True
            elif (h.eth1.net.n == net.n) and (self not in h.eth2.net.hosts):
              if h.eth2.net.n > net.n or h.nat == False:
                print "FOUND route to net "+`h.eth2.net.n`
                dst_net = h.eth2.net.n
                gw_net = h.eth1.net.n
                gw_n = h.eth1.n
                routing=True

            if (routing):
              dst = "172.16."+`dst_net`+".0"
              gw = "172.16."+`gw_net`+"."+`gw_n`
              self.routes.append("-r")
              self.routes.append(dst+":255.255.255.0:"+gw+":")
            if (routing and gw_net > dst_net and h.nat == False):
              dst_net -= 1
              while(dst_net > 0):
                dst = "172.16."+`dst_net`+".0"
                self.routes.append("-r")
                self.routes.append(dst+":255.255.255.0:"+gw+":")
                dst_net -= 1
            elif (routing and gw_net != None and gw_net  < dst_net):
              dst_net += 1
              while(dst_net < net.topology.nextn):
                dst = "172.16."+`dst_net`+".0"
                self.routes.append("-r")
                self.routes.append(dst+":255.255.255.0:"+gw+":")
                dst_net += 1
  def parse_options(self, eth, delay, bw, loss):
    if (delay != "" or  bw != ""):
      mysock = eth.net.sock + "__" + `eth.n`
      wirecmd = ['wirefilter', '-v']
      wirecmd.append(mysock +":" + eth.net.sock)
      if (delay != ''):
        wirecmd.append("-d")
        wirecmd.append(delay)
      if (bw != ''):
        wirecmd.append("-b")
        wirecmd.append(bw)
      if (loss != ''):
        wirecmd.append("-l")
        wirecmd.append(loss)
      print wirecmd
      subprocess.Popen(['vde_switch', '-s', mysock], stdin=subprocess.PIPE)
      subprocess.Popen(wirecmd, stdin=subprocess.PIPE)
    else:
      mysock = eth.net.sock
    return mysock

  def __init__(self, topology, net1=None, net2=None, gw=None, args="tcpecho:5555", delay1="", bw1="", delay2="", bw2="", loss1="", loss2=""):
    if net1:
      self.eth1 = Node(topology, net1)
      net1.hosts.append(self)
    else:
      self.eth1 = None
    if net2:
      self.eth2 = Node(topology, net2)
      net2.hosts.append(self)
    else:
      self.eth2 = None
    self.cmd = ["./build/test/picoapp.elf"]
    self.gw = gw
    if args.startswith("nat"):
      self.nat = True
    else:
      self.nat = False


    if (net1):
      mysock = self.parse_options(self.eth1, delay1, bw1, loss1)
      if (args.startswith("dhcpclient")):
        self.cmd.append("--barevde")
        vdeline = "eth1:"+mysock+':'
      else:
        self.cmd.append("--vde")
        vdeline = "eth1:"+mysock+':'+"172.16."+`self.eth1.net.n`+"."+`self.eth1.n`+":255.255.255.0:"
      if (self.gw and re.search("172\.16\."+`self.eth1.net`, self.gw)):
        vdeline +=self.gw+":"
      self.cmd.append(vdeline)
    if (net2):
      mysock = self.parse_options(self.eth2, delay2, bw2, loss2)
      if (args.startswith("dhcpclient")):
        self.cmd.append("--barevde")
        vdeline = "eth2:"+mysock+':'
      else:
        self.cmd.append("--vde")
        vdeline = "eth2:"+mysock+':'+"172.16."+`self.eth2.net.n`+"."+`self.eth2.n`+":255.255.255.0:"
      if (self.gw and re.search("172\.16\."+`self.eth2.net`+".", self.gw)):
        vdeline +=self.gw+":"
      self.cmd.append(vdeline)
    self.args = args
    self.pop = None
    topology.hosts.append(self)
    self.routes = []


  def start(self):
    if self.pop:
      return
    for r in self.routes:
      self.cmd.append(r)
    self.cmd.append("-a")
    self.cmd.append(self.args)
    print self.cmd
    self.pop = subprocess.Popen(self.cmd)



def cleanup():
  try:
    subprocess.call(["killall","vde_switch"])
    subprocess.call(["killall","picoapp.elf"])
    subprocess.call(["killall","wirefilter"])
    os.unlink("/tmp/topology")
  except:
    pass



def loop():
  while(True):
    time.sleep(1)
  sys.exit(0)

def sleep(n):
  time.sleep(n)

def wait(x):
  if (x is None):
    print("start failed: "+x.cmd)
    sys.exit(1)
  while (x.pop.poll() == None):
    time.sleep(1)
  print "Goodbye"
  sys.exit(0)

def start(T):
  print "Calculating routes.."
  for n in T.nets:
    for h in n.hosts:
      h.add_routes(T)
  print "Done!"
  print "Starting up..."
  for n in T.nets:
    for h in n.hosts:
      h.start()

try:
  os.mkdir("/tmp/topology/")
except:
  pass
cleanup()
