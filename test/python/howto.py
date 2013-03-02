#PicoTCP topology test environment.
#Guidelines to prepare test scenarios.
#
#The interface is simple, it has three objects:
# * Topology
# * Network
# * Host
#
#And a handful of helping routines, such as:
# * start()
# * loop()
# * sleep()
# * wait()
#
#
########################################################################
#== Create a test scenario                                           ==#
########################################################################
# Every script file will start with: "#!/usr/bin/python" in the first
# line, and will have execution permissions. This script is an exception
# because it is not intended to be run, as it is in fact a walkthrough to
# all the functionalities.

# Importing the topology objects is mandatory, so add:
from topology import *

# A Topology must be created to use all other objects:
T = Topology()

# Now, we can create "Network" objects. The networks will have address
# 172.16.X.0/24, where 'X' is the order of creation, starting from 1.
#

network1 = Network(T)
network2 = Network(T)
# The two networks are separated and using different address pools:
#
#   ## ### ## ##       ## ### ## ##
#  #  network1  #     #  network2  #
#  # 172.16.1.0 #     # 172.16.2.0 #
#   ## ## ######       ## ## ######
#

# If you are running your test as root, you can also add a tun-tap connection
# to the network, which will be automatically configured:
networkLocal = Network(T,'tap0')


# In the same way ad networks, you can create a PicoTCP Host that connects to a
# network as follows:
host1_1 = Host(T, network1)

# Also, you can specify a role for the application/host, by using picoapp's
# args format for '--app'. For example, the machine below will ping the previously
# created one:
host1_2 = Host(T, network1, args ="ping:172.16.1.1:")
#
#             ## ### ## ##       ## ### ## ##
#   host1.1--#  network1  #     #  network2  #
#            # 172.16.1.0 #     # 172.16.2.0 #
#             ## ## ######       ## ## ######
#            /
# host1.2___/
# (ping host1.1)
#

# At this point, a picoTCP host with two network cards can connect
# the two networks like this:
router1 = Host(T, network1, network2)
#
#             ## ### ## ##  router1  ## ### ## ##
#   host1.1--#  network1  #__/  \__ #  network2  #
#            # 172.16.1.0 #         # 172.16.2.0 #
#             ## ## ######           ## ## ######
#            /
# host1.2___/
# (ping host1.1)

# Now, we can attach an host to the second network too:
# Connection to the host can be an emulated channel, i.e.
# it is possible to add bidirectional delay and limited
# bandwidth in the link between the host and the network:
#

host2_2 = Host(network2, delay1="100", bw1="500K")
#
#             ## ### ## ##  router1  ## ### ## ##
#   host1.1--#  network1  #__/  \__ #  network2  #
#            # 172.16.1.0 #         # 172.16.2.0 #
#             ## ## ######           ## ## ######
#            /                       *
# host1.2.__/                         \._*_*_host2.2
# (ping host1.1)

## Since the routes will be automatically added before the test starts,
# all the hosts in the networks will be reachable to each other:
# all the picoapps will have their static routes populated automatically
# by the topology tool, no matter how complex the network is. The only
# requirement is that all the networks share at least one router.
#
# For this reason, we can create a host that pings across the network:
host1_4 = Host(T, network1, args="ping:172.16.2.2:")
#
#    host1.4.
# (ping 2.2) \
#             \## ### ## ##  router1  ## ### ## ##
#    host1.1--#  network1  #__/  \__ #  network2  #
#             # 172.16.1.0 #         # 172.16.2.0 #
#              ## ## ######           ## ## ######
#             /                       *
#  host1.2.__/                         \._*_*_host2.2
#  (ping host1.1)

########################################################################
#== Start the test                                                   ==#
########################################################################
# All the host will be connected and activated when you call:
start()

# At this point you may want to define your exit strategy. Valid commands
# are:

loop() # Loop forever, until the test is interrupted (e.g. by ctrl+c)

sleep(N) # Sleep N seconds

wait(host1_4) # Wait for application running on host 1.4, and return only if
              # it has terminated


########################################################################
#== End the test                                                     ==#
########################################################################
# Always call:
cleanup()
