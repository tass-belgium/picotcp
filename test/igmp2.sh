#!/bin/bash

# check if user is root
if [[ $EUID -ne 0 ]]
then
   echo "This script must be run as root"
   exit 1
fi

#set up vde_switch
gksu "vdecmd -s /tmp/pico.mgmt shutdown"
gksu "vde_switch -t pic0 -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub"
gksu "ifconfig pic0 10.40.0.1 netmask 255.255.255.0 up"

#set up XORP router
#gksu "xorp_rtrmgr -b xorp.conf"
