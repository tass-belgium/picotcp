#!/bin/bash

# check if user is root
if [[ $EUID -ne 0 ]]
then
   echo "This script must be run as root"
   exit 1
fi

vde_switch -s /tmp/pic0.ctl -t tap0 -d -hub
slirpvde -s /tmp/pic0.ctl --dhcp --daemon
ifconfig tap0 10.40.0.1 netmask 255.255.255.0 up
