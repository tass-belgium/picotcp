#!/bin/bash

# check if user is root
if [[ $EUID -eq 0 ]]
then
   echo "This script must not be run as root"
   exit 1
fi

vdecmd -s /tmp/pico.mgmt shutdown
sleep 1
vde_switch -s /tmp/pic0.ctl -M /tmp/pico.mgmt -d
slirpvde -s /tmp/pic0.ctl --dhcp --daemon
./build/test/dhcp_example.elf || exit 55
