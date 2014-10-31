#!/bin/bash

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

vdecmd -s /tmp/pico.mgmt shutdown
vdecmd -s /tmp/pici.mgmt shutdown
rm -rf /tmp/pic0.ctl
rm -rf /tmp/pic1.ctl
vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub -t vde0
vde_switch -s /tmp/pic1.ctl -m 777 -M /tmp/pici.mgmt -d -hub
/sbin/ifconfig vde0 10.50.0.1 netmask 255.255.0.0
