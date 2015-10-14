#!/bin/bash

gksu "vdecmd -s /tmp/pico.mgmt shutdown"
gksu "vdecmd -s /tmp/pico1.mgmt shutdown"
gksu "vde_switch -t pic0 -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub"
gksu "vde_switch -t pic1 -x -s /tmp/pic1.ctl -m 777 -M /tmp/pico1.mgmt -d -hub"

# we prefer to use ip over ifconfig (which is obsolete), but the script has to work when ip is not available as well
USINGIP=1
command -v ip >/dev/null 2>&1 || USINGIP=0

if [ $USINGIP -eq 1 ]; 
then
	gksu "ip addr add 10.40.0.1/24 dev pic0"
	gksu "ip addr add 10.50.0.1/24 dev pic1"
else
	gksu "ifconfig pic0 10.40.0.1 netmask 255.255.255.0"
	gksu "ifconfig pic1 10.50.0.1 netmask 255.255.255.0"
fi
#ping 10.40.0.3 &


