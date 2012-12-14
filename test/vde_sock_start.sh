#!/bin/bash

gksu "vdecmd -s /tmp/pico.mgmt shutdown"
gksu "vdecmd -s /tmp/pico1.mgmt shutdown"
gksu "vde_switch -t pic0 -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub"
gksu "vde_switch -t pic1 -x -s /tmp/pic1.ctl -m 777 -M /tmp/pico1.mgmt -d -hub"
gksu "ifconfig pic0 10.40.0.1 netmask 255.255.255.0"
gksu "ifconfig pic1 10.50.0.1 netmask 255.255.255.0"

#ping 10.40.0.3 &


