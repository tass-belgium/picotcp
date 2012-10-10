#!/bin/bash

gksu "vdecmd -s /tmp/pico.mgmt shutdown"
gksu "vde_switch -t pic0 -s /tmp/pico.ctl -m 777 -M /tmp/pico.mgmt -d"
gksu "ifconfig pic0 10.40.0.1 netmask 255.255.255.0"

#ping 10.40.0.3 &


