#!/bin/bash
killall wirefilter

gksu "vdecmd -s /tmp/pico.mgmt shutdown"
gksu "vdecmd -s /tmp/pico1.mgmt shutdown"
gksu "vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d"
gksu "vde_switch -t pic0 -s /tmp/pic1.ctl -m 777 -M /tmp/pico1.mgmt -d"
gksu "ifconfig pic0 10.40.0.1 netmask 255.255.255.0"
wirefilter -v /tmp/pic0.ctl:/tmp/pic1.ctl -d 100 -l 1 &

#ping 10.40.0.3 &


