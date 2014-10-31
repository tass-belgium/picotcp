#!/bin/bash

vdecmd -s /tmp/pico.mgmt shutdown
vdecmd -s /tmp/pici.mgmt shutdown
vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub -t vde0
vde_switch -s /tmp/pic1.ctl -m 777 -M /tmp/pici.mgmt -d -hub
/sbin/ifconfig vde0 10.50.0.1 netmask 255.255.0.0
