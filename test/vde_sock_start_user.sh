#!/bin/bash

vdecmd -s /tmp/pico.mgmt shutdown
vdecmd -s /tmp/pici.mgmt shutdown
vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub
vde_switch -s /tmp/pic1.ctl -m 777 -M /tmp/pici.mgmt -d -hub


