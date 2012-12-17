#!/bin/bash

vdecmd -s /tmp/pico.mgmt shutdown
vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub


