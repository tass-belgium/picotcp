#!/bin/bash

sudo vde_switch -s /tmp/switch -t tap0 -d -hub
sudo ifconfig tap0 192.171.24.5 netmask 255.255.255.0 up
sudo build/test/test_http.elf
