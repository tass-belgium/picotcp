#!/bin/bash

sudo vde_switch -s /tmp/switch -t tap0 -d -hub
sudo ifconfig tap0 192.168.24.5 netmask 255.255.255.0 up
sudo ./test.elf
