#!/usr/bin/env bash

sudo apt-get update -y
sudo apt-get install -y check vde2 libvdeplug2-dev libpcap0.8-dev openvpn
make -j$(nproc)
