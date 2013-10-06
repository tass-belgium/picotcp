#!/bin/bash

sudo vde_switch -t pic0 -s /tmp/pic0.ctl -d
sudo vde_switch -s /tmp/pic1.ctl -d
sudo vde_switch -s /tmp/pic2.ctl -d
sudo vde_switch -s /tmp/pic3.ctl -d

sudo ifconfig pic0 10.40.0.254/16 up

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0: \
  --vde pic1:/tmp/pic1.ctl:10.41.0.9:255.255.0.0: \
  -a olsr: &

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic1.ctl:10.41.0.1:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic1.ctl:10.41.0.2:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic1.ctl:10.41.0.3:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic1.ctl:10.41.0.10:255.255.0.0: \
  --vde pic1:/tmp/pic2.ctl:10.42.0.10:255.255.0.0: \
  -a olsr: &

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic2.ctl:10.42.0.1:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic2.ctl:10.42.0.2:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic1.ctl:10.42.0.3:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic2.ctl:10.42.0.11:255.255.0.0: \
  --vde pic1:/tmp/pic3.ctl:10.43.0.11:255.255.0.0: \
  -a olsr: &

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic3.ctl:10.43.0.1:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic3.ctl:10.43.0.2:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic3.ctl:10.43.0.3:255.255.0.0: \
  -a olsr: & 

sleep 5
sudo killall olsrd
sudo olsrd -i pic0

