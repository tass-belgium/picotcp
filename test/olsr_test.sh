#!/bin/bash

./build/test/picoapp.elf \
  --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10: \
  --vde pic1:/tmp/pic1.ctl:10.41.0.9:255.255.0.0: \
  -a olsr: &


./build/test/picoapp.elf \
  --vde pic1:/tmp/pic1.ctl:10.41.0.1:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic1:/tmp/pic1.ctl:10.41.0.2:255.255.0.0: \
  -a olsr: & 

./build/test/picoapp.elf \
  --vde pic1:/tmp/pic1.ctl:10.41.0.3:255.255.0.0: \
  -a olsr: & 
