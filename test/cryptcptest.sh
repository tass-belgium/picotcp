#!/bin/bash

sh ./test/vde_sock_start_user.sh
sleep 2
ulimit -c unlimited

echo "TCP TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0: -a cryptcpbench:r:6667:) &
time (./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0: -a cryptcpbench:t:10.40.0.8:6667: || exit 1)
killall picoapp.elf

echo "SUCCESS!" && exit 0
