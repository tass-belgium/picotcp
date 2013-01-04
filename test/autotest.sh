#!/bin/bash

sh ./test/vde_sock_start_user.sh
sleep 2

echo "TCP TEST"
(./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0: -a tcpecho:6667) &
./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0: -a tcpclient:10.40.0.8:6667 || exit 1
wait %1 || exit 1
wait

echo "UDP TEST"
(./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0: -a udpecho:6667 >/dev/null) &
./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0: -a udpclient:10.40.0.8:6667 >/dev/null || exit 1
wait %1 || exit 1
wait

echo "NAT TCP TEST"
(./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.0.0: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.0.0: -a natbox:10.50.0.10) &
sleep 2
(./build/test/picoapp --vde pic0:/tmp/pic1.ctl:10.50.0.8:255.255.0.0: -a tcpecho:6667 >/dev/null) &
sleep 2
./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10: -a tcpclient:10.50.0.8:6667: || exit 1

echo "Waiting for echo server to finish..."
wait %2 || exit 1

killall picoapp

echo "NAT UDP TEST"
(./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.0.0: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.0.0: -a natbox:10.50.0.10) &
(./build/test/picoapp --vde pic0:/tmp/pic1.ctl:10.50.0.8:255.255.0.0: -a udpecho:6667 >/dev/null) &
./build/test/picoapp --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10: -a udpclient:10.50.0.8:6667: || exit 1
wait %2 || exit 1


killall picoapp


killall vde_switch
echo "SUCCESS!" && exit 0
