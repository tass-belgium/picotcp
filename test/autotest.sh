#!/bin/bash

sh ./test/vde_sock_start_user.sh
rm -f /tmp/pico-mem-report-*
sleep 2
ulimit -c unlimited
killall picoapp.elf
killall picoapp6.elf


echo "IPV6 tests!"
echo "PING6 LOCALHOST"
./build/test/picoapp6.elf --loop -a ping,::1, || exit 1

echo "PING6 TEST"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,,,) &
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a ping,aaaa::1, || exit 1
killall picoapp6.elf


echo "TCP6 TEST"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,, -a tcpbench,r,6667,,) &
time (./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a tcpbench,t,aaaa::1,6667,, || exit 1)
killall picoapp6.elf

echo "TCP6 TEST (with 2% packet loss on both directions)"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,2,2, -a tcpbench,r,6667,,) &
time (./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a tcpbench,t,aaaa::1,6667,, || exit 1)
killall picoapp6.elf

echo "TCP6 TEST (nagle)"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,, -a tcpbench,r,6667,n,) &
time (./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a tcpbench,t,aaaa::1,6667,n, || exit 1)
killall picoapp6.elf

echo "UDP6 TEST"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,, -a udpecho,aaaa::1,6667,) &
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a udpclient,aaaa::1,6667,6667,1400,100,10, || exit 1
wait || exit 1
wait

killall picoapp6.elf
#echo "MULTICAST TEST"
#(./build/test/picoapp.elf --vde pic1:/tmp/pic0.ctl:10.40.0.3:255.255.0.0: -a mcastreceive:10.40.0.3:224.7.7.7:6667:6667) &
#(./build/test/picoapp.elf --vde pic2:/tmp/pic0.ctl:10.40.0.4:255.255.0.0: -a mcastreceive:10.40.0.4:224.7.7.7:6667:6667) &
#(./build/test/picoapp.elf --vde pic3:/tmp/pic0.ctl:10.40.0.5:255.255.0.0: -a mcastreceive:10.40.0.5:224.7.7.7:6667:6667) &
#sleep 2
#./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0: -a mcastsend:10.40.0.2:224.7.7.7:6667:6667 || exit 1
#(wait && wait && wait) || exit 1
#
echo
echo
echo
echo
echo

echo "IPV4 tests!"

echo "PING LOCALHOST"
./build/test/picoapp.elf --loop -a ping:127.0.0.1: || exit 1

echo "PING TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0:::) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a ping:10.40.0.8: || exit 1
killall picoapp.elf

echo "TCP TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0:::: -a tcpbench:r:6667::) &
time (./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a tcpbench:t:10.40.0.8:6667:: || exit 1)
killall picoapp.elf

echo "TCP TEST (with 2% packet loss on both directions)"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0::2:2: -a tcpbench:r:6667::) &
time (./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a tcpbench:t:10.40.0.8:6667:: || exit 1)
killall picoapp.elf

echo "TCP TEST (nagle)"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0::: -a tcpbench:r:6667:n:) &
time (./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a tcpbench:t:10.40.0.8:6667:n: || exit 1)
killall picoapp.elf

echo "UDP TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0::: -a udpecho:10.40.0.8:6667) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a udpclient:10.40.0.8:6667:6667:1400:100:10 || exit 1
wait || exit 1
wait

echo "NAT TCP TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.0.0::: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.0.0: -a natbox:10.50.0.10) &
sleep 2
(./build/test/picoapp.elf --vde pic0:/tmp/pic1.ctl:10.50.0.8:255.255.0.0::: -a tcpbench:r:6667) &
sleep 2
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10::: -a tcpbench:t:10.50.0.8:6667: || exit 1
killall picoapp.elf

echo "NAT UDP TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.0.0::: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.0.0::: -a natbox:10.50.0.10) &
(./build/test/picoapp.elf --vde pic0:/tmp/pic1.ctl:10.50.0.8:255.255.0.0::: -a udpecho:10.50.0.8:6667) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10::: -a udpclient:10.50.0.8:6667:6667:1400:100:10 || exit 1
#sometimes udpecho finishes before reaching wait %2
#wait %2

killall picoapp.elf

echo "MULTICAST TEST"
(./build/test/picoapp.elf --vde pic1:/tmp/pic0.ctl:10.40.0.3:255.255.0.0::: -a mcastreceive:10.40.0.3:224.7.7.7:6667:6667) &
(./build/test/picoapp.elf --vde pic2:/tmp/pic0.ctl:10.40.0.4:255.255.0.0::: -a mcastreceive:10.40.0.4:224.7.7.7:6667:6667) &
(./build/test/picoapp.elf --vde pic3:/tmp/pic0.ctl:10.40.0.5:255.255.0.0::: -a mcastreceive:10.40.0.5:224.7.7.7:6667:6667) &
sleep 2
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0::: -a mcastsend:10.40.0.2:224.7.7.7:6667:6667 || exit 1
(wait && wait && wait) || exit 1

killall picoapp.elf

echo "DHCP TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.1:255.255.0.0::: -a dhcpserver:pic0:10.40.0.1:255.255.255.0:64:128:) &
./build/test/picoapp.elf --barevde pic0:/tmp/pic0.ctl: -a dhcpclient:pic0 || exit 1
killall picoapp.elf

echo "DHCP DUAL TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0::: -a dhcpserver:pic0:10.40.0.2:255.255.255.0:64:128:) &
(./build/test/picoapp.elf --vde pic1:/tmp/pic1.ctl:10.50.0.2:255.255.0.0::: -a dhcpserver:pic1:10.50.0.2:255.255.255.0:64:128:) &
./build/test/picoapp.elf --barevde pic0:/tmp/pic0.ctl: --barevde pic1:/tmp/pic1.ctl: -a dhcpclient:pic0:pic1 || exit 1
killall picoapp.elf

#TO DO: the ping address 169.254.22.5 is hardcoded in the slaacv4 test. Nice to pass that by parameter
echo "SLAACV4 TEST"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:169.254.22.5:255.255.0.0:::) &
./build/test/picoapp.elf --barevde pic0:/tmp/pic0.ctl: -a slaacv4:pic0 || exit 1
killall picoapp.elf


./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0:10.40.0.1::: -a udpdnsclient:www.google.be:173.194.67.94:: &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0:10.40.0.1::: -a udpdnsclient:ipv6.google.be:doesntmatter:ipv6: &
./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.0.0:10.50.0.1::: -a sntp:ntp.nasa.gov
sleep 20
killall picoapp.elf


echo "MDNS TEST"
#retrieve a local mdns host name from the host
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.255.0:10.50.0.1: --app mdns:hostfoo.local:hostbar.local:) &
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.3:255.255.255.0:10.50.0.1: --app mdns:hostbar.local:hostfoo.local:) &
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.255.0:10.50.0.1: --app mdns:hostfoobar.local:nonexisting.local:) &
sleep 20
killall picoapp.elf




MAXMEM=`cat /tmp/pico-mem-report-* | sort -r -n |head -1`
echo
echo
echo
echo "MAX memory used: $MAXMEM"
rm -f /tmp/pico-mem-report-*

echo "SUCCESS!" && exit 0
