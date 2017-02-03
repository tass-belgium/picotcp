#!/bin/bash

TFTP_EXEC_DIR="$(pwd)/build/test"
TFTP_WORK_DIR="${TFTP_EXEC_DIR}/tmp"
TFTP_WORK_SUBDIR="${TFTP_WORK_DIR}/subdir"
TFTP_WORK_FILE="test.img"



function tftp_setup() {
    dd if=/dev/urandom bs=1000 count=10 of=${1}/$TFTP_WORK_FILE
}

function tftp_cleanup() {
	echo CLEANUP
	pwd;ls
	killall -wq picoapp.elf
	rm -rf $TFTP_WORK_DIR
	if [ $1 ]; then
		exit $1
	fi
}

if ! [ -x "$(command -v vde_switch)" ]; then
      echo 'VDE Switch is not installed.' >&2
fi

if [ ! -e test/vde_sock_start_user.sh ]; then
   echo "VDE SOCK START FILE NOT FOUND. NO VDE SETUP. EXITING"
   exit 1
else
   echo "VDE SOCK START SCRIPT STARTED."
   ./test/vde_sock_start_user.sh
fi

rm -f /tmp/pico-mem-report-*
sleep 2
ulimit -c unlimited
killall -wq picoapp.elf
killall -wq picoapp6.elf


echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ 6LoWPAN PING 1HOP   (1500B) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(build/test/picoapp6.elf -6 0,0,0) &
pids="$! "
sleep 1
(build/test/picoapp6.elf -6 1,2,1 -a noop) &
pids+="$! "
sleep 1
build/test/picoapp6.elf -6 2,1,0 -a ping,2aaa:abcd:0000:0000:0200:00aa:ab00:0001,1500,0,1 || exit 1
#TODO roll out this check for all "daemon" processes
for pid in $pids; do ps -o pid= -p $pid || exit 1; done # check whether daemon processes didn't die from e.g. ASAN
killall -w picoapp6.elf -s SIGQUIT

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ 6LoWPAN UDP 1HOP   (1400B) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#TODO are these "daemon" processes that need to be killed, or are they intended to halt on their own, giving a status code?
(build/test/picoapp6.elf -6 0,0,0) &
sleep 1
(build/test/picoapp6.elf -6 1,2,1 -a udpecho,::0,6667,) &
sleep 1
build/test/picoapp6.elf -6 2,1,0 -a udpclient,2aaa:abcd:0000:0000:0200:00aa:ab00:0001,6667,6667,1400,10,1, || exit 1
killall -w picoapp6.elf -s SIGQUIT

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ MULTICAST6 TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic1,/tmp/pic0.ctl,aaaa::2,ffff::, -a mcastreceive_ipv6,aaaa::2,ff00::e007:707,6667,6667,) &
(./build/test/picoapp6.elf --vde pic2,/tmp/pic0.ctl,aaaa::3,ffff::, -a mcastreceive_ipv6,aaaa::3,ff00::e007:707,6667,6667,) &
(./build/test/picoapp6.elf --vde pic3,/tmp/pic0.ctl,aaaa::4,ffff::, -a mcastreceive_ipv6,aaaa::4,ff00::e007:707,6667,6667,) &
sleep 2
 ./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::, -a  mcastsend_ipv6,aaaa::1,ff00::e007:707,6667,6667,|| exit 1
killall -w picoapp6.elf -s SIGQUIT

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ PING6 LOCALHOST TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
./build/test/picoapp6.elf --loop -a ping,::1,,,, || exit 1
killall -w picoapp6.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ PING6 TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,,,) &
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a ping,aaaa::1,,,, || exit 1
killall -w picoapp6.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ PING6 TEST (aborted in 4 seconds...) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,,,) &
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a ping,aaaa::1,64,4,,) &
sleep 7
killall -w picoapp6.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TCP6 TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,, -a tcpbench,r,6667,,) &
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a tcpbench,t,aaaa::1,6667,, || exit 1
killall -w picoapp6.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TCP6 TEST (with 2% packet loss on both directions) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,2,2, -a tcpbench,r,6667,,) &
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a tcpbench,t,aaaa::1,6667,, || exit 1
killall -w picoapp6.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TCP6 TEST (nagle) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,, -a tcpbench,r,6667,n,) &
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a tcpbench,t,aaaa::1,6667,n, || exit 1
killall -w picoapp6.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ UDP6 TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::1,ffff::,,, -a udpecho,::0,6667,) &
pids="$! "
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,aaaa::2,ffff::,,, -a udpclient,aaaa::1,6667,6667,1400,100,10, || exit 1
wait $pids || exit 1
killall -w picoapp6.elf

echo
echo
echo
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ IPV6 FWD TCP TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp6.elf --vde pic0,/tmp/pic1.ctl,2001:aabb::2,ffff:ffff::,2001:aabb::ff,, -a tcpbench,r,6667,,) &
(./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,2001:aaaa::ff,ffff:ffff::,,, --vde pic1,/tmp/pic1.ctl,2001:aabb::ff,ffff:ffff::,,, -a noop,) &
./build/test/picoapp6.elf --vde pic0,/tmp/pic0.ctl,2001:aaaa::1,ffff:ffff::,2001:aaaa::ff,, -a tcpbench,t,2001:aabb::2,6667,, || exit 1
sleep 2
killall -w picoapp6.elf


echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ MULTICAST TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic1:/tmp/pic0.ctl:10.40.0.3:255.255.0.0: -a mcastreceive:10.40.0.3:224.7.7.7:6667:6667:) &
(./build/test/picoapp.elf --vde pic2:/tmp/pic0.ctl:10.40.0.4:255.255.0.0: -a mcastreceive:10.40.0.4:224.7.7.7:6667:6667:) &
(./build/test/picoapp.elf --vde pic3:/tmp/pic0.ctl:10.40.0.5:255.255.0.0: -a mcastreceive:10.40.0.5:224.7.7.7:6667:6667:) &
sleep 2
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0: -a mcastsend:10.40.0.2:224.7.7.7:6667:6667: || exit 1
killall -w picoapp.elf

echo
echo
echo
echo
echo

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ IPV4 tests! ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ PING LOCALHOST TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
./build/test/picoapp.elf --loop -a ping:127.0.0.1:::: || exit 1

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ PING TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0:::) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a ping:10.40.0.8:::: || exit 1
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ PING TEST -- Aborted in 4 seconds ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0:::) &
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a ping:10.40.0.8:64:4::) &
sleep 7
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TCP TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0:::: -a tcpbench:r:6667::) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a tcpbench:t:10.40.0.8:6667:: || exit 1
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TCP TEST (with global route) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0:::: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.0.0:10.50.0.1: -a tcpbench:r:6667::) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a tcpbench:t:10.40.0.8:6667:: || exit 1
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TCP TEST (with 2% packet loss on both directions) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0::2:2: -a tcpbench:r:6667::) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a tcpbench:t:10.40.0.8:6667:: || exit 1
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TCP TEST (nagle) ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0::: -a tcpbench:r:6667:n:) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a tcpbench:t:10.40.0.8:6667:n: || exit 1
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ UDP TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0::: -a udpecho:10.40.0.8:6667:) &
pids="$! "
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a udpclient:10.40.0.8:6667:6667:1400:100:10: || exit 1
wait $pids || exit 1

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ UDP TEST with fragmentation ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.8:255.255.0.0::: -a udpecho:10.40.0.8:6667:) &
pids="$! "
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0::: -a udpclient:10.40.0.8:6667:6667:4500:100:10: || exit 1
wait $pids || exit 1

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ NAT TCP TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.0.0::: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.0.0: -a natbox:10.50.0.10) &
sleep 2
(./build/test/picoapp.elf --vde pic0:/tmp/pic1.ctl:10.50.0.8:255.255.0.0::: -a tcpbench:r:6667:) &
sleep 2
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10::: -a tcpbench:t:10.50.0.8:6667: || exit 1
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ NAT UDP TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.0.0::: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.0.0::: -a natbox:10.50.0.10) &
(./build/test/picoapp.elf --vde pic0:/tmp/pic1.ctl:10.50.0.8:255.255.0.0::: -a udpecho:10.50.0.8:6667:) &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10::: -a udpclient:10.50.0.8:6667:6667:1400:100:10: || exit 1
#sometimes udpecho finishes before reaching wait %2
#wait %2
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ MULTICAST TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic1:/tmp/pic0.ctl:10.40.0.3:255.255.0.0::: -a mcastreceive:10.40.0.3:224.7.7.7:6667:6667:) &
(./build/test/picoapp.elf --vde pic2:/tmp/pic0.ctl:10.40.0.4:255.255.0.0::: -a mcastreceive:10.40.0.4:224.7.7.7:6667:6667:) &
(./build/test/picoapp.elf --vde pic3:/tmp/pic0.ctl:10.40.0.5:255.255.0.0::: -a mcastreceive:10.40.0.5:224.7.7.7:6667:6667:) &
sleep 2
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0::: -a mcastsend:10.40.0.2:224.7.7.7:6667:6667: || exit 1
killall -w picoapp.elf

killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ DHCP TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.1:255.255.0.0::: -a dhcpserver:pic0:10.40.0.1:255.255.255.0:64:128:) &
./build/test/picoapp.elf --barevde pic0:/tmp/pic0.ctl: -a dhcpclient:pic0 || exit 1
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ DHCP DUAL TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0::: -a dhcpserver:pic0:10.40.0.2:255.255.255.0:64:128:) &
(./build/test/picoapp.elf --vde pic1:/tmp/pic1.ctl:10.50.0.2:255.255.0.0::: -a dhcpserver:pic1:10.50.0.2:255.255.255.0:64:128:) &
./build/test/picoapp.elf --barevde pic0:/tmp/pic0.ctl: --barevde pic1:/tmp/pic1.ctl: -a dhcpclient:pic0:pic1: || exit 1
killall -w picoapp.elf

#TO DO: the ping address 169.254.22.5 is hardcoded in the slaacv4 test. Nice to pass that by parameter
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ SLAACV4 TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:169.254.22.5:255.255.0.0:::) &
./build/test/picoapp.elf --barevde pic0:/tmp/pic0.ctl: -a slaacv4:pic0 || exit 1
killall -w picoapp.elf


./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0:10.40.0.1::: -a udpdnsclient:www.google.be:173.194.67.94:: &
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0:10.40.0.1::: -a udpdnsclient:ipv6.google.be:doesntmatter:ipv6: &
./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.0.0:10.50.0.1::: -a sntp:0.europe.pool.ntp.org &
sleep 20
killall -w picoapp.elf


echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ MDNS TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#retrieve a local mdns host name from the host
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.255.0:10.50.0.1: --app mdns:hostfoo.local:hostbar.local:) &
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.3:255.255.255.0:10.50.0.1: --app mdns:hostbar.local:hostfoo.local:) &
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.255.0:10.50.0.1: --app mdns:hostfoobar.local:nonexisting.local:) &
sleep 10
killall -w picoapp.elf

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ DNS_SD TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#register a service
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.255.0:10.50.0.1: --app dns_sd:host.local:WebServer) &
(./build/test/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.3:255.255.255.0:10.50.0.1: --app dns_sd:host.local:WebServer) &
sleep 30
killall -w picoapp.elf

sleep 1
sync


# TFTP TEST BEGINS...

if [ ! -d $TFTP_WORK_DIR ]; then
        mkdir $TFTP_WORK_DIR || exit 1
fi
if [ ! -d ${TFTP_WORK_SUBDIR}/server ]; then
        mkdir $TFTP_WORK_SUBDIR || exit 1
fi

pushd $TFTP_WORK_DIR

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TFTP GET TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
tftp_setup $TFTP_WORK_DIR
(${TFTP_EXEC_DIR}/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.255.0:10.50.0.1: --app tftp:S:) &
cd $TFTP_WORK_SUBDIR
sleep 2
${TFTP_EXEC_DIR}/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.3:255.255.255.0:10.50.0.1: --app tftp:R:${TFTP_WORK_FILE}:10.50.0.2: || tftp_cleanup 1
sleep 3
killall -w picoapp.elf

sleep 1

rm $TFTP_WORK_FILE

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~ TFTP PUT TEST ~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
(${TFTP_EXEC_DIR}/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.2:255.255.255.0:10.50.0.1: --app tftp:S:) &
cd $TFTP_WORK_DIR
tftp_setup $TFTP_WORK_DIR
sleep 2
${TFTP_EXEC_DIR}/picoapp.elf  --vde pic0:/tmp/pic0.ctl:10.50.0.3:255.255.255.0:10.50.0.1: --app tftp:T:${TFTP_WORK_FILE}:10.50.0.2: || tftp_cleanup 1
sleep 3

tftp_cleanup
popd
# TFTP TEST ENDS.

MAXMEM=`cat /tmp/pico-mem-report-* | sort -r -n |head -1`
echo
echo
echo
echo "MAX memory used: $MAXMEM"
rm -f /tmp/pico-mem-report-*

./test/vde_sock_start_user.sh stop
echo "SUCCESS!"
