#!/bin/bash
function help(){
		echo 'Cmd line arguments can be:'
		echo 'start: to start the vde setup for the autotest.'
		echo 'stop: to cleanup the vde setup for the autotest.'
		exit
}

function check_if(){
   t1=$(ifconfig | grep -o vde0)
   t2="vde0"
   if [ "$t1" != "$t2" ]; then
       return 1
   fi
   return 0
   
}

function start_vde(){
		sudo vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub -t vde0
		sudo vde_switch -s /tmp/pic1.ctl -m 777 -M /tmp/pici.mgmt -d -hub
		sudo /sbin/ifconfig vde0 10.50.0.1 netmask 255.255.0.0 
}

function stop_vde(){
		echo "Stopping VDE0."
		sudo /sbin/ifconfig vde0 down
		sudo vdecmd -s /tmp/pico.mgmt shutdown
		sudo vdecmd -s /tmp/pici.mgmt shutdown
}

case $1 in
start)
		echo 'Starting VDE setup'
		if_result=$(check_if)
		if [[ $if_result -eq 1 ]]
		then
		   stop_vde
		fi
		start_vde
		;;
stop)
		echo 'Stopping VDE setup'
		stop_vde
		;;
--help)
		help
		;;
*)
		echo 'Wrong syntax!'
		help
		;;
esac
