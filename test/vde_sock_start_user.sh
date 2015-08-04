#!/bin/bash
function help(){
		echo 'Cmd line arguments can be:'
		echo 'start: to start the vde setup for the autotest.'
		echo 'stop: to cleanup the vde setup for the autotest.'
		exit
}

function start_vde(){
		sudo vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub -t vde0
		sudo vde_switch -s /tmp/pic1.ctl -m 777 -M /tmp/pici.mgmt -d -hub
		sudo /sbin/ifconfig vde0 10.50.0.1 netmask 255.255.0.0 
}

function stop_vde(){
		sudo /sbin/ifconfig vde0 down
		sudo vdecmd -s /tmp/pico.mgmt shutdown
		sudo vdecmd -s /tmp/pici.mgmt shutdown
		sudo rm -f /tmp/pic0.ctl
		sudo rm -f /tmp/pic1.ctl
}

case $1 in
start)
		echo 'Starting VDE setup'
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



