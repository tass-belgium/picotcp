#!/bin/bash
function help(){
		echo 'Cmd line arguments can be:'
		echo 'start: to start the vde setup for the autotest.'
		echo 'stop: to cleanup the vde setup for the autotest.'
		exit
}

function start_vde(){
		vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub
		vde_switch -s /tmp/pic1.ctl -m 777 -M /tmp/pici.mgmt -d -hub
}

start_vde

