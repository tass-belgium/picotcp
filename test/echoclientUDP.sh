#!/bin/bash

# check if user is root
if [[ $EUID -ne 0 ]] 
then
   echo "This script must be run as root" 
   exit 1
fi

# function to execute on ^C
control_c()
{
	PS=$(ps -ef | grep echoUDP | awk 'BEGIN {min = 100000} {if ($2<min) min=$2} END {print min}')	
	if [ $PS -ne 0 ]
	then
		echo -en "\n\nKilled background process echoUDP (pid=$PS)\n\n"
		kill $PS
	else
		echo -en "\n\nWARNING: background process echoUDP is NOT killed\n\n"
	fi

  exit $?
}

# trap SIGINT and execute control_c 
trap control_c SIGINT

# execute unittest in background
if [ ! -f ./../build/test/echoUDP ]
then
	echo "Can not find file ./../build/test/echoUDP. Make sure to run the script in his directory."
	exit 1
else
	./../build/test/echoUDP &
fi

# wait for unittest main loop
sleep 1
echo -en "\nwaiting "
for i in {1..8}
do
	sleep 1
	echo -n "."
done

# config tup0
if [ ! -f ./tun.sh ]
then
	echo "Can not find file ./tun.sh"
	exit 1
else
	./tun.sh
fi

# get the configured IP in tun.sh
IP=$(cat tun.sh | awk '{if (NF > 0 && NR > 1) print $5}')

# send UDP "hello" packet every 2 seconds
while :
do
	echo -en "\n\n==============================="
	echo -en "\nTransmitting UDP \"hello\" packet\n"
	echo -en "===============================\n\n"
	echo -en "hello" | nc -u -w2 $IP -p 5555 5555
done
