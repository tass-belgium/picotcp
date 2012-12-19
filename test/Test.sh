#!/bin/bash
clear
if [ x$1 != x--nocolor ]; then
  RED='\e[1;31m'
  GREEN='\e[1;32m'
  BLUE='\e[1;34m'
  MAGENTA='\e[1;35m'
  NC='\e[0m'
fi

rm -f logfile.log

function unit() {
  echo -e $1
  shift
  $@ >>./logfile.log
  retval=$?
  if [ $retval -eq 0 ];
  then
          echo -e "${GREEN}SUCCESS${NC}"
  else
          echo -e "${RED}FAILED${NC}"
          exit 1  # To ensure that script exits with error upon failure.
  fi
  return $retval
}


#echo -e "${MAGENTA}Exec 'make' & 'make tst'${NC}"
#make > ./test/logfile.log
#make tst > ./test/logfile2.log

echo -e "${MAGENTA}Startup vde script'${NC}"
sh ./test/vde_sock_start_user.sh

unit "${MAGENTA}VDE CREATE${NC}" ./build/test/testserver 1
unit "${MAGENTA}OPEN UDP ${NC}" ./build/test/testserver 2
unit "${MAGENTA}OPEN TCP ${NC}" ./build/test/testserver 3
unit "${MAGENTA}BIND UDP ${NC}" ./build/test/testserver 4
unit "${MAGENTA}BIND TCP ${NC}" ./build/test/testserver 5
unit "${MAGENTA}LISTEN TCP ${NC}" ./build/test/testserver 7

# Starting TCP server
#./build/test/testserver 8 >> ./logfile.log &
#SERVER=$!
#echo -e "${BLUE}Started server (PID=$SERVER) ${NC}"
#sleep 3
#unit "${MAGENTA}SEND and RECEIVE TCP ${NC}" ./build/test/testclient 9

echo

./build/test/picoapp --vde vde0:/tmp/pic0.ctl:10.40.0.5:255.255.255.0: --app tcpecho:5556 &
sleep 1
./build/test/picoapp --vde vde0:/tmp/pic0.ctl:10.40.0.6:255.255.255.0: --app tcpclient:10.40.0.5:5556 || exit 1

exit 0 # I am the last line.
