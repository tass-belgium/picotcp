#!/bin/bash

#ACTION STSLIFS:  stop timer, send leave if flag set
#ACTION SRSFST:   send report, set flag, start timer
#ACTION SLIFS:    send leave if flag set
#ACTION ST:       start timer
#ACTION STCL:     stop timer, clear flag
#ACTION SRSF:     send report, set flag
#ACTION RTIMRTCT: reset timer if Max resp time < current time

clear
if [ x$1 != x--nocolor ]; then
  RED='\e[1;31m'
  GREEN='\e[1;32m'
  BLUE='\e[1;34m'
  MAGENTA='\e[1;35m'
  NC='\e[0m'
fi


function checkOutput() {

  for i in "$@" 
  do
    read outFromC
      echo "> $i"
      if [ "$outFromC" = "$i" ];
      then
          echo -e "${BLUE}Correct${NC}"
      else
          echo -e "${RED}Not Correct${NC}"
          return 1
      fi
  done
  return 0
}


function check() {

  returnval=$?
  echo "Test:"
  if [ "$returnval" -eq 0 ];
  then
    echo -e "${GREEN}SUCCESS${NC}"       
  else
    echo -e "${RED}FAILED${NC}" 
    exit 1  # To ensure that script exits with error upon failure.
  fi
}

#echo "To Test: Functionality of analyse packet : PICO_IGMP_TYPE_MEM_QUERY "
#../build/test/testigmp2.elf 10 | checkOutput "QUERY REQUEST"
#check

#echo "To Test: Functionality of analyse packet : PICO_IGMP_TYPE_V1_MEM_REPORT "
#../build/test/testigmp2.elf 11 | checkOutput "REPORT = VERSION 1"
#check

#echo "To Test: Functionality of analyse packet : PICO_IGMP_TYPE_V2_MEM_REPORT "
#../build/test/testigmp2.elf 12 | checkOutput "REPORT = VERSION 2"
#check

#echo "To Test: Functionality of analyse packet : PICO_IGMP_TYPE_LEAVE_GROUP "
#../build/test/testigmp2.elf 13 | checkOutput "Error unkown TYPE 23"
#check

#echo "To Test: IGMP2 CHECKSUM "
#../build/test/testigmp2.elf 14 | checkOutput "CHECKSUM = 04FA" "CHECKSUM = EAF0"
#check

echo "---------------------------------------"
echo "To Test: STATE = Delayed Member | EVENT = Query Received | ACTION = RTIMRTCT | NEW STATE = Delayed Member"
../build/test/testigmp2.elf 2 | checkOutput "STATE = Delayed Member" "EVENT = Query Received" "ACTION = RTIMRTCT" "NEW STATE = Delayed Member"
check

echo "---------------------------------------"
echo "To Test: STATE = Delayed Member | EVENT = Report Received | ACTION = STCF | NEW STATE = Idle Member"
../build/test/testigmp2.elf 3 | checkOutput 'STATE = Delayed Member' "EVENT = Report Received" "ACTION = STCF" "NEW STATE = Idle Member"
check

echo "---------------------------------------"
echo "To Test: STATE = Delayed Member | EVENT = Timer Expired | ACTION = SRSF | NEW STATE = Idle Member"
../build/test/testigmp2.elf 4 | checkOutput 'STATE = Delayed Member' "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member"
check

echo "---------------------------------------"
echo "To Test: STATE = Non-Member | EVENT = Join Group | ACTION = SRSFST | NEW STATE = Delayed Member"
../build/test/testigmp2.elf 5 | checkOutput 'STATE = Non-Member' "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delayed Member"
check

echo "---------------------------------------"
echo "To Test: STATE = Idle Member | EVENT = Leave Group | ACTION = SLIFS | NEW STATE = Non-Member"
../build/test/testigmp2.elf 6 | checkOutput 'STATE = Idle Member' "EVENT = Leave Group" "ACTION = SLIFS" "NEW STATE = Non-Member"
check

echo "---------------------------------------"
echo "To Test: STATE = Idle Member | EVENT = Query Received | ACTION = ST | NEW STATE = Delayed Member"
../build/test/testigmp2.elf 7 | checkOutput 'STATE = Idle Member' "EVENT = Query Received" "ACTION = ST" "NEW STATE = Delayed Member"
check


exit 0
