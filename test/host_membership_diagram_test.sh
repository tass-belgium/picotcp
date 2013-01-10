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


echo "To Test: STATE = Delayed Member | EVENT = Leave Group | ACTION = STSLIFS | NEW STATE = Non-Member"
../build/test/testigmp2.elf 1 | checkOutput "STATE = Delayed Member" "EVENT = Leave Group" "ACTION = STSLIFS" "NEW STATE = Non-Member"
check

echo "---------------------------------------"
echo "To Test: STATE = Delayed Member | EVENT = Query Received | ACTION = RTIMRTCT | NEW STATE = Delayed Member"
../build/test/testigmp2.elf 2 | checkOutput "STATE = Delayed Member" "EVENT = Query Received" "ACTION = RTIMRTCT" "NEW STATE = Delayed Member"
test

echo "---------------------------------------"
echo "To Test: STATE = Delayed Member | EVENT = Report Received | ACTION = STCF | NEW STATE = Idle Member"
../build/test/testigmp2.elf 3 | checkOutput 'STATE = Delayed Member' "EVENT = Report Received" "ACTION = STCF" "NEW STATE = Idle Member"
test

echo "---------------------------------------"
echo "To Test: STATE = Delayed Member | EVENT = Timer Expired | ACTION = SRSF | NEW STATE = Idle Member"
../build/test/testigmp2.elf 4 | checkOutput 'STATE = Delayed Member' "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member"
test

echo "---------------------------------------"
echo "To Test: STATE = Non-Member | EVENT = Join Group | ACTION = SRSFST | NEW STATE = Delayed Member"
../build/test/testigmp2.elf 5 | checkOutput 'STATE = Non-Member' "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delayed Member"
test

echo "---------------------------------------"
echo "To Test: STATE = Idle Member | EVENT = Leave Group | ACTION = SLIFS | NEW STATE = Non-Member"
../build/test/testigmp2.elf 6 | checkOutput 'STATE = Idle Member' "EVENT = Leave Group" "ACTION = SLIFS" "NEW STATE = Non-Member"
test

echo "---------------------------------------"
echo "To Test: STATE = Idle Member | EVENT = Query Received | ACTION = ST | NEW STATE = Delayed Member"
../build/test/testigmp2.elf 7 | checkOutput 'STATE = Idle Member' "EVENT = Query Received" "ACTION = ST" "NEW STATE = Delayed Member"
test


exit 0
