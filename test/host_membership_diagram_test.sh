#!/bin/bash

clear
if [ x$1 != x--nocolor ]; then
  RED='\e[1;31m'
  GREEN='\e[1;32m'
  BLUE='\e[1;34m'
  MAGENTA='\e[1;35m'
  NC='\e[0m'
fi

function checkOutput() {

  args=("$@")
  i=0
  while read outFromC
  do
    if [[ "$outFromC" = "DEBUG_IGMP2:"* ]];
    then
      dbg_info=${outFromC##*:}
      echo "> test: ${args[i]}"
      if [[ "$dbg_info" = "${args[i]}" ]];
      then
          echo -e "${BLUE}Correct${NC}"
          i=$[$i+1]
      else
          echo -e "${RED}Not Correct${NC}"
          return 1
      fi
    fi
    if [ "$i" -eq "$#" ]
    then
      return 0
    fi
  done
  echo ">> $i from the $# tests succeed."
  if [ "$i" -eq "$#" ];
  then
    return 0
  else
    return 1
  fi
}


function check() {

  returnval=$?
  echo "TEST:"
  if [ "$returnval" -eq 0 ];
  then
    echo -e "${GREEN}SUCCESS${NC}"
  else
    echo -e "${RED}FAILED${NC}" 
    exit 1  # To ensure that script exits with error upon failure.
  fi
}

echo ">>TEST: API call JOIN (DM) + Timer for JOIN (IM) + API call LEAVE (NM)"
../build/test/testigmp2.elf 1 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member" "STATE = Idle Member" "EVENT = Leave Group" "ACTION = SLIFS" "NEW STATE = Non-Member"
check

echo ">>TEST: API call JOIN (DM) + API call LEAVE (NM)"
../build/test/testigmp2.elf 2 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Leave Group" "ACTION = STSLIFS" "NEW STATE = Non-Member"
check

echo ">>TEST: API call JOIN (DM) + Timer for JOIN (IM) + Query Received (DM)"
../build/test/testigmp2.elf 3 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member" "STATE = Idle Member" "EVENT = Query Received" "ACTION = ST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Report Received" "ACTION = STCL" "NEW STATE = Idle Member"
check

echo ">>TEST: API call JOIN (DM) + Query Received (DM) + Timer Expired (IM)"
../build/test/testigmp2.elf 4 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Query Received" "ACTION = RTIMRTCT" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member"
check


exit 0
