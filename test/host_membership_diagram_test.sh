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
          i=$i+1
      else
          echo -e "${RED}Not Correct${NC}"
          return 1
      fi
    fi
  done
  return 0
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

#echo "TEST: API call JOIN + Timer for JOIN (IM)"
#../build/test/testigmp2.elf 0 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member"
#check

echo "TEST: API call JOIN + Timer for JOIN + API call LEAVE (NM)"
../build/test/testigmp2.elf 1 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member" "STATE = Idle Member" "EVENT = Leave Group" "ACTION = SLIFS" "NEW STATE = Non-Member"
check

echo "TEST: API call JOIN + API call LEAVE (NM)"
../build/test/testigmp2.elf 2 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Leave Group" "ACTION = STSLIFS" "NEW STATE = Non-Member"
check

echo "TEST: API call JOIN + Timer for JOIN (IM) + Query Received + Query Received + Timer Expired (IM)+ Leave Group (NM)"
../build/test/testigmp2.elf 3 | checkOutput "STATE = Non-Member" "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member" "STATE = Idle Member" "EVENT = Query Received" "ACTION = ST" "NEW STATE = Delaying Member" "STATE = Delaying Member" "EVENT = Query Received" "ACTION = RTIMRTCT" "NEW STATE = Delaying Member"
check


#echo "ACTION1---------------------------------------"
#echo "To Test: STATE = Delaying Member | EVENT = Leave Group | ACTION = STSLIFS | NEW STATE = Non-Member"
#../build/test/testigmp2.elf 1 | checkOutput "STATE = Delaying Member" "EVENT = Leave Group" "ACTION = STSLIFS" "NEW STATE = Non-Member"
#check

#echo "ACTION2---------------------------------------"
#echo "To Test: STATE = Non-Member | EVENT = Join Group | ACTION = SRSFST | NEW STATE = Delaying Member"
#../build/test/testigmp2.elf 2 | checkOutput 'STATE = Non-Member' "EVENT = Join Group" "ACTION = SRSFST" "NEW STATE = Delaying Member"
#check

#echo "ACTION3---------------------------------------"
#echo "To Test: STATE = Idle Member | EVENT = Leave Group | ACTION = SLIFS | NEW STATE = Non-Member"
#../build/test/testigmp2.elf 3 | checkOutput 'STATE = Idle Member' "EVENT = Leave Group" "ACTION = SLIFS" "NEW STATE = Non-Member"
#check

#echo "ACTION4---------------------------------------"
#echo "To Test: STATE = Idle Member | EVENT = Query Received | ACTION = ST | NEW STATE = Delaying Member"
#../build/test/testigmp2.elf 4 | checkOutput 'STATE = Idle Member' "EVENT = Query Received" "ACTION = ST" "NEW STATE = Delaying Member"
#check

#echo "ACTION5---------------------------------------"
#echo "To Test: STATE = Delaying Member | EVENT = Report Received | ACTION = STCF | NEW STATE = Idle Member"
#../build/test/testigmp2.elf 5 | checkOutput 'STATE = Delaying Member' "EVENT = Report Received" "ACTION = STCF" "NEW STATE = Idle Member"
#check

#echo "ACTION6---------------------------------------"
#echo "To Test: STATE = Delaying Member | EVENT = Timer Expired | ACTION = SRSF | NEW STATE = Idle Member"
#../build/test/testigmp2.elf 6 | checkOutput 'STATE = Delaying Member' "EVENT = Timer Expired" "ACTION = SRSF" "NEW STATE = Idle Member"
#check

#echo "ACTION7---------------------------------------"
#echo "To Test: STATE = Delaying Member | EVENT = Query Received | ACTION = RTIMRTCT | NEW STATE = Delaying Member"
#../build/test/testigmp2.elf 7 | checkOutput "STATE = Delaying Member" "EVENT = Query Received" "ACTION = RTIMRTCT" "NEW STATE = Delaying Member"
#check






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


exit 0
