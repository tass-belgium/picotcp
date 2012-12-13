#!/bin/bash
clear
RED='\e[1;31m'
GREEN='\e[1;32m'
NC='\e[0m'
MAGENTA='\e[1;35m'
echo -e "${MAGENTA}Exec 'make' & 'make tst'${NC}"
make 
make tst
echo -e "${MAGENTA}Kill Wireshark'${NC}"
killall wireshark
echo -e "${MAGENTA}Startup vde script'${NC}"
#sh ./test/vde_sock_start.sh
echo -e "${MAGENTA}restart Wireshark'${NC}"
wireshark &

echo -e "${MAGENTA}starting echo server...${NC}"
sudo ./build/test/testserver
if [ $? -eq 10 ];
then
        echo -e "${GREEN}TEST SUCCESS${NC}"
else
        echo -e "${RED}TEST FAILED${NC}"
fi
