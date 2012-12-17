#!/bin/bash
clear
RED='\e[1;31m'
GREEN='\e[1;32m'
BLUE='\e[1;34m'
NC='\e[0m'
MAGENTA='\e[1;35m'
echo -e "${MAGENTA}Exec 'make' & 'make tst'${NC}"
make > ./test/logfile.log
make tst > ./test/logfile2.log
echo -e "${MAGENTA}Startup vde script'${NC}"
#sh ./test/vde_sock_start.sh

echo -e "${MAGENTA}VDE CREATE${NC}"
sudo ./build/test/testserver 1 > ./logfile.log
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi

echo -e "${MAGENTA}OPEN UDP SOCKET${NC}"
sudo ./build/test/testserver 2 > ./logfile.log
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi


echo -e "${MAGENTA}OPEN TCP SOCKET${NC}"
sudo ./build/test/testserver 3 > ./logfile.log
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi

echo -e "${MAGENTA}BIND UDP SOCKET${NC}"
sudo ./build/test/testserver 4 > ./logfile.log
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi

echo -e "${MAGENTA}BIND TCP SOCKET${NC}"
sudo ./build/test/testserver 5 > ./logfile.log
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi

#echo -e "${MAGENTA}UDP LISTEN SOCKET${NC}"
#sudo ./build/test/testserver 6 > ./logfile.log
#if [ $? -eq 0 ];
#then
#        echo -e "${GREEN}SUCCESS${NC}"
#else
#        echo -e "${RED}FAILED${NC}"
#fi

echo -e "${MAGENTA}TCP LISTEN SOCKET${NC}"
sudo ./build/test/testserver 7 > ./logfile.log
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi

echo -e "${MAGENTA}SEND and RECEIVE SOCKET TCP ${NC}"
sudo ./build/test/testserver 8 > ./logfile.log &
echo -e "${BLUE}Start started server ${NC}"
SERVER=$!
#sudo ./build/test/testserver 8 &
sleep 3
echo -e "${BLUE}Start client ${NC}"
sudo ./build/test/testclient 9 > ./logfile.log 
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi

echo -e "${MAGENTA}Close socket TCP ${NC}"
sudo ./build/test/testserver 8 > ./logfile.log &
SERVER=$!
echo -e "${BLUE}Started server ${NC}"
sleep 3
echo -e "${BLUE}Start client ${NC}"
sudo ./build/test/testclient 9 > ./logfile.log
if [ $? -eq 0 ];
then
        echo -e "${GREEN}SUCCESS${NC}"
else
        echo -e "${RED}FAILED${NC}"
fi

