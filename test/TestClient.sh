#!/bin/bash
clear
RED='\e[1;31m'
GREEN='\e[1;32m'
NC='\e[0m'
MAGENTA='\e[1;35m'

echo -e "${MAGENTA}starting send client ...${NC}"
sudo ./build/test/testclient
if [ $? -eq 10 ];
then
        echo -e "${GREEN}TEST SUCCESS${NC}"
else
        echo -e "${RED}TEST FAILED${NC}"
fi
