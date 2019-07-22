#!/bin/bash

gcc -o serialize_tcp_sock -I build/include serialize_tcp_sock.c ; \
./serialize_tcp_sock
./serialize_tcp_sock restore
