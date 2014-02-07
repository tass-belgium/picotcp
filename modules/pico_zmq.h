/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#ifndef __PICO_ZMQ_H
#define __PICO_ZMQ_H

#include <stdint.h>
#include <stdio.h>

struct zmq_zmtp_list_item {
    struct zmtp_socket* sock;
    struct zmq_zmtp_socket_item* next_item;
};

struct zmq_socket_base
{
    uint8_t type;
    struct zmtp_socket* sock;
};

struct zmq_socket_req {
    struct zmq_socket_base base;
    struct zmtp_socket* sock;
};

void* zmq_socket(void* context, int type);
int zmq_setsockopt (void* socket, int option_name, const void* option_value, size_t option_len);
int zmq_getsockopt (void* socket, int option_name, void* option_value, size_t* option_len);
int zmq_bind(void* s, char* address, uint16_t port);
int zmq_connect(void* socket, const char* endpoint);
int zmq_send(void* socket, char* txt, int len);
int zmq_recv(void* socket, char* txt);
void zmq_close(void* socket);

#endif
