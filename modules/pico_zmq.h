/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#ifndef __PICO_ZMQ_H
#define __PICO_ZMQ_H

#include <stdint.h>
#include <stdio.h>
#include "pico_zmtp.h"

struct zmq_zmtp_list_item {
    struct zmtp_socket* sock;
    struct zmq_zmtp_socket_item* next_item;
};

struct zmq_socket {
    struct zmtp_socket* sock;
    struct zmq_zmtp_list_item* zmtp_socket_list;
};

struct zmq_socket* zmq_create_socket(enum zmq_socket_t type);
int8_t zmq_setsockopt (struct zmq_socket* z, int option_name, const void* option_value, size_t option_len);
int8_t zmq_getsockopt (struct zmq_socket* z, int option_name, void* option_value, size_t* option_len);
int8_t zmq_bind(struct zmq_socket* s, char* address, uint16_t port);
int8_t zmq_connect(struct zmq_socket* z, const char* endpoint);
int8_t zmq_send(struct zmq_socket* z, char* txt, int len);
int8_t zmq_recv(struct zmq_socket* z, char* txt);
void zmq_close(struct zmq_socket* z);

#endif
