/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "stdint.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_zmq.h"
#include "pico_zmtp.h"

struct zmq_zmtp_list_item {
    struct zmtp_socket* sock;
    struct zmq_zmtp_socket_item* next_item;
};

struct zmq_socket {
    struct zmtp_socket* sock;
    struct zmq_zmtp_list_item* zmtp_socket_list;
};


static void zmq_zmtp_add(struct zmq_socket* z, struct zmtp_socket* zc)
{

}

static void zmq_zmtp_socket_del(struct zmtp_socket* zc)
{

}

int8_t zmq_bind(struct zmq_socket* s, char* address, uint16_t port)
{
    return 0;
}

int8_t zmq_connect(struct zmq_socket * z, char* address, uint16_t port)
{
    return 0;
}

int8_t zmq_send(struct zmq_socket* z, char* txt, int len)
{
    return 0;
}

int8_t zmq_recv(struct zmq_socket* z, char* txt)
{
    return 0;
}

void zmq_close(struct zmq_socket* z)
{

}
