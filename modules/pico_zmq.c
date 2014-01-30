/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera, Stijn Haers, Mathias Devos, 
    Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_zmq.h"
#include "pico_zmtp.h"

struct zmq_socket {
    struct zmtp_socket *sock;
    struct zmtp_socket *subs;
};


static void zmq_zmtp_add(struct zmq_socket * z, struct zmtp_socket *zc)
{

}

static void zmq_zmtp_socket_del(struct zmtp_socket *zc)
{

}

int zmq_socket_bind(struct zmq_socket* s, char *address, uint16_t port)
{
    return 0;
}

int zmq_socket_connect(struct zmq_socket * z, char *address, uint16_t port)
{
    return 0;
}

int zmq_socket_send(struct zmq_socket * z, char *txt, int len)
{
    return ret;
}

int zmq_socket_recv(struct zmq_socket * z, char *txt)
{
    return 0;
}

void zmq_socket_close(struct zmq_socket * z)
{

}


