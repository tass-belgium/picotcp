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

#define dbg(x,args...) printf("[%s:%s:%i] "x" \n",__FILE__,__func__,__LINE__ ,##args )


static void zmq_zmtp_add(struct zmq_socket* z, struct zmtp_socket* zc)
{

}

static void zmq_zmtp_socket_del(struct zmtp_socket* zc)
{

}

void cb_zmtp_sockets(uint16_t ev, struct zmtp_socket* s) 
{
    dbg("In cb_zmtp_sockets!"); 
    //TODO: process events!!
}

struct zmq_socket* zmq_create_socket(uint16_t type)
{
    struct zmq_socket* sock;

    sock = pico_zalloc(sizeof(struct zmq_socket));

    if(!sock)
        return NULL;

    switch(type)
    {
        case(ZMQ_TYPE_REQ): 
                        sock->sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMQ_TYPE_REQ, &cb_zmtp_sockets);
                        break;
        default:
                pico_free(sock);
                return NULL;
    }
    
    if(!sock->sock) {
        pico_free(sock);
        return NULL;
    }

    return sock; 
}

int8_t zmq_bind(struct zmq_socket* s, char* address, uint16_t port)
{
    return 0;
}

int8_t zmq_connect(struct zmq_socket* z, const char* endpoint)
{
    struct pico_ip4 dst = { 0 };

    //TODO: parse endpoint!!!

    pico_string_to_ipv4("127.0.0.1", &dst.addr);
    return zmtp_socket_connect(z->sock, &dst.addr, short_be(5555));
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
