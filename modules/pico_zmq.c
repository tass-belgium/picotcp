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
#include "pico_config.h"

#include "pico_zmq.h"
#include "pico_zmtp.h"

#define dbg(x,args...) printf("[%s:%s:%i] "x" \n",__FILE__,__func__,__LINE__ ,##args )

/*
static void zmq_zmtp_add(void* socket, struct zmtp_socket* z)
{

}

static void zmq_zmtp_socket_del(struct zmtp_socket* z)
{

}
*/

static void cb_zmtp_sockets(uint16_t ev, struct zmtp_socket* s) 
{
    dbg("In cb_zmtp_sockets!"); 
    //TODO: process events!!
}

void* zmq_socket(void* context, int type)
{
    struct zmq_socket_base* sock = NULL;

    switch(type)
    {
        case(ZMTP_TYPE_REQ): 
            sock = pico_zalloc(sizeof(struct zmq_socket_req));
            break;
        case(ZMTP_TYPE_REP):
            break; 
        case(ZMTP_TYPE_PUB):
            break;
        default:
            pico_free(sock);
            return NULL;
    }
    
    if(!sock) 
    {
        //pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    sock->type = type;
        
    //sock->sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_zmtp_sockets);
    
    if(!sock->sock) {
        pico_free(sock);
        return NULL;
    }

    return sock; 
}

int zmq_bind(void* socket, char* address, uint16_t port)
{
    return 0;
}

int zmq_connect(void* socket, const char* endpoint)
{
    struct pico_ip4 dst = { 0 };

    //TODO: parse endpoint!!!

    //pico_string_to_ipv4("127.0.0.1", &dst.addr);
    //return zmtp_socket_connect(z->sock, &dst.addr, short_be(5555));
    return 0;
}

int zmq_send(void* socket, char* txt, int len)
{
    return 0;
}

int zmq_recv(void* socket, char* txt)
{
    return 0;
}

void zmq_close(void* socket)
{

}

/* cyclic states
    if(s->state == ST_OPEN && ev & PICO_SOCK_EV_CONN)
    {
        s->state = ST_CONNECTED;
        zmtp_send_greeting(zmtp_s);
    }
    else if(s->state == ST_CONNECTED && ev & PICO_SOCK_EV_RD)
    {
        //read greeting
    }
    return;
*/
