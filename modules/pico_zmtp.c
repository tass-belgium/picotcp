/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "pico_zmtp.h"
#include "pico_socket.h"
#include "pico_zmq.h"



static void zmtp_tcp_cb(uint16_t ev, struct pico_socket *s)
{
    return;
}

int8_t zmtp_bind(struct zmtp_socket* s, void* local_addr, uint16_t* port)
{
    return 0;
}

int8_t zmtp_connect(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port);
{
    return 0;
}

int8_t zmtp_send(struct zmtp_socket* s, struct zmq_msg** msg, uint16_t len);
{
    return 0;
}

int8_t zmtp_socket_close(struct zmtp_socket *s);
{
    return 0;
}

int8_t zmtp_read(struct smtp_socket* s, void* buf, uint16_t len);
{
    return 0;
}


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, enum zmq_socket_t type, void (*wakeup)(uint16_t ev, struct zmtp_socket* s));
{  
    struct zmtp_socket* s;
    /*
    s = pico_zalloc(sizeof(zmtp_socket));
    if (s == NULL)
       return NULL;
    
    struct* pico_socket = pico_socket_open(net, proto, &zmtp_tcp_cb);
    if (pico_socket == NULL)
        return NULL;
    s->sock = pico_socket;

    s->state = ST_OPEN;

    if (type >= TYPE_END)
    {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    s->type = type;
    */
    return s;
}
