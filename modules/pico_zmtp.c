/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "pico_zmtp.h"
#include "pico_socket.h"
#include "pico_zmq.h"



struct zmtp_socket {
    struct pico_socket* sock;
    enum zmq_state state;
    zmq_socket* parent;
    enum zmq_socket_type role;
    uint16_t bytes_received;
};

static void zmtp_tcp_cb(uint16_t ev, struct pico_socket *s)
{
    return;
}

int8_t zmtp_bind(struct zmtp_socket* s, void* local_addr, uint16_t* port)
{
    int8_t ret = pico_socket_bind(s->sock, local_addr, port);
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


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, struct zmq_socket* parent, enum zmq_socket_t type, void (*wakeup)(uint16_t ev, struct zmtp_socket* s));
{  
    struct zmtp_socket* s;
//    s = pico_zalloc(sizeof(zmtp_socket));
//    if (s == NULL)
//       return s;
    
//    s->parent = parent;
    
//    struct* pico_socket = pico_socket_open(net, proto, &zmtp_tcp_cb);
//    s->
    return s;
}
