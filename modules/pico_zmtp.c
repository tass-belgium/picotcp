/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "pico_zmtp.h"
#include "pico_socket.h"
#include "pico_zmq.h"


static void zmtp_tcp_cb(uint16_t ev, struct pico_socket* s)
{
    return;
}

int8_t zmtp_socket_bind(struct zmtp_socket* s, void* local_addr, uint16_t* port)
{
    int8_t ret = pico_socket_bind(s->sock, local_addr, port);
    return ret;
}


int8_t zmtp_socket_connect(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port)
{
    return 0;
}

int8_t zmtp_socket_send(struct zmtp_socket* s, struct zmq_msg** msg, uint16_t len)
{
    return 0;
}

int8_t zmtp_socket_close(struct zmtp_socket *s)
{
    return 0;

}


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, uint16_t type, void (*wakeup)(uint16_t ev, struct zmtp_socket* s))
{  
    struct zmtp_socket* s;
    if (NULL == wakeup)
    {
	return NULL;
    } 
    s = pico_zalloc(sizeof(struct zmtp_socket));
    if (s == NULL)
       return NULL;
    
    struct pico_socket* pico_s = pico_socket_open(net, proto, &zmtp_tcp_cb);
    if (pico_s == NULL)
    {
        pico_free(s);
        return NULL;
    }
    s->sock = pico_s;

    s->state = ST_OPEN;

    if (NULL == type || ZMQ_TYPE_END <= type)
    {
      printf("fail on type with number %d\n", type);
        pico_err = PICO_ERR_EINVAL;
	pico_free(pico_s);
	pico_free(s);
        return NULL;
    }
    s->type = type;
    
    return s;
}
