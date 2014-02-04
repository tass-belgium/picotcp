/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "pico_zmtp.h"
#include "pico_socket.h"
#include "pico_zmq.h"
#include "pico_tree.h"
#include "pico_protocol.h"

//#include "pico_stack.h"
//#include "pico_config.h"
//#include "pico_ipv4.h"

static int zmtp_socket_cmp(void *ka, void *kb)
{
    struct zmtp_socket* a = ka;
    struct zmtp_socket* b = kb;
    if(a->sock < b->sock)
        return -1;

    if (b->sock < a->sock)
        return 1;

    return 0;
}
PICO_TREE_DECLARE(zmtp_sockets, zmtp_socket_cmp);

static inline struct zmtp_socket* get_zmtp_socket(struct pico_socket *s)
{
    struct zmtp_socket tst = {
        .sock = s
    };
    return (pico_tree_findKey(&zmtp_sockets, &tst));
}

int zmtp_send_greeting(struct zmtp_socket* s, uint8_t type)
{
    uint8_t signature[14] = {
        0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 1, type, 0, 0
    };
    
    return pico_socket_send(s->sock, signature, 14);
}
static void zmtp_tcp_cb(uint16_t ev, struct pico_socket* s)
{
    struct zmtp_socket* zmtp_s = get_zmtp_socket(s);
    zmtp_s->zmq_cb(ev,zmtp_s);
}

int zmtp_socket_bind(struct zmtp_socket* s, void* local_addr, uint16_t* port)
{
    int ret = 0;

    if (s && s->sock)
    {
        ret = pico_socket_bind(s->sock, local_addr, port);
    } else {
        ret = PICO_ERR_EFAULT;
    }

    return ret;
}


int zmtp_socket_connect(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port)
{
    return pico_socket_connect(s->sock, srv_addr, remote_port);
}

int8_t zmtp_socket_send(struct zmtp_socket* s, struct zmq_msg** msg, uint16_t len)
{
/*
    int ret;
    int i;

    for(i=0; i < len - 1; i++)
    {
        //create_msg
    }
    ret = pico_socket_send(s->sock, buf, lenBuf)
*/
    return 0;
}

int8_t zmtp_socket_close(struct zmtp_socket *s)
{
    return 0;

}


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s))
{  
    struct zmtp_socket* s;

    s = pico_zalloc(sizeof(struct zmtp_socket));
    if (s == NULL)
    {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    if (zmq_cb == NULL)
    {
        pico_err = PICO_ERR_EINVAL;
        pico_free(s);
        return NULL;
    } 
    s->zmq_cb = zmq_cb;
    
    struct pico_socket* pico_s = pico_socket_open(net, proto, &zmtp_tcp_cb);
    if (pico_s == NULL) // Leave pico_err the same 
    {
        pico_free(s);
        return NULL;
    }
    s->sock = pico_s;

    s->state = ST_OPEN;
    
    return s;
}
