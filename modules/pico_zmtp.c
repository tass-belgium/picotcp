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


uint8_t check_signature(void* buf)
{
    uint8_t i;

    printf("received signature: ");
    for(i = 0; i < 10; i++)
        printf("%x ",((uint8_t*)buf)[i]);
    printf("\n");
    return 0;
}

uint8_t check_revision(void* buf)
{
    printf("received revision: ");
    printf("%x ",*(uint8_t*)buf);
    printf("\n");
    return 0;
}

uint8_t check_socket_type(void* buf)
{
    printf("received type: ");
    printf("%x ",*(uint8_t*)buf);
    printf("\n");
    return 0;
}

uint8_t get_identity_len(void* buf)
{
    uint8_t i;

    printf("received identity final-short: ");
    for(i = 0; i < 2; i++)
        printf("%x ",((uint8_t*)buf)[i]);
    printf("\n");
    return 0;
}

static void zmtp_tcp_cb(uint16_t ev, struct pico_socket* s)
{
    uint8_t ret;
    void* buf;
    uint8_t len;

    struct zmtp_socket* zmtp_s = get_zmtp_socket(s);
    zmtp_s->zmq_cb(ev,zmtp_s);


    if(ev & PICO_SOCK_EV_CONN) /* check socket_type */
    {
        ret = zmtp_send_greeting(zmtp_s);
        if(ret == -1)
             zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event for zmq? */
        zmtp_s->snd_state = ST_SND_GREETING;
        return;
    }
    
    if(ev & PICO_SOCK_EV_RD) 
    {
        if(zmtp_s->rcv_state == ST_RCV_IDLE)
        {
            len = 10;
            buf = pico_zalloc(len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event unexpexted short data */
            ret = check_signature(buf);
            if(ret == -1)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event wrong signature */
            zmtp_s->rcv_state = ST_RCV_SIGNATURE;
            pico_free(buf);
            return;
        }

        if(zmtp_s->rcv_state == ST_RCV_SIGNATURE)
        {
            len = 1;
            buf = pico_zalloc(len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event unexpexted short data */
            ret = check_revision(buf);
            if(ret == -1)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event wrong (not supported?) revision */
            zmtp_s->rcv_state = ST_RCV_REVISION;
            pico_free(buf);
            return;
        }

        if(zmtp_s->rcv_state == ST_RCV_REVISION)
        {
            len = 1;
            buf = pico_zalloc(len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event unexpexted short data */
            ret = check_socket_type(buf);
            if(ret == -1)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event wrong type or just cancel yourself? */
            zmtp_s->rcv_state = ST_RCV_TYPE;
            pico_free(buf);
            return;
        }
        
        if(zmtp_s->rcv_state == ST_RCV_TYPE)
        {
            len = 2;
            buf = pico_zalloc(len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event unexpexted short data */
            ret = get_identity_len(buf);
            if(ret == -1)
                zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event wrong final-short in identity? */
            if(ret == 0)
                zmtp_s->rcv_state = ST_RCV_ID;  
            else
            {
                zmtp_s->rcv_state = ST_RCV_ID_LEN;
                while(1);
            }
            pico_free(buf);
            return;
        }

        if(zmtp_s->rcv_state == ST_RCV_ID_LEN)
        {
        }
                
        
        if(zmtp_s->snd_state == ST_SND_GREETING && zmtp_s->rcv_state == ST_RCV_ID)
        {
            zmtp_s->zmq_cb(EV_ERR, zmtp_s); /* event data available */
        }
    }

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

int zmtp_send_greeting(struct zmtp_socket* s)
{
    /* zmtp2.0 full greeting */
    uint8_t signature[14] = {
        0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 1, s->type, 0, 0
    };
    
    return pico_socket_send(s->sock, signature, 14);
}

int zmtp_socket_connect(struct zmtp_socket* zmtp_s, void* srv_addr, uint16_t remote_port)
{
    int ret;
     
    if(zmtp_s == NULL)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    ret = pico_socket_connect(zmtp_s->sock, srv_addr, remote_port);
    if(ret == -1)
        return -1;

    
    return 0;
}

int zmtp_socket_send(struct zmtp_socket* s, struct pico_vector* vec)
{
    return 0;
}

int8_t zmtp_socket_close(struct zmtp_socket *s)
{
    int ret;
    if(NULL==s || NULL==s->sock)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    s->snd_state = ST_SND_IDLE;
    s->rcv_state = ST_RCV_IDLE;
    return pico_socket_close(s->sock);
}


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, uint8_t type , void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s))
{  
    struct zmtp_socket* s;

    if (type < 0 || type >= ZMTP_TYPE_END)
    {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if (zmq_cb == NULL)
    {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    s = pico_zalloc(sizeof(struct zmtp_socket));
    if (s == NULL)
    {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    s->type = type;
    s->zmq_cb = zmq_cb;
    
    struct pico_socket* pico_s = pico_socket_open(net, proto, &zmtp_tcp_cb);
    if (pico_s == NULL) // Leave pico_err the same 
    {
        pico_free(s);
        return NULL;
    }
    s->sock = pico_s;
    s->snd_state = ST_SND_IDLE;
    s->rcv_state = ST_RCV_IDLE;
    
    pico_tree_insert(&zmtp_sockets, s);

    return s;
}

int zmtp_socket_read(struct zmtp_socket* s, void* buff, int len)
{
    int retval = -1;
    if (NULL==s || NULL==s->sock)
    {
        pico_err = PICO_ERR_EINVAL;
        retval = -1;
    } else {
        retval = pico_socket_read(s->sock, buff, len);
    }
    return retval;
}
