#undef pico_zalloc
#undef pico_free
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

int zmtp_send_greeting(struct zmtp_socket* s)
{
    /* zmtp2.0 full greeting */
    uint8_t* signature;
    int ret;

    signature = PICO_ZALLOC(14);
    signature[0] = 0xff;
    signature[9] = 0x7f;
    signature[10] = 0x01;
    signature[11] = s->type;
    
    ret = pico_socket_send(s->sock, signature, 14);
    PICO_FREE(signature);
    return ret;
}

/* Checking zmtp2.0 header, discarding 9th byte */
int8_t check_signature(uint8_t* buf)
{
    uint8_t i;
    uint8_t sign[10] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x7f};

    for(i = 0; i < 8; i++)
        if(sign[i] != buf[i])
            return -1;
    if(sign[9] != buf[i])
        return -1;
    else
        return 0;
}


/* Returns the socket type if valid, else -1 */
int8_t check_socket_type(uint8_t* buf)
{
    if(*buf > 8)
        return -1;
    else
        return (int8_t)(*buf);
/*    switch(*buf)
    {
        case 0x00: 
            return ZMTP_TYPE_PAIR;
            break;
        case 0x01:
            return ZMTP_TYPE_PUB;
            break;
        case 0x02:
            return ZMTP_TYPE_SUB;
            break;
        case 0x03:
            return ZMTP_TYPE_REQ;
            break;
        case 0x04:
            return ZMTP_TYPE_REP;
            break;
        case 0x05:
            return ZMTP_TYPE_DEALER;
            break;
        case 0x06:
            return ZMTP_TYPE_ROUTER;
            break;
        case 0x07:
            return ZMTP_TYPE_PULL;
            break;
        case 0x08:
            return ZMTP_TYPE_PUSH;
            break;
        default:
            return -1;
    }
*/
}

/* takes the identity flags (2 bytes) and returns the length of the identity body */
int16_t get_identity_len(uint8_t* buf)
{
    if(0x00 != *buf)
        return -1;
    buf++;
    return *((int16_t*)buf);
}

static void zmtp_tcp_cb(uint16_t ev, struct pico_socket* s)
{
    int ret;
    void* buf;
    int len;

    struct zmtp_socket* zmtp_s = get_zmtp_socket(s);


    if(ev & PICO_SOCK_EV_CONN)
    {
        ret = zmtp_send_greeting(zmtp_s);
        if(ret == -1)
             zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event for zmq? */
        zmtp_s->state = ZMTP_ST_SND_GREETING;
        return;
    }
    
    if(ev & PICO_SOCK_EV_RD) 
    {
        if(zmtp_s->state == ZMTP_ST_SND_GREETING)
        {
            len = 10;
            buf = PICO_ZALLOC((size_t)len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event unexpexted short data */
            ret = check_signature(buf);
            if(ret == -1)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event wrong signature */
            zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
            PICO_FREE(buf);
            return;
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_SIGNATURE)
        {
            len = 1;
            buf = PICO_ZALLOC((size_t)len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event unexpexted short data */
            /* ret = check_revision(buf); */
            if(ret == -1)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event wrong (not supported?) revision */
            zmtp_s->state = ZMTP_ST_RCVD_REVISION;
            PICO_FREE(buf);
            return;
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_REVISION)
        {
            len = 1;
            buf = PICO_ZALLOC((size_t)len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event unexpexted short data */
            ret = check_socket_type(buf);
            if(ret == -1)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event wrong type or just cancel yourself? */
            zmtp_s->state = ZMTP_ST_RCVD_TYPE;
            PICO_FREE(buf);
            return;
        }
        
        if(zmtp_s->state == ZMTP_ST_RCVD_TYPE)
        {
            len = 2;
            buf = PICO_ZALLOC((size_t)len);
            ret = pico_socket_read(zmtp_s->sock, buf, len);
            if(ret < len)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event unexpexted short data */
            ret = get_identity_len(buf);
            if(ret == -1)
                zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event wrong final-short in identity? */
            if(ret == 0)
                zmtp_s->state = ZMTP_ST_RDY;
            else
            {
                zmtp_s->state = ZMTP_ST_RCVD_ID_LEN;
                while(1);
            }
            PICO_FREE(buf);
            return;
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_ID_LEN)
        {
        }
        
        if(zmtp_s->state == ZMTP_ST_RDY)
        {
            zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event data available */
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
        ret = PICO_ERR_EINVAL;
    }

    return ret;
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
    uint8_t* data = NULL;
    struct zmtp_frame_t* frame;
    int i;
    
    //Should append the more-short/final-short field code
    for(i=0; i<2; i++) {
        frame = (struct zmtp_frame_t *)pico_vector_pop_front(vec);
        data = PICO_ZALLOC(frame->len + 2);
        if(i==0) 
            data[0] = 0x01; /* Frame delimiter is more-short frame! */
        else
            data[0] = 0x00; /* Final short frame */
        data[1] = frame->len;   /* Length final short frame */
        memcpy(data+2, frame->buf, frame->len);
        pico_socket_send(s->sock, data, frame->len + 2);
        PICO_FREE(data);
    }
    return 0;
}

int zmtp_socket_close(struct zmtp_socket *s)
{
    if(NULL==s || NULL==s->sock)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    s->state = ZMTP_ST_IDLE;
    return pico_socket_close(s->sock);
}


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, uint8_t type , void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s))
{  
    struct zmtp_socket* s;
    struct pico_vector* out_buff;
    struct pico_socket* pico_s;
    if (type >= ZMTP_TYPE_END)
    {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if (zmq_cb == NULL)
    {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    s = PICO_ZALLOC(sizeof(struct zmtp_socket));
    if (s == NULL)
    {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    s->type = type;
    s->zmq_cb = zmq_cb;
    
    out_buff = PICO_ZALLOC(sizeof(struct pico_vector));
    pico_vector_init(out_buff, SOCK_BUFF_CAP, sizeof(struct zmtp_frame_t));

    if (NULL == out_buff) 
    {
        pico_err = PICO_ERR_ENOMEM;
        PICO_FREE(s);
        return NULL;
    }
    pico_s = pico_socket_open(net, proto, &zmtp_tcp_cb);
    if (pico_s == NULL) // Leave pico_err the same 
    {
        PICO_FREE(s);
        return NULL;
    }
    s->sock = pico_s;
    s->state = ZMTP_ST_IDLE;
    
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
