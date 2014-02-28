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
#include "pico_ipv4.h"

#define dbg printf

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

void close_socket(struct zmtp_socket *zmtp_s)
{
    dbg("close socket\n");
    IGNORE_PARAMETER(zmtp_s);
}

void zmtp_send_greeting(struct zmtp_socket* zmtp_s)
{
    int ret;
    uint8_t greeting[14] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x7f, 0x01, zmtp_s->type, 0x00, 0x00};
    ret = pico_socket_write(zmtp_s->sock, &greeting, 14);
    if(ret == 0)
        zmtp_s->state = ZMTP_ST_SND_GREETING;
    else
        close_socket(zmtp_s);
}

/* Checking zmtp2.0 header, discarding 9th byte */
/* returns 0 when signature was ok, else -1 */
int check_signature(struct zmtp_socket *zmtp_s)
{
    int ret = 0;
    int len = 10;
    uint8_t *buf;

    uint8_t i;
    uint8_t sign[10] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x7f};

    buf = PICO_ZALLOC((size_t)len);
    if(buf == NULL)
    {
        zmtp_err = ZMTP_ERR_ENOMEM;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s);
    }

    ret = pico_socket_read(zmtp_s->sock, buf, len);
    if(ret == 0)
    {
        PICO_FREE(buf);
        return -1;
    }
    else if(ret < len)
    {
        PICO_FREE(buf);
        zmtp_err = ZMTP_ERR_NOTIMPL;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s); /* event unexpexted short data */
        return -1;
    }

    ret = 0;
    for(i = 0; i < 8; i++)
        if(sign[i] != buf[i])
            ret = -1;
    if(sign[9] != buf[9])
        ret = -1;

    if(ret != 0)
    {
        PICO_FREE(buf);
        close_socket(zmtp_s);
        return -1;
    }   

    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    PICO_FREE(buf);

    return ret;
}

int check_revision(struct zmtp_socket *zmtp_s)
{
    int ret;
    int len = 1;
    uint8_t *buf;

    buf = PICO_ZALLOC((size_t)len);
    if(buf == NULL)
    {
        zmtp_err = ZMTP_ERR_ENOMEM;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s);
    }

    ret = pico_socket_read(zmtp_s->sock, buf, len);
    if(ret == 0)
    {
        PICO_FREE(buf);
        return -1;
    }
    else if(ret < len)
    {
        PICO_FREE(buf);
        zmtp_err = ZMTP_ERR_NOTIMPL;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s); /* event unexpexted short data */
        return -1;
    }
    else
    
    zmtp_s->state = ZMTP_ST_RCVD_REVISION;
    PICO_FREE(buf);
    
    return 0;
}

int check_socket_type(struct zmtp_socket* zmtp_s)
{
    int ret;
    int len = 1;
    uint8_t* buf;

    buf = PICO_ZALLOC((size_t)len);
    if(buf == NULL)
    {
        zmtp_err = ZMTP_ERR_ENOMEM;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s);
    }

    ret = pico_socket_read(zmtp_s->sock, buf, len);

    if(ret == 0)
    {
        PICO_FREE(buf);
        return -1;
    }
    else if(ret < len)
    {
        PICO_FREE(buf);
        zmtp_err = ZMTP_ERR_NOTIMPL;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s); /* event unexpexted short data */
        return -1;
    }

    if(*buf > 8)
    {
        PICO_FREE(buf);
        close_socket(zmtp_s);
        return -1;
    }
    
    zmtp_s->state = ZMTP_ST_RCVD_TYPE;
    PICO_FREE(buf);
    
    return 0;
}

/* takes the identity flags (2 bytes) and returns the length of the identity body */
int check_identity(struct zmtp_socket* zmtp_s)
{
    int ret;
    int len = 2;
    uint8_t* buf;
    uint8_t* ptr;

    buf = PICO_ZALLOC((size_t)len);
    if(buf == NULL)
    {
        zmtp_err = ZMTP_ERR_ENOMEM;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s);
    }

    ret = pico_socket_read(zmtp_s->sock, buf, len);
    if(ret == 0)
    {
        PICO_FREE(buf);
        return -1;
    }
    else if(ret < len)
    {
        PICO_FREE(buf);
        zmtp_err = ZMTP_ERR_NOTIMPL;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s); /* event unexpexted short data */
        return -1;
    }

    if(0x00 != *buf)
    {
        PICO_FREE(buf);
        close_socket(zmtp_s);
        return -1;
    }
    ptr = buf + 1;

    if(*ptr == 0)
    {
        PICO_FREE(buf);
        zmtp_s->state = ZMTP_ST_RDY;
        return 0;
    }
    else
    {
        PICO_FREE(buf);
        /* read identity */
        return -1;
    }
}

static void zmtp_tcp_cb(uint16_t ev, struct pico_socket* s)
{
    int ret;
    struct zmtp_socket* zmtp_s = get_zmtp_socket(s);

    if(zmtp_s == NULL)
        return;
    if(ev & PICO_SOCK_EV_CONN)
    {
        dbg("connection\n");
        zmtp_s->zmq_cb(ZMTP_EV_CONN, zmtp_s);
        return;
    }
    
    if(ev & PICO_SOCK_EV_RD) 
    {
        if(zmtp_s->state == ZMTP_ST_SND_GREETING)
        {
            ret = check_signature(zmtp_s);
            if(ret != 0)
                return;
            dbg("zmtp_s->state: ZMTP_ST_RCVD_SIGNATURE\n");
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_SIGNATURE)
        {
            ret = check_revision(zmtp_s);
            if(ret != 0)
                return;
            dbg("zmtp_s->state: ZMTP_ST_RCVD_REVISION\n");
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_REVISION)
        {
            ret = check_socket_type(zmtp_s);
            if(ret != 0)
                return;
            dbg("zmtp_s->state: ZMTP_ST_RCVD_TYPE\n");
        }
        
        if(zmtp_s->state == ZMTP_ST_RCVD_TYPE)
        {
            ret = check_identity(zmtp_s);
            if(ret != 0)
                return;
            dbg("zmtp_s->state: ZMTP_ST_RCVD_IDENTITY\n");
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_ID_LEN)
        {
        }
        
        if(zmtp_s->state == ZMTP_ST_RDY)
        {
            dbg("zmtp_s->state: ZMTP_ST_RDY\n");
            zmtp_s->zmq_cb(ZMTP_ERR_NOTIMPL, zmtp_s); /* event data available */
        }
    }

}

struct zmtp_socket* zmtp_socket_accept(struct zmtp_socket* zmtp_s)
{
    struct zmtp_socket* new_zmtp_s;
    struct pico_ip4 orig;
    uint16_t port;

    new_zmtp_s = PICO_ZALLOC(sizeof(struct zmtp_socket));
    if(new_zmtp_s == NULL)
    {
        zmtp_err = ZMTP_ERR_ENOMEM;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s);
    }

    new_zmtp_s->sock = pico_socket_accept(zmtp_s->sock, &orig, &port);
    dbg("new_zmtp_s->sock: %p\n", new_zmtp_s->sock);
    if(new_zmtp_s->sock == NULL)
    {
        /* if EAGAIN try again */
        /* if EINVAL */
        zmtp_err = ZMTP_ERR_NOTIMPL;
        zmtp_s->zmq_cb(ZMTP_EV_ERR, zmtp_s);
    }
    new_zmtp_s->state = ZMTP_ST_IDLE;
    new_zmtp_s->type = zmtp_s->type;
    new_zmtp_s->zmq_cb = zmtp_s->zmq_cb;
    new_zmtp_s->parent = zmtp_s->parent;
    pico_tree_insert(&zmtp_sockets, new_zmtp_s);

    zmtp_send_greeting(new_zmtp_s);
    new_zmtp_s->state = ZMTP_ST_SND_GREETING;

    return new_zmtp_s;
}

int zmtp_socket_bind(struct zmtp_socket* s, void* local_addr, uint16_t* port)
{
    int ret = 0;

    if (s && s->sock)
    {
        ret = pico_socket_bind(s->sock, local_addr, port);
    } else {
        ret = PICO_ERR_EINVAL;
        ret = -1;
    }
    pico_socket_listen(s->sock, 10);

    return ret;
}

int zmtp_socket_connect(struct zmtp_socket* zmtp_s, void* srv_addr, uint16_t remote_port)
{
    if(zmtp_s == NULL)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return pico_socket_connect(zmtp_s->sock, srv_addr, remote_port);
}

int zmtp_socket_send(struct zmtp_socket* s, struct pico_vector* vec)
{
    int ret = 0;    
    struct pico_vector_iterator* it  = pico_vector_begin(vec);
    struct zmtp_frame_t* frame = NULL;
    uint8_t* msgBuffer = NULL;
    uint16_t totalLength = 0;
    uint16_t byteIndex = 0;
    uint8_t numFrames = 0;

    if (!s || !vec || !s->sock || !s->out_buff)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    while (it)
    {
        frame = (struct zmtp_frame_t*) it->data;
        totalLength = (uint16_t) (totalLength + frame->len);
        numFrames++;
        if (frame->len > 255)
            totalLength = (uint16_t)(totalLength + 9);
        else
            totalLength =(uint16_t)(totalLength + 2);    
        it = pico_vector_iterator_next(it);

    }

    msgBuffer = PICO_ZALLOC((size_t) totalLength);
    if (!msgBuffer)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    it  = pico_vector_begin(vec);
    while (it)
    {
        frame = (struct zmtp_frame_t*) it->data;
        it = pico_vector_iterator_next(it);
        numFrames--;
        if (frame->len <= 255)
        {
            if (numFrames > 0)
            {
                /*more frame*/
                msgBuffer[byteIndex + 0] = 0x01;
                msgBuffer[byteIndex + 1] = (uint8_t) frame->len;
            } else {
                /*final frame*/
                msgBuffer[byteIndex + 0] = 0x00;
                msgBuffer[byteIndex + 1] = (uint8_t) frame->len;
            }
            byteIndex = (uint16_t)(byteIndex + 2);
        }
        if (frame->len > 255)
        {
            /*this case should be extended to add proper size */
            if (numFrames > 0)
            {
                /*more frame*/
                msgBuffer[byteIndex + 0] = 0x03;
                msgBuffer[byteIndex + 1] = (uint8_t) frame->len;
            } else {
                /*final frame*/
                msgBuffer[byteIndex + 0] = 0x02;
                msgBuffer[byteIndex + 1] = (uint8_t) frame->len;
            }
            byteIndex = (uint16_t) (byteIndex + 9);
        }
        
        memcpy(msgBuffer+byteIndex, frame->buf, frame->len);
        byteIndex = (uint16_t) (byteIndex + frame->len);
    }

    if (ZMTP_ST_RDY == s->state)
    {
        ret = pico_socket_write(s->sock, (void*) msgBuffer, totalLength);
        PICO_FREE(msgBuffer);
    } else {
        /* save it to the buffer */
        /* do not free the buffer but pass on the pointer when this case is implemented */
        PICO_FREE(msgBuffer);
    }
    if (it)
        PICO_FREE(it);

    return ret;
}

int zmtp_socket_close(struct zmtp_socket *s)
{
    int ret = 0;
    if(NULL==s)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    ret = pico_socket_close(s->sock);
    if (s->sock)
        PICO_FREE(s->sock);
    if (s->out_buff)
    {
        /*implement the freeing of all messages still required*/
        pico_vector_destroy(s->out_buff);
    }
    if (s)
        PICO_FREE(s);
    return ret; 
}


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, uint8_t type, void* parent, void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s))
{  
    struct zmtp_socket* s = NULL;
    struct pico_socket* pico_s = NULL;

    if (parent == NULL)
    {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
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
    s->parent = parent;
    
    s->out_buff = PICO_ZALLOC(sizeof(struct pico_vector));
    if (NULL == s->out_buff) 
    {
        pico_err = PICO_ERR_ENOMEM;
        PICO_FREE(s);
        return NULL;
    }
    pico_s = pico_socket_open(net, proto, &zmtp_tcp_cb);
    pico_vector_init(s->out_buff, SOCK_BUFF_CAP, sizeof(struct zmtp_frame_t));
    if (pico_s == NULL) // Leave pico_err the same 
    {
        PICO_FREE(s->out_buff);
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
