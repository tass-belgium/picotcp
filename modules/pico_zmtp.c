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

    if(ev & PICO_SOCK_EV_CONN)
    {
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
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_SIGNATURE)
        {
            ret = check_revision(zmtp_s);
            if(ret != 0)
                return;
        }

        if(zmtp_s->state == ZMTP_ST_RCVD_REVISION)
        {
            ret = check_socket_type(zmtp_s);
            if(ret != 0)
                return;
        }
        
        if(zmtp_s->state == ZMTP_ST_RCVD_TYPE)
        {
            ret = check_identity(zmtp_s);
            if(ret != 0)
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
    pico_tree_insert(&zmtp_sockets, new_zmtp_s);

    zmtp_send_greeting(new_zmtp_s);

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

int save2OutBuffer(struct pico_vector* buff, struct pico_vector_iterator* it) 
{
    struct zmtp_frame_t* sendFrame;
    struct zmtp_frame_t*  frame;
    char*  newBuff;
    size_t headerSize = 2;
    if (!buff)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    sendFrame = PICO_ZALLOC(sizeof(struct zmtp_frame_t));
    if (!sendFrame)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    while (it)
    {
        frame = (struct zmtp_frame_t*) it->data;
        it = pico_vector_iterator_next(it);
        if (frame)
        {
            newBuff = PICO_ZALLOC(frame->len + headerSize);
            if (!newBuff)
            {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            sendFrame->buf = newBuff;
            sendFrame->len = frame->len + headerSize;
            if (it)
            {
                /*more frame*/
                newBuff[0] = 0x01;
                newBuff[1] = frame->len;
            } else {
                /*final frame*/
                newBuff[0] = 0x00;
                newBuff[1] = frame->len;
            }
            memcpy(sendFrame->buf + headerSize, frame->buf, frame->len);
            pico_vector_push_back(buff, (void*) sendFrame);
        }
    }
    return 0;
}

int zmtp_socket_send(struct zmtp_socket* s, struct pico_vector* vec)
{
    size_t maxsize = 255;
    if (!s || !vec || !s->sock || !s->out_buff)
    {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    uint8_t* sendbuffer = PICO_ZALLOC(maxsize);
    if (!sendbuffer)
    {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    int ret = 0;    
    struct pico_vector_iterator* it  = pico_vector_begin(vec);
    struct pico_vector_iterator* prevIt = PICO_ZALLOC(sizeof(struct pico_vector_iterator));
    struct pico_vector_iterator* buffIt = pico_vector_begin(s->out_buff);
    struct zmtp_frame_t* frame;

    if (ZMTP_ST_RDY == s->state)
    {
        while (buffIt && ret == 0)
        {
            /* we use the iterator instead of pop, because we don't want to lose any data
            in case pico_socket_write fails*/
            /*send the frames that are still in the buffer*/
            frame = (struct zmtp_frame_t*) (buffIt->data);
            ret = pico_socket_write(s->sock, frame->buf, frame->len);
            if (0 == ret)
            {
                /*free the buffer from the frame, in case the write fails, we don't need to free*/
                printf("should not get here");
                PICO_FREE(frame->buf);
                pico_vector_pop_front(s->out_buff);
            } 
            buffIt = pico_vector_iterator_next(buffIt);
        }
        /*make a duplicate of the iterator, this one we only increment after trying to write*/
        memcpy(prevIt, it, sizeof(struct pico_vector_iterator));
        while (it && ret==0)
        {
            frame = (struct zmtp_frame_t*) it->data;
            it = pico_vector_iterator_next(it);
            if (it)
            {
                /*more frame*/
                sendbuffer[0] = 0x01;
                sendbuffer[1] = frame->len;
            } else {
                /*final frame*/
                sendbuffer[0] = 0x00;
                sendbuffer[1] = frame->len;
            }
            memcpy(sendbuffer+2, frame->buf, frame->len);
            ret = pico_socket_write(s->sock, (void*) sendbuffer, frame->len+2);

            if (ret != 0)
            {
                /*socket write went wrong, pushback starting from previous iterator*/
                //save2OutBuffer(s->out_buff, prevIt);
            } else {
                prevIt = pico_vector_iterator_next(prevIt);
            }
        }


    } else {
        //save2OutBuffer(s->out_buff, it);    
    }
    if (it)
        PICO_FREE(it);
    if (buffIt)
        PICO_FREE(buffIt);
    PICO_FREE(sendbuffer);

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


struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, uint8_t type , void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s))
{  
    struct zmtp_socket* s = NULL;
    struct pico_vector* out_buff = NULL;
    struct pico_socket* pico_s = NULL;
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
