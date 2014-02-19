/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#include "stdint.h"
#include "pico_vector.h"
#include "pico_zmq.h"
#include "pico_zmtp.h"

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_protocol.h"



#undef dbg
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
    IGNORE_PARAMETER(ev);
    IGNORE_PARAMETER(s);
    dbg("In cb_zmtp_sockets!");
    //TODO: process events!!
    //In zmtp_socket will be a void* parent. Cast that one to a pub socket and add it to the subscribers vector. Don't forget to check type!!    
    if(ev == EV_CONNECT)
    {
        if(s->type == ZMTP_TYPE_PUB)
        {
            pico_vector_push_back(&((struct zmq_socket_pub *)s)->subscribers, s);
        }
    }
}

int zmq_bind(void* socket, const char *endpoint)
{
    struct pico_ip4 addr;

    if( !socket || !endpoint || ((struct zmq_socket_base *)socket)->type != ZMTP_TYPE_PUB )
        return -1;
        //TODO: error handling! (EINVAL)

    //TODO: parse endpoint!!
    pico_string_to_ipv4("0.0.0.0", &addr.addr); 
    return zmtp_socket_bind(((struct zmq_socket_base *)socket)->sock, &addr.addr, short_be(5555));
}

void* zmq_socket(void* context, int type)
{
    struct zmq_socket_base* sock = NULL;

    IGNORE_PARAMETER(context);

    switch(type)
    {
        case(ZMTP_TYPE_REQ): 
            sock = PICO_ZALLOC(sizeof(struct zmq_socket_req));
            break;
        case(ZMTP_TYPE_REP):
            break; 
        case(ZMTP_TYPE_PUB):
            sock = PICO_ZALLOC(sizeof(struct zmq_socket_pub));
            break;
        default:
            return NULL;
    }
    
    if(!sock) 
    {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    if(type == ZMTP_TYPE_REQ)
        ((struct zmq_socket_req *)sock)->send_enable = ZMQ_SEND_ENABLED;

    sock->type = (uint8_t)type;
        
    sock->sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, (uint8_t)type, &cb_zmtp_sockets);
    
    if(!sock->sock) {
        PICO_FREE(sock);
        return NULL;
    }
    
    /* Init the pico_vector that is going to be used */
    pico_vector_init(&sock->in_vector, 5, sizeof(struct zmq_msg_t));
    pico_vector_init(&sock->out_vector, 5, sizeof(struct zmq_msg_t));

    if(type == ZMTP_TYPE_PUB)
        pico_vector_init(&((struct zmq_socket_pub *)sock)->subscribers, 5, sizeof(struct zmtp_socket));

    return sock;
}

int zmq_connect(void* socket, const char* endpoint)
{
    struct zmq_socket_base *base = NULL;
    struct pico_ip4 addr;
    
    if(!socket || !endpoint)
        return -1;
        //TODO: error handling! => EINVAL

    //TODO: parse endpoint!!!
    base = (struct zmq_socket_base *)socket;
    
    pico_string_to_ipv4("10.40.0.1", &addr.addr);
    return zmtp_socket_connect(base->sock, &addr.addr, short_be(5555));
}

int zmq_send(void* socket, void* buf, size_t len, int flags)
{
    struct zmtp_frame_t* frame = NULL;
    struct zmq_socket_base* bsock = NULL;
    struct pico_vector_iterator* iterator;

    if(!socket)
        return -1;

    frame = PICO_ZALLOC(sizeof(struct zmtp_frame_t));

    if(!frame)
        return -1;

    frame->buf = PICO_ZALLOC(len);

    if(!frame->buf)
        return -1;

    memcpy(frame->buf, buf, len);
    frame->len = len;

    bsock = (struct zmq_socket_base *)socket;
    

    if(bsock->type == ZMTP_TYPE_REQ && ((struct zmq_socket_req *)bsock)->send_enable == ZMQ_SEND_DISABLED )
        return -1; //For REQ, if send_enable is disabled, then return -1
    
    /* Multi-part messages are described here: http://zguide.zeromq.org/page:all#Multipart-Messages */
    if( (flags & ZMQ_SNDMORE) != 0)
    {
        /* More frames to come. Just add into pico_vector and wait for a later call with a final frame */
        pico_vector_push_back(&bsock->out_vector, frame);
    }
    else {
        /* Pass the vector to zmtp layer */
        
        /* Push the final frame to the out_vector */
        pico_vector_push_back(&bsock->out_vector, frame);
        
        //iterator = pico_vector_begin(..); 
        //while(iterator)
        //{
            if( zmtp_socket_send(bsock->sock, &bsock->out_vector) < 0 )
            {
                while(1);
                //TODO: do some error handling!
            }
            //iterator = pico_vector_iterator_next(iterator);
        //}

        if(bsock->type == ZMTP_TYPE_REQ)
            ((struct zmq_socket_req *)bsock)->send_enable = ZMQ_SEND_DISABLED;

        pico_vector_clear(&bsock->out_vector);  //Who has ownership of the data pointers?
    }

    return 0;
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
