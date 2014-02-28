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

static void cb_zmtp_sockets(uint16_t ev, struct zmtp_socket* s) 
{
    struct zmtp_socket* client;

    dbg("In cb_zmtp_sockets!");
    /* TODO: process events!! */
    /* In zmtp_socket will be a void* parent. Cast that one to a pub socket and add it to the subscribers vector. Don't forget to check type!! */ 
    if(ev == ZMTP_EV_CONN)
    {
        client = zmtp_socket_accept(s);
        if(s->type == ZMTP_TYPE_PUB)
        {
            pico_vector_push_back(&((struct zmq_socket_pub *)s)->subscribers, client);
        }
    }
}

/* When a new subscribers connects to the publisher, that zmtp_socket should be added into a list of subscribers. 
 * The reason why we use a pair of socket-mark is because when we want to send something out to subscribers,
 * we mark every socket that matches with the subscription and in a later phase, we send the message to all
 * marked sockets.
 */
static int8_t add_subscriber_to_publisher_subscribers(void* zmq_sock, struct zmtp_socket* zmtp_sock)
{
    struct zmq_socket_base* bsock = NULL;
    struct zmq_socket_pub* psock = NULL;
    struct zmq_sock_flag_pair pair;

    if(!zmq_sock || !zmtp_sock)
        return -1;
    
    bsock = (struct zmq_socket_base*)zmq_sock;
    
    if(bsock->type != ZMTP_TYPE_PUB)
        return -1;

    psock = (struct zmq_socket_pub*)zmq_sock;
    pair.socket = zmtp_sock;
    pair.mark = CLEAR_MARK_SOCKET_TO_SEND;  
    pico_vector_push_back(&psock->subscribers, &pair);

    return 0;
}

static int8_t add_subscription(void* subscription_in, uint16_t subscription_len, void *zmq_sock, struct zmtp_socket* zmtp_sock)
{
    /* TODO: scan if subscritpion already exists */
    /* TODO: if doesnt exist: add new sub_sub_pair into zmq_sock->subscriptions list */
    /* TODO: if exists: add zmtp_sock into the subscribers of the found sub_sub_pair */

    void* subscription = NULL;
    struct zmq_socket_pub* pub;
    struct zmq_sub_sub_pair pair;

    pub = (struct zmq_socket_pub*)zmq_sock;

    subscription = PICO_ZALLOC(subscription_len);
    memcpy(subscription, subscription_in, subscription_len);
    pair.subscription = subscription;
    pair.subscription_len = subscription_len;
    pico_vector_init(&pair.subscribers, 5, sizeof(struct zmq_sock_flag_pair));
    pico_vector_push_back(&pub->subscriptions, &pair);
    
}

int zmq_bind(void* socket, const char *endpoint)
{
    struct pico_ip4 addr;
    uint16_t port;

    if( !socket || !endpoint || ((struct zmq_socket_base *)socket)->type != ZMTP_TYPE_PUB )
        return -1;
        /* TODO: error handling! (EINVAL) */

    /* TODO: parse endpoint!! */
    pico_string_to_ipv4("0.0.0.0", &addr.addr); 
    port = short_be(5555);
    return zmtp_socket_bind(((struct zmq_socket_base *)socket)->sock, &addr.addr, &port);
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
        
    sock->sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, (uint8_t)type, sock, &cb_zmtp_sockets);
    
    if(!sock->sock) {
        PICO_FREE(sock);
        return NULL;
    }
    
    /* Init the pico_vector that is going to be used */
    pico_vector_init(&sock->in_vector, 5, sizeof(struct zmq_msg_t));
    pico_vector_init(&sock->out_vector, 5, sizeof(struct zmq_msg_t));

    if(type == ZMTP_TYPE_PUB) 
    {
        pico_vector_init(&((struct zmq_socket_pub *)sock)->subscribers, 5, sizeof(struct zmq_sock_flag_pair));  /* TODO: make initial size configurable */
        pico_vector_init(&((struct zmq_socket_pub *)sock)->subscriptions, 5, sizeof(struct zmq_sub_sub_pair));  /* TODO: make initial size configurable */
    }

    return sock;
}

int zmq_connect(void* socket, const char* endpoint)
{
    struct zmq_socket_base *base = NULL;
    struct pico_ip4 addr;
    
    if(!socket || !endpoint)
        return -1;
        /* TODO: error handling! => EINVAL */

    /* TODO: parse endpoint!!! */
    base = (struct zmq_socket_base *)socket;
    
    pico_string_to_ipv4("10.40.0.1", &addr.addr);
    return zmtp_socket_connect(base->sock, &addr.addr, short_be(5555));
}

int zmq_send(void* socket, const void* buf, size_t len, int flags)
{
    struct zmtp_frame_t frame;
    struct zmq_socket_base* bsock = NULL;
    struct pico_vector_iterator* iterator;

    if(!socket)
        return -1;

    frame.buf = PICO_ZALLOC(len);

    if(!frame.buf)
        return -1;

    memcpy(frame.buf, buf, len);
    frame.len = len;

    bsock = (struct zmq_socket_base *)socket;
    

    if(bsock->type == ZMTP_TYPE_REQ && ((struct zmq_socket_req *)bsock)->send_enable == ZMQ_SEND_DISABLED )
        return -1; /* For REQ, if send_enable is disabled, then return -1 */
    
    if( (flags & ZMQ_SNDMORE) != 0)
    {
        /* More frames to come. Just add into pico_vector and wait for a later call with a final frame */
        pico_vector_push_back(&bsock->out_vector, &frame);
    }
    else {
        /* Pass the vector to zmtp layer */
        
        /* Push the final frame to the out_vector */
        pico_vector_push_back(&bsock->out_vector, &frame);
        
        if(bsock->type == ZMTP_TYPE_PUB)
            iterator = pico_vector_begin(&((struct zmq_socket_pub *)bsock)->subscribers);

        /* Iteratore through all the registered ztmp sockets */
        while(iterator)
        {
            if( zmtp_socket_send(iterator->data, &bsock->out_vector) < 0 )
            {
                while(1);
                /* TODO: do some error handling! */
            }
            iterator = pico_vector_iterator_next(iterator);
        }

        if(bsock->type == ZMTP_TYPE_REQ)
            ((struct zmq_socket_req *)bsock)->send_enable = ZMQ_SEND_DISABLED;

        pico_vector_clear(&bsock->out_vector);  /* TODO: check if free(...) is needed somewhere!! */
    }

    return 0;
}
