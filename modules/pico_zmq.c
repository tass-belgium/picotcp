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


#define INITIAL_CAPACITY_SUBSCRIBERS_VECTOR 5
#define INITIAL_CAPACITY_SUBSCRIPTIONS_VECTOR 5
#define INITIAL_CAPACITY_SUBSCRIBERS_PER_SUBSCRIPTION 5
#define INITIAL_CAPACITY_OUT_VECTOR 5
#define INITIAL_CAPACITY_IN_VECTOR 5

#undef dbg
#define dbg(x,args...) printf("[%s:%s:%i] "x" \n",__FILE__,__func__,__LINE__ ,##args )

/* When a new subscribers connects to the publisher, that zmtp_socket should be added into a list of subscribers. 
 * The reason why we use a pair of socket-mark is because when we want to send something out to subscribers,
 * we mark every socket that matches with the subscription and in a later phase, we send the message to all
 * marked sockets.
 */
static int8_t add_subscriber_to_publisher(void* zmq_sock, struct zmtp_socket* zmtp_sock)
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

static int8_t add_subscription(void* subscription_in, size_t subscription_len, void *zmq_sock, struct zmtp_socket* zmtp_sock)
{
    void* subscription = NULL;
    struct zmq_socket_pub* pub;
    struct zmq_sub_sub_pair pair;
    struct pico_vector_iterator* it;

    pub = (struct zmq_socket_pub*)zmq_sock;

    /* Get the subscriptions iterator to search if the subscription already exists */
    it = pico_vector_begin(&pub->subscriptions);
    while(it)
    {
        if(memcmp(((struct zmq_sub_sub_pair*)it->data)->subscription, subscription_in, subscription_len) == 0)
        {
            /* The subscription already exists so add the new zmtp_sock into the subscribers of that specific subscription */
            pico_vector_push_back(&((struct zmq_sub_sub_pair*)it->data)->subscribers, zmtp_sock);
            PICO_FREE(it); /* Free the it. This must be done if you don't iterate through the end. See pico_vector for details. */
            return 0;
        }
        it = pico_vector_iterator_next(it);
    } 

    /* If subscription doesn't exist in the subscriptions list, create a new one and add it into the subscriptions list */
    subscription = PICO_ZALLOC(subscription_len);
    memcpy(subscription, subscription_in, subscription_len);
    pair.subscription = subscription;
    pair.subscription_len = subscription_len;
    pico_vector_init(&pair.subscribers, INITIAL_CAPACITY_SUBSCRIBERS_PER_SUBSCRIPTION, sizeof(struct zmq_sock_flag_pair));
    pico_vector_push_back(&pub->subscriptions, &pair);
    
    return 0;    
}

static void cb_zmtp_sockets(uint16_t ev, struct zmtp_socket* s) 
{
    struct zmtp_socket* client;

    dbg("In cb_zmtp_sockets!");
    /* TODO: process events!! */
    if(ev == ZMTP_EV_CONN)
    {
        client = zmtp_socket_accept(s);
        if(s->type == ZMTP_TYPE_PUB)
        {
            add_subscriber_to_publisher(client->parent, client);
        }
    }
    /* Else if read event for pub: zmtp_read(...); check if the first byte is 0x01 and then call add_subscription */
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
    pico_vector_init(&sock->in_vector, INITIAL_CAPACITY_IN_VECTOR, sizeof(struct zmq_msg_t));
    pico_vector_init(&sock->out_vector, INITIAL_CAPACITY_OUT_VECTOR, sizeof(struct zmq_msg_t));

    if(type == ZMTP_TYPE_PUB) 
    {
        pico_vector_init(&((struct zmq_socket_pub *)sock)->subscribers, INITIAL_CAPACITY_SUBSCRIBERS_VECTOR, sizeof(struct zmq_sock_flag_pair));
        pico_vector_init(&((struct zmq_socket_pub *)sock)->subscriptions, INITIAL_CAPACITY_SUBSCRIPTIONS_VECTOR, sizeof(struct zmq_sub_sub_pair));
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

static void scan_and_mark(void* socket, struct pico_vector* vec)
{
    struct pico_vector_iterator* it;
    struct zmq_sock_flag_pair* pair;

    IGNORE_PARAMETER(vec);

    it = pico_vector_begin(&((struct zmq_socket_pub*)socket)->subscribers);
    while(it)
    {
        pair = it->data;
        pair->mark = MARK_SOCKET_TO_SEND; /* Mark every socket for now! */
        it = pico_vector_iterator_next(it);
    } 
}

static int send_pub(void* socket, struct pico_vector* vec)
{
    struct zmq_socket_base* bsock = NULL;
    struct zmq_socket_pub* psock = NULL;
    struct pico_vector_iterator* it = NULL;
    struct zmq_sock_flag_pair* pair = NULL;

    bsock = (struct zmq_socket_base*)socket;

    if(!socket || !vec || bsock->type != ZMTP_TYPE_PUB)
        return -1;

    scan_and_mark(socket, vec);

    psock = (struct zmq_socket_pub*)socket;
    it = pico_vector_begin(&psock->subscribers);
    while(it)
    {
        pair = it->data;
        if(pair->mark == MARK_SOCKET_TO_SEND)
        {
            if(zmtp_socket_send(pair->socket, vec) < 0) 
            {
                /* TODO: do some error handling! */
            }
        }
        it = pico_vector_iterator_next(it);
    }
    return 0;
}

int zmq_send(void* socket, const void* buf, size_t len, int flags)
{
    struct zmtp_frame_t frame;
    struct zmq_socket_base* bsock = NULL;
    struct pico_vector_iterator* it = NULL;

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
        
        switch(bsock->type)
        {
            case ZMTP_TYPE_PUB:
                send_pub(bsock, &bsock->out_vector); /* TODO: think about return type! */
                break;

            default:
                return -1;
        }

        /* Clear the out_vector */
        it = pico_vector_begin(&bsock->out_vector);
        while(it)
        {
            PICO_FREE(((struct zmtp_frame_t *)it->data)->buf);
            it = pico_vector_iterator_next(it);
        }
        pico_vector_clear(&bsock->out_vector); 
    }

    return 0;
}
