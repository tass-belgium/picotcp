/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#ifndef __PICO_ZMQ_H
#define __PICO_ZMQ_H


#include <stdint.h>
#include <stdio.h>
#include "pico_vector.h"
#include "pico_addressing.h"
#include "pico_zmtp.h"


/*  Send/recv options.  */
#define ZMQ_DONTWAIT                1
#define ZMQ_SNDMORE                 2

#define ZMQ_SEND_ENABLED            1
#define ZMQ_SEND_DISABLED           2

#define MARK_SOCKET_TO_SEND         1   /* Used by zmq_publisher socket to mark zmtp_sockets that should receive an update */
#define CLEAR_MARK_SOCKET_TO_SEND   2   /* Used by zmq_publisher socket to mark zmtp_sockets that should receive an update */


struct zmq_msg_t
{
    size_t len;
    void* buf;
};

struct zmq_socket_base
{
    uint8_t type;
    struct zmtp_socket* sock; /* The local socket that is used */
    //State??
    //DECLARE_PICO_VECTOR(zmq_msg_t_in) out_vector;
    //DECLARE_PICO_VECTOR(zmq_msg_t_out) in_vector;
    struct pico_vector out_vector;
    struct pico_vector in_vector;
};

struct zmq_sub_sub_pair
{
    void* subscription;         /* Subscription can be anything but will probably be a string for most of the time */
    uint16_t subscription_len;
    struct pico_vector subscribers;    /* vector of sock_flag_pair elements */
};

struct zmq_sock_flag_pair
{
    struct zmtp_socket* socket;
    uint8_t mark;
};

struct zmq_socket_pub
{
    struct zmq_socket_base base;
    struct pico_vector subscriptions;  /* vector of sub_sub_pair elements */
    struct pico_vector subscribers;    /* vector of sock_flag_pair elements */
};

struct zmq_socket_req 
{
    struct zmq_socket_base base;
    uint8_t send_enable;        //Req can send data but afterwards it should receive something before sending again!
    struct zmtp_socket* sock; /* Remote socket. Should become a vector? */
};

void* zmq_socket(void* context, int type);
int zmq_setsockopt (void* socket, int option_name, const void* option_value, size_t option_len);
int zmq_getsockopt (void* socket, int option_name, void* option_value, size_t* option_len);
int zmq_bind(void* socket, const char* endpoint);
int zmq_connect(void* socket, const char* endpoint);
int zmq_send(void* socket, const void* buf, size_t len, int flags);
int zmq_recv(void* socket, char* txt);
void zmq_close(void* socket);

int zmq_msg_init_size(struct zmq_msg_t* msg, size_t size);

#endif
