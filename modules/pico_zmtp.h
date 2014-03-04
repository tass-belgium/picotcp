/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#ifndef __PICO_ZMTP_H
#define __PICO_ZMTP_H

#include <stdint.h>
#include "pico_socket.h"
#include "pico_vector.h"

#define SOCK_BUFF_CAP    10

#define ZMTP_TYPE_PAIR     (uint8_t)0x00
#define ZMTP_TYPE_PUB      (uint8_t)0x01
#define ZMTP_TYPE_SUB      (uint8_t)0x02
#define ZMTP_TYPE_REQ      (uint8_t)0x03
#define ZMTP_TYPE_REP      (uint8_t)0x04
#define ZMTP_TYPE_DEALER   (uint8_t)0x05
#define ZMTP_TYPE_ROUTER   (uint8_t)0x06
#define ZMTP_TYPE_PULL     (uint8_t)0x07
#define ZMTP_TYPE_PUSH     (uint8_t)0x08
#define ZMTP_TYPE_END      (uint8_t)0x09

enum zmtp_state {
    ZMTP_ST_IDLE,           //0
    ZMTP_ST_SND_GREETING,   //1
    ZMTP_ST_RCVD_SIGNATURE, //2
    ZMTP_ST_RCVD_REVISION,  //3
    ZMTP_ST_RCVD_TYPE,      //4
    ZMTP_ST_RCVD_ID_LEN,    //5
    ZMTP_ST_RDY             //6
};

#define ZMTP_EV_NONE        (uint8_t)0
#define ZMTP_EV_CONN        (uint8_t)4
#define ZMTP_EV_ERR         (uint8_t)0x80

enum zmtp_error_e {
    ZMTP_ERR_NOERR,
    ZMTP_ERR_EINVAL,
    ZMTP_ERR_ENOMEM,
    ZMTP_ERR_NOTIMPL
};

enum zmtp_error_e zmtp_err;


struct zmtp_frame_t {
    size_t len;
    void* buf;
};

struct zmtp_socket {
    struct pico_socket* sock;
    struct pico_vector* out_buff;
    enum zmtp_state state;
    uint8_t type;
    void* parent;
    void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s);
};

struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, uint8_t type, void* parent, void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s));
struct zmtp_socket* zmtp_socket_accept(struct zmtp_socket* zmtp_s);
int zmtp_socket_connect(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port);
int zmtp_socket_send(struct zmtp_socket* s, struct pico_vector* vec);
int zmtp_socket_bind(struct zmtp_socket* s, void* local_addr, uint16_t* port);
int zmtp_socket_close(struct zmtp_socket *s);
#endif
