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

#define ZMTP_TYPE_PAIR     (uint8_t)0
#define ZMTP_TYPE_PUB      (uint8_t)1
#define ZMTP_TYPE_SUB      (uint8_t)2
#define ZMTP_TYPE_REQ      (uint8_t)3
#define ZMTP_TYPE_REP      (uint8_t)4
#define ZMTP_TYPE_DEALER   (uint8_t)5
#define ZMTP_TYPE_ROUTER   (uint8_t)6
#define ZMTP_TYPE_PULL     (uint8_t)7
#define ZMTP_TYPE_PUSH     (uint8_t)8
#define ZMTP_TYPE_END      (uint8_t)9

enum zmtp_state {
    ST_SND_IDLE,
    ST_SND_OPEN,
    ST_SND_CONNECT,
    ST_SND_GREETING,
    ST_SND_RDY
};

enum zmtp_ev {
    EV_NONE=0,
    EV_ERR=1
};
/*
enum zmq_state {
    ST_OPEN = 0,
    ST_RDY,
    ST_BUSY,
    ST_END //Marks the end of the enum
};
*/

struct zmtp_frame_t {
    size_t len;
    void* buf;
};

struct zmtp_socket {
    struct pico_socket* sock;
    /*enum zmq_state state;*/
    enum zmtp_snd_state snd_state;
    enum zmtp_rcv_state rcv_state;
    uint8_t type;
    void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s);
};

struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, uint8_t type, void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s));
int zmtp_socket_connect(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port);
int zmtp_socket_send(struct zmtp_socket* s, struct pico_vector* vec);
int8_t zmtp_socket_close(struct zmtp_socket *s);
#endif
