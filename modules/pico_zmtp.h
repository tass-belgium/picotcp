/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Stijn Haers, Mathias Devos, Gustav Janssens, Sam Van Den Berge
 *********************************************************************/

#ifndef __PICO_ZMTP_H
#define __PICO_ZMTP_H

#include <stdint.h>
#include "pico_socket.h"


enum zmq_state {
    ST_OPEN = 0,
    ST_CONNECTED,
    ST_SIGNATURE,
    ST_VERSION,
    ST_GREETING,
    ST_RDY,
    ST_BUSY,
    ST_END //Marks the end of the enum
};

struct zmtp_frame_t {
    size_t len;
    void* buf;
};

struct zmtp_socket {
    struct pico_socket* sock;
    enum zmq_state state;
    uint8_t type;
    void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s);
};

struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, void (*zmq_cb)(uint16_t ev, struct zmtp_socket* s));
int zmtp_socket_connect(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port);
int zmtp_socket_send(struct zmtp_socket* s, void** buf, int* len, int lenBuf);
int8_t zmtp_socket_close(struct zmtp_socket *s);
#endif
