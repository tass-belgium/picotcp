#ifndef __PICO_ZMTP_H
#define __PICO_ZMTP_H

struct zmtp_socket;

enum zmq_socket_type {
    ROLE_NONE = 0,
    ROLE_PUBLISHER,
    ROLE_SUBSCRIBER
};

enum zmq_state {
    ST_OPEN = 0,
    ST_CONNECTED,
    ST_SIGNATURE,
    ST_VERSION,
    ST_GREETING,
    ST_RDY,
    ST_BUSY
};

struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, struct zmq_socket* parent, enum zmq_socket_t type, void (*wakeup)(uint16_t ev, struct zmtp_socket* s));

static void zmtp_tcp_cb(uint16_t ev, struct pico_socket *s);
 



#endif
