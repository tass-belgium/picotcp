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

#endif
