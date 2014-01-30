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

<<<<<<< HEAD
struct zmtp_socket* zmtp_socket_open(uint16_t net, uint16_t proto, struct zmq_socket* parent, enum zmq_socket_t type, void (*wakeup)(uint16_t ev, struct zmtp_socket* s));

static void zmtp_tcp_cb(uint16_t ev, struct pico_socket *s);
 


=======
struct zmq_msg {
    uint8_t flags;
    uint64_t len;
    uint8_t *buf;
};

struct zmtp_socket* zmtp_socket_open(struct zmq_socket* parent, 
    enum zmq_socket_t t, void (*wakeup)(uint16_t ev, struct zmtp_socket* s))

int8_t zmtp_bind(struct zmtp_socket* s, void* local_addr, uint16_t* port);
int8_t zmtp_connect(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port);
int8_t zmtp_send(struct zmtp_socket* s, zmq_msg_t** msg, uint16_t len);
int8_t zmtp_socket_close(struct zmtp_socket *s);
int8_t zmtp_read(struct smtp_socket* s, void* buf, uint16_t len);
>>>>>>> 28464d3224cebaf43e0b5ccaf297b6a07ebc3ac4

#endif
