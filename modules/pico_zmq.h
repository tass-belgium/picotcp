#ifndef __PICO_ZMQ_H
#define __PICO_ZMQ_H

struct zmq_socket;
typedef struct zmq_socket *ZMQ; 

ZMQ zmq_producer(uint16_t _port, void (*cb)(ZMQ z));
int zmq_send(ZMQ z, char *txt, int len);

#endif
