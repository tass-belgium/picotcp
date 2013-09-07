#ifndef __PICO_ZMQ_H
#define __PICO_ZMQ_H

struct zmq_socket;
typedef struct zmq_socket *ZMQ; 

ZMQ zmq_publisher(uint16_t _port, void (*cb)(ZMQ z));
ZMQ zmq_subscriber(void (*cb)(ZMQ z));
int zmq_connect(ZMQ z, char *address, uint16_t port);
int __attribute__((unused)) zmq_send(ZMQ z, char *txt, int len);
int zmq_recv(ZMQ z, char *txt);
void zmq_close(ZMQ z);

#endif
