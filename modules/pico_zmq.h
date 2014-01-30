#ifndef __PICO_ZMQ_H
#define __PICO_ZMQ_H

struct zmq_socket;

struct zmq_socket * zmq_socket_open(struct socket_type t);
int zmq_setsockopt (struct zmq_socket * z, int option_name, const void *option_value, size_t option_len);
int zmq_getsockopt (struct zmq_socket * z, int option_name, void *option_value, size_t *option_len);
int zmq_socket_bind(struct zmq_socket* s, char *address, uint16_t port)
int zmq_socket_connect(struct zmq_socket * z, char *address, uint16_t port);
int zmq_socket_send(struct zmq_socket * z, char *txt, int len);
int zmq_socket_recv(struct zmq_socket * z, char *txt);
void zmq_socket_close(struct zmq_socket * z);

#endif
