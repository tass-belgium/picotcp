#ifndef PICO_SOCKET_UDP_H
#define PICO_SOCKET_UDP_H

struct pico_socket *pico_socket_udp_open(void);


#ifdef PICO_SUPPORT_UDP
# define pico_socket_udp_recv(s, buf, len, addr, port) pico_udp_recv(s, buf, len, addr, port)
#else
# define pico_socket_udp-recv(...) (0)
#endif


#endif
