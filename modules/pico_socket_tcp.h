#ifndef PICO_SOCKET_TCP_H
#define PICO_SOCKET_TCP_H

#ifdef PICO_SUPPORT_TCP
# define IS_NAGLE_ENABLED(s) (!(!(!(s->opt_flags & (1 << PICO_SOCKET_OPT_TCPNODELAY)))))

int pico_setsockopt_tcp(struct pico_socket *s, int option, void *value);
int pico_getsockopt_tcp(struct pico_socket *s, int option, void *value);

#else
#   define pico_getsockopt_tcp(...) (-1)
#   define pico_setsockopt_tcp(...) (-1)
#   define IS_NAGLE_ENABLED(s) (0)
#endif


#endif
