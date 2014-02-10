#ifndef PICO_SOCKET_TCP_H
#define PICO_SOCKET_TCP_H
#include "pico_socket.h"

#ifdef PICO_SUPPORT_TCP

/* Functions/macros: conditional! */

# define IS_NAGLE_ENABLED(s) (!(!(!(s->opt_flags & (1 << PICO_SOCKET_OPT_TCPNODELAY)))))
int pico_setsockopt_tcp(struct pico_socket *s, int option, void *value);
int pico_getsockopt_tcp(struct pico_socket *s, int option, void *value);
int pico_socket_tcp_deliver(struct pico_sockport *sp, struct pico_frame *f);

#else
#   define pico_getsockopt_tcp(...) (-1)
#   define pico_setsockopt_tcp(...) (-1)
#   define pico_socket_tcp_deliver(...) (-1)
#   define IS_NAGLE_ENABLED(s) (0)
#endif


/* non-conditionals: left empty if PICO_SUPPORT_TCP is off */

void pico_socket_tcp_delete(struct pico_socket *s);
void pico_socket_tcp_cleanup(struct pico_socket *sock);
struct pico_socket *pico_socket_tcp_open(void);

#endif
