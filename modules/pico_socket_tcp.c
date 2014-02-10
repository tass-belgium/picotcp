#include <stdint.h>
#include "pico_socket.h"

int pico_getsockopt_tcp(struct pico_socket *s, int option, void *value)
{
#ifdef PICO_SUPPORT_TCP
    if (option == PICO_TCP_NODELAY) {
        if (s->proto->proto_number == PICO_PROTO_TCP)
            /* state of the NODELAY option */
            *(int *)value = PICO_SOCKET_GETOPT(s, PICO_SOCKET_OPT_TCPNODELAY);
        else
            *(int *)value = 0;
        return 0;
    }
#endif
    return -1;
}

int pico_setsockopt_tcp(struct pico_socket *s, int option, void *value)
{
#ifdef PICO_SUPPORT_TCP
    if (option ==  PICO_TCP_NODELAY) {
        if (!value) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        if (s->proto->proto_number == PICO_PROTO_TCP) {
            int *val = (int*)value;
            if (*val > 0) {
                dbg("setsockopt: Nagle algorithm disabled.\n");
                PICO_SOCKET_SETOPT_EN(s, PICO_SOCKET_OPT_TCPNODELAY);
            } else {
                dbg("setsockopt: Nagle algorithm enabled.\n");
                PICO_SOCKET_SETOPT_DIS(s, PICO_SOCKET_OPT_TCPNODELAY);
            }
            return 0;
        } else {
            pico_err = PICO_ERR_EINVAL;
        }
    }
#endif
    return -1;
}
