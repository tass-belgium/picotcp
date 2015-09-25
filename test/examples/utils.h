#ifndef PICO_EXAMPLES_UTILS_H
#define PICO_EXAMPLES_UTILS_H
#include <pico_stack.h>
#define TCPSIZ (1024 * 1024 * 5)
extern struct pico_ip4 ZERO_IP4;
extern struct pico_ip_mreq ZERO_MREQ;
extern struct pico_ip_mreq_source ZERO_MREQ_SRC;
extern struct pico_ip6 ZERO_IP6;
extern struct pico_ip_mreq ZERO_MREQ_IP6;
extern struct pico_ip_mreq_source ZERO_MREQ_SRC_IP6;
#define picoapp_dbg(...) do {} while(0)
/* #define picoapp_dbg printf */
extern int IPV6_MODE;


extern struct pico_ip4 inaddr_any;
extern struct pico_ip6 inaddr6_any;

extern char *cpy_arg(char **dst, char *str);

extern void deferred_exit(pico_time now, void *arg);

struct udpclient_pas {
    struct pico_socket *s;
    uint8_t loops;
    uint8_t subloops;
    uint16_t datasize;
    uint16_t sport;
    union pico_address dst;
}; /* per application struct */

struct udpecho_pas {
    struct pico_socket *s;
    uint16_t sendto_port; /* big-endian */
    uint16_t datasize;
}; /* per application struct */


#endif
