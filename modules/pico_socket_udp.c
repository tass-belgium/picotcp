#include <stdint.h>
#include "pico_socket.h"
#include "pico_udp.h"

#define UDP_FRAME_OVERHEAD (sizeof(struct pico_frame))


struct pico_socket *pico_socket_udp_open(void)
{
    struct pico_socket *s = NULL;
#ifdef PICO_SUPPORT_UDP
    s = pico_udp_open();
    s->proto = &pico_proto_udp;
    s->q_in.overhead = s->q_out.overhead = UDP_FRAME_OVERHEAD;
#endif
    return s;
}
