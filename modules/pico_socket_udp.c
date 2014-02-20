#include <stdint.h>
#include "pico_socket.h"
#include "pico_udp.h"
#include "pico_socket_multicast.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"

#define UDP_FRAME_OVERHEAD (sizeof(struct pico_frame))


struct pico_socket *pico_socket_udp_open(void)
{
    struct pico_socket *s = NULL;
#ifdef PICO_SUPPORT_UDP
    s = pico_udp_open();
    if (!s) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    s->proto = &pico_proto_udp;
    s->q_in.overhead = s->q_out.overhead = UDP_FRAME_OVERHEAD;
#endif
    return s;
}


#ifdef PICO_SUPPORT_IPV4
static int pico_socket_udp_deliver_ipv4(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_ip4 s_local, p_dst;
    struct pico_ipv4_hdr *ip4hdr;
    struct pico_frame *cpy;
    ip4hdr = (struct pico_ipv4_hdr*)(f->net_hdr);
    s_local.addr = s->local_addr.ip4.addr;
    p_dst.addr = ip4hdr->dst.addr;
    if ((pico_ipv4_is_broadcast(p_dst.addr)) || pico_ipv4_is_multicast(p_dst.addr)) {
        struct pico_device *dev = pico_ipv4_link_find(&s->local_addr.ip4);
        if (pico_ipv4_is_multicast(p_dst.addr) && (pico_socket_mcast_filter(s, &ip4hdr->dst, &ip4hdr->src) < 0))
            return -1;

        if ((s_local.addr == PICO_IPV4_INADDR_ANY) || /* If our local ip is ANY, or.. */
            (dev == f->dev)) { /* the source of the bcast packet is a neighbor... */
            cpy = pico_frame_copy(f);
            if (!cpy)
                return -1;

            if (pico_enqueue(&s->q_in, cpy) > 0) {
                if (s->wakeup)
                    s->wakeup(PICO_SOCK_EV_RD, s);
            }
            else
                pico_frame_discard(cpy);

        }
    } else if ((s_local.addr == PICO_IPV4_INADDR_ANY) || (s_local.addr == p_dst.addr))
    { /* Either local socket is ANY, or matches dst */
        cpy = pico_frame_copy(f);
        if (!cpy)
            return -1;

        if (pico_enqueue(&s->q_in, cpy) > 0) {
            if (s->wakeup)
                s->wakeup(PICO_SOCK_EV_RD, s);
        }
    }

    pico_frame_discard(f);
    return 0;
}
#endif

#ifdef PICO_SUPPORT_IPV6
static int pico_socket_udp_deliver_ipv6(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_ip6 s_local, p_dst;
    struct pico_ipv6_hdr *ip6hdr;
    struct pico_frame *cpy;
    ip6hdr = (struct pico_ipv6_hdr*)(f->net_hdr);
    s_local = s->local_addr.ip6;
    p_dst = ip6hdr->dst;
    if ((pico_ipv6_is_multicast(p_dst.addr))) {
        cpy = pico_frame_copy(f);
        if (!cpy)
            return -1;

        if (pico_enqueue(&s->q_in, cpy) > 0) {
            if (s->wakeup)
                s->wakeup(PICO_SOCK_EV_RD, s);
        }
        else
            pico_frame_discard(cpy);
    } else if (pico_ipv6_is_unspecified(s->local_addr.ip6.addr) || (pico_ipv6_compare(&s_local, &p_dst) == 0))
    { /* Either local socket is ANY, or matches dst */
        cpy = pico_frame_copy(f);
        if (!cpy)
            return -1;

        if (pico_enqueue(&s->q_in, cpy) > 0) {
            if (s->wakeup)
                s->wakeup(PICO_SOCK_EV_RD, s);
        }
    }

    pico_frame_discard(f);
    return 0;
}
#endif


int pico_socket_udp_deliver(struct pico_sockport *sp, struct pico_frame *f)
{
    struct pico_tree_node *index = NULL;
    struct pico_tree_node *_tmp;
    struct pico_socket *s = NULL;
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    #ifdef PICO_SUPPORT_UDP
    pico_err = PICO_ERR_NOERR;
    pico_tree_foreach_safe(index, &sp->socks, _tmp){
        s = index->keyValue;
        if (IS_IPV4(f)) { /* IPV4 */
#ifdef PICO_SUPPORT_IPV4
            return pico_socket_udp_deliver_ipv4(s, f);
#endif
        } else {
#ifdef PICO_SUPPORT_IPV6
            return pico_socket_udp_deliver_ipv6(s, f);
#endif
        }
    } /* FOREACH */
    pico_frame_discard(f);
    if (s)
        return 0;

    pico_err = PICO_ERR_ENXIO;
  #endif
    return -1;
}
