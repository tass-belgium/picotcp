#include <stdint.h>
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_tcp.h"

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

void pico_socket_tcp_cleanup(struct pico_socket *sock)
{
#ifdef PICO_SUPPORT_TCP
    /* for tcp sockets go further and clean the sockets inside queue */
    if(sock->proto == &pico_proto_tcp)
        pico_tcp_cleanup_queues(sock);

#endif
}


void pico_socket_tcp_delete(struct pico_socket *s)
{
#ifdef PICO_SUPPORT_TCP
    if(s->parent)
        s->parent->number_of_pending_conn--;

#endif
}

int pico_socket_tcp_deliver(struct pico_sockport *sp, struct pico_frame *f)
{
    struct pico_socket *found = NULL;
    struct pico_tree_node *index = NULL;
    struct pico_tree_node *_tmp;
    struct pico_trans *tr = (struct pico_trans *) f->transport_hdr;
    struct pico_socket *s = NULL;


    pico_tree_foreach_safe(index, &sp->socks, _tmp){
        s = index->keyValue;
        /* 4-tuple identification of socket (port-IP) */
        #ifdef PICO_SUPPORT_IPV4
        if (IS_IPV4(f)) {
            struct pico_ip4 s_local, s_remote, p_src, p_dst;
            struct pico_ipv4_hdr *ip4hdr = (struct pico_ipv4_hdr*)(f->net_hdr);
            s_local.addr = s->local_addr.ip4.addr;
            s_remote.addr = s->remote_addr.ip4.addr;
            p_src.addr = ip4hdr->src.addr;
            p_dst.addr = ip4hdr->dst.addr;
            if ((s->remote_port == tr->sport) && /* remote port check */
                (s_remote.addr == p_src.addr) && /* remote addr check */
                ((s_local.addr == PICO_IPV4_INADDR_ANY) || (s_local.addr == p_dst.addr))) { /* Either local socket is ANY, or matches dst */
                found = s;
                break;
            } else if ((s->remote_port == 0)  && /* not connected... listening */
                       ((s_local.addr == PICO_IPV4_INADDR_ANY) || (s_local.addr == p_dst.addr))) { /* Either local socket is ANY, or matches dst */
                /* listen socket */
                found = s;
            }
        }

        #endif
        #ifdef PICO_SUPPORT_IPV6
        if (IS_IPV6(f)) {
            struct pico_ipv6_hdr *ip6hdr = (struct pico_ipv6_hdr*)(f->net_hdr);
            if ((s->remote_port == localport)) {
                found = s;
                break;
            } else if (s->remote_port == 0) {
                /* listen socket */
                found = s;
            }
        }

        #endif
    } /* FOREACH */
    if (found != NULL) {
        pico_tcp_input(found, f);
        if ((found->ev_pending) && found->wakeup) {
            found->wakeup(found->ev_pending, found);
            if(!found->parent)
                found->ev_pending = 0;
        }

        return 0;
    } else {
        dbg("TCP SOCKET> Not found.\n");
        return -1;
    }
}

struct pico_socket *pico_socket_tcp_open(void)
{
    struct pico_socket *s = NULL;
#ifdef PICO_SUPPORT_TCP
    s = pico_tcp_open();
    if (!s) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    s->proto = &pico_proto_tcp;
    /*check if Nagle enabled */
    /*
       if (!IS_NAGLE_ENABLED(s))
           dbg("ERROR Nagle should be enabled here\n\n");
     */
#endif
    return s;
}

int pico_socket_tcp_read(struct pico_socket *s, void *buf, uint32_t len)
{
#ifdef PICO_SUPPORT_TCP
    /* check if in shutdown state and if no more data in tcpq_in */
    if ((s->state & PICO_SOCKET_STATE_SHUT_REMOTE) && pico_tcp_queue_in_is_empty(s)) {
        pico_err = PICO_ERR_ESHUTDOWN;
        return -1;
    } else {
        return (int)(pico_tcp_read(s, buf, (uint32_t)len));
    }

#endif
    return 0;
}
