/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_udp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_stack.h"


/* Queues */
static struct pico_queue udp_in = {
    0
};
static struct pico_queue udp_out = {
    0
};


/* Functions */

uint16_t pico_udp_checksum_ipv4(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_udp_hdr *udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    struct pico_socket *s = f->sock;
    struct pico_ipv4_pseudo_hdr pseudo;

    if (s) {
        /* Case of outgoing frame */
        /* dbg("UDP CRC: on outgoing frame\n"); */
        pseudo.src.addr = s->local_addr.ip4.addr;
        pseudo.dst.addr = s->remote_addr.ip4.addr;
    } else {
        /* Case of incomming frame */
        /* dbg("UDP CRC: on incomming frame\n"); */
        pseudo.src.addr = hdr->src.addr;
        pseudo.dst.addr = hdr->dst.addr;
    }

    pseudo.zeros = 0;
    pseudo.proto = PICO_PROTO_UDP;
    pseudo.len = short_be(f->transport_len);

    return pico_dualbuffer_checksum(&pseudo, sizeof(struct pico_ipv4_pseudo_hdr), udp_hdr, f->transport_len);
}


static int pico_udp_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    return pico_network_send(f);
}

static int pico_udp_push(struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_udp_hdr *hdr = (struct pico_udp_hdr *) f->transport_hdr;
    struct pico_remote_duple *remote_duple = (struct pico_remote_duple *) f->info;

    /* this (fragmented) frame should contain a transport header */
    if (f->transport_hdr != f->payload) {
        hdr->trans.sport = f->sock->local_port;
        if (remote_duple) {
            hdr->trans.dport = remote_duple->remote_port;
        } else {
            hdr->trans.dport = f->sock->remote_port;
        }

        hdr->len = short_be(f->transport_len);
        /* do not perform CRC validation. If you want to, a system needs to be
           implemented to calculate the CRC over the total payload of a
           fragmented payload */
        hdr->crc = 0;
    }

    if (pico_enqueue(self->q_out, f) > 0) {
        return f->payload_len;
    } else {
        return 0;
    }
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_udp = {
    .name = "udp",
    .proto_number = PICO_PROTO_UDP,
    .layer = PICO_LAYER_TRANSPORT,
    .process_in = pico_transport_process_in,
    .process_out = pico_udp_process_out,
    .push = pico_udp_push,
    .q_in = &udp_in,
    .q_out = &udp_out,
};


#define PICO_UDP_MODE_UNICAST 0x01
#define PICO_UDP_MODE_MULTICAST 0x02
#define PICO_UDP_MODE_BROADCAST 0xFF

struct pico_socket_udp
{
    struct pico_socket sock;
    int mode;
#ifdef PICO_SUPPORT_MCAST
    uint8_t mc_ttl; /* Multicasting TTL */
#endif
};

#ifdef PICO_SUPPORT_MCAST
int pico_udp_set_mc_ttl(struct pico_socket *s, uint8_t ttl)
{
    struct pico_socket_udp *u;
    if(!s) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    u = (struct pico_socket_udp *) s;
    u->mc_ttl = ttl;
    return 0;
}

int pico_udp_get_mc_ttl(struct pico_socket *s, uint8_t *ttl)
{
    struct pico_socket_udp *u;
    if(!s)
        return -1;

    u = (struct pico_socket_udp *) s;
    *ttl = u->mc_ttl;
    return 0;
}
#endif /* PICO_SUPPORT_MCAST */

struct pico_socket *pico_udp_open(void)
{
    struct pico_socket_udp *u = pico_zalloc(sizeof(struct pico_socket_udp));
    if (!u)
        return NULL;

    u->mode = PICO_UDP_MODE_UNICAST;

#ifdef PICO_SUPPORT_MCAST
    u->mc_ttl = PICO_IP_DEFAULT_MULTICAST_TTL;
    /* enable multicast loopback by default */
    u->sock.opt_flags |= (1 << PICO_SOCKET_OPT_MULTICAST_LOOP);
#endif

    return &u->sock;
}

uint16_t pico_udp_recv(struct pico_socket *s, void *buf, uint16_t len, void *src, uint16_t *port)
{
    struct pico_frame *f = pico_queue_peek(&s->q_in);
    if (f) {
        if(!f->payload_len) {
            f->payload = f->transport_hdr + sizeof(struct pico_udp_hdr);
            f->payload_len = (uint16_t)(f->transport_len - sizeof(struct pico_udp_hdr));
        }

/*    dbg("expected: %d, got: %d\n", len, f->payload_len); */
        if (src)
            pico_store_network_origin(src, f);

        if (port) {
            struct pico_trans *hdr = (struct pico_trans *)f->transport_hdr;
            *port = hdr->sport;
        }

        if (f->payload_len > len) {
            memcpy(buf, f->payload, len);
            f->payload += len;
            f->payload_len = (uint16_t)(f->payload_len - len);
            return len;
        } else {
            uint16_t ret = f->payload_len;
            memcpy(buf, f->payload, f->payload_len);
            f = pico_dequeue(&s->q_in);
            pico_frame_discard(f);
            return ret;
        }
    } else return 0;
}

