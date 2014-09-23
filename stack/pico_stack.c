/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_config.h"
#include "pico_frame.h"
#include "pico_device.h"
#include "pico_protocol.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_dns_client.h"

#include "pico_eth.h"
#include "pico_arp.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_icmp4.h"
#include "pico_icmp6.h"
#include "pico_igmp.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "heap.h"

#define IS_LIMITED_BCAST(f) (((struct pico_ipv4_hdr *) f->net_hdr)->dst.addr == PICO_IP4_BCAST)

const uint8_t PICO_ETHADDR_ALL[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

# define PICO_SIZE_MCAST 3
const uint8_t PICO_ETHADDR_MCAST[6] = {
    0x01, 0x00, 0x5e, 0x00, 0x00, 0x00
};

#ifdef PICO_SUPPORT_IPV6
# define PICO_SIZE_MCAST6 2
const uint8_t PICO_ETHADDR_MCAST6[6] = {
    0x33, 0x33, 0x00, 0x00, 0x00, 0x00
};
#endif


volatile pico_time pico_tick;
volatile pico_err_t pico_err;

static uint32_t _rand_seed;

void pico_rand_feed(uint32_t feed)
{
    if (!feed)
        return;

    _rand_seed *= 1664525;
    _rand_seed += 1013904223;
    _rand_seed ^= ~(feed);
}

uint32_t pico_rand(void)
{
    pico_rand_feed((uint32_t)pico_tick);
    return _rand_seed;
}

void pico_to_lowercase(char *str)
{
    int i = 0;
    if (!str)
        return;

    while(str[i]) {
        if ((str[i] <= 'Z') && (str[i] >= 'A'))
            str[i] = (char) (str[i] - (char)('A' - 'a'));

        i++;
    }
}

/* NOTIFICATIONS: distributed notifications for stack internal errors.
 */

int pico_notify_socket_unreachable(struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_port_unreachable(f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_port_unreachable(f);
    }
#endif

    return 0;
}

int pico_notify_proto_unreachable(struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_proto_unreachable(f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_proto_unreachable(f);
    }
#endif
    return 0;
}

int pico_notify_dest_unreachable(struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_dest_unreachable(f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_dest_unreachable(f);
    }
#endif
    return 0;
}

int pico_notify_ttl_expired(struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_ttl_expired(f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_ttl_expired(f);
    }
#endif
    return 0;
}


/* Transport layer */
int32_t pico_transport_receive(struct pico_frame *f, uint8_t proto)
{
    int32_t ret = -1;
    switch (proto) {

#ifdef PICO_SUPPORT_ICMP4
    case PICO_PROTO_ICMP4:
        ret = pico_enqueue(pico_proto_icmp4.q_in, f);
        break;
#endif

#ifdef PICO_SUPPORT_ICMP6
    case PICO_PROTO_ICMP6:
        ret = pico_enqueue(pico_proto_icmp6.q_in, f);
        break;
#endif


#ifdef PICO_SUPPORT_IGMP
    case PICO_PROTO_IGMP:
        ret = pico_enqueue(pico_proto_igmp.q_in, f);
        break;
#endif

#ifdef PICO_SUPPORT_UDP
    case PICO_PROTO_UDP:
        ret = pico_enqueue(pico_proto_udp.q_in, f);
        break;
#endif

#ifdef PICO_SUPPORT_TCP
    case PICO_PROTO_TCP:
        ret = pico_enqueue(pico_proto_tcp.q_in, f);
        break;
#endif

    default:
        /* Protocol not available */
        dbg("pkt: no such protocol (%d)\n", proto);
        pico_notify_proto_unreachable(f);
        pico_frame_discard(f);
        ret = -1;
    }
    return ret;
}

int32_t pico_network_receive(struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_IPV4
    else if (IS_IPV4(f)) {
        pico_enqueue(pico_proto_ipv4.q_in, f);
    }
#endif
#ifdef PICO_SUPPORT_IPV6
    else if (IS_IPV6(f)) {
        pico_enqueue(pico_proto_ipv6.q_in, f);
    }
#endif
    else {
        dbg("Network not found.\n");
        pico_frame_discard(f);
        return -1;
    }
    return (int32_t)f->buffer_len;
}

/* Network layer: interface towards socket for frame sending */
int32_t pico_network_send(struct pico_frame *f)
{
    if (!f || !f->sock || !f->sock->net) {
        pico_frame_discard(f);
        return -1;
    }

    return f->sock->net->push(f->sock->net, f);
}

int pico_source_is_local(struct pico_frame *f)
{
    if (0) { }

#ifdef PICO_SUPPORT_IPV4
    else if (IS_IPV4(f)) {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
        if (hdr->src.addr == PICO_IPV4_INADDR_ANY)
            return 1;

        if (pico_ipv4_link_find(&hdr->src))
            return 1;
    }
#endif
#ifdef PICO_SUPPORT_IPV6
    else if (IS_IPV6(f)) {
        struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        if (pico_ipv6_is_unspecified(hdr->src.addr) || pico_ipv6_link_find(&hdr->src))
            return 1;
    }
#endif
    return 0;
}

#ifdef PICO_SUPPORT_ETH
/* DATALINK LEVEL: interface from network to the device
 * and vice versa.
 */

/* The pico_ethernet_receive() function is used by
 * those devices supporting ETH in order to push packets up
 * into the stack.
 */

static int destination_is_bcast(struct pico_frame *f)
{
    if (!f)
        return 0;

    if (IS_IPV6(f))
        return 0;

#ifdef PICO_SUPPORT_IPV4
    else {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
        return pico_ipv4_is_broadcast(hdr->dst.addr);
    }
#else
    return 0;
#endif
}

static int destination_is_mcast(struct pico_frame *f)
{
    int ret = 0;
    if (!f)
        return 0;

#ifdef PICO_SUPPORT_IPV6
    if (IS_IPV6(f)) {
        struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *) f->net_hdr;
        ret = pico_ipv6_is_multicast(hdr->dst.addr);
    }

#endif
#ifdef PICO_SUPPORT_IPV4
    else {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
        ret = pico_ipv4_is_multicast(hdr->dst.addr);
    }
#endif

    return ret;
}

#ifdef PICO_SUPPORT_IPV4
static int32_t pico_ipv4_ethernet_receive(struct pico_frame *f)
{
    if (IS_IPV4(f)) {
        pico_enqueue(pico_proto_ipv4.q_in, f);
    } else {
        (void)pico_icmp4_param_problem(f, 0);
        pico_frame_discard(f);
        return -1;
    }
    return (int32_t)f->buffer_len;
}
#endif

#ifdef PICO_SUPPORT_IPV6
static int32_t pico_ipv6_ethernet_receive(struct pico_frame *f)
{
    if (IS_IPV6(f)) {
        pico_enqueue(pico_proto_ipv6.q_in, f);
    } else {
        /* Wrong version for link layer type */
        (void)pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_HDRFIELD, 0);
        pico_frame_discard(f);
        return -1;
    }
    return (int32_t)f->buffer_len;
}
#endif

static int32_t pico_ll_receive(struct pico_frame *f)
{
    struct pico_eth_hdr *hdr = (struct pico_eth_hdr *) f->datalink_hdr;
    f->net_hdr = f->datalink_hdr + sizeof(struct pico_eth_hdr);

#if (defined PICO_SUPPORT_IPV4) && (defined PICO_SUPPORT_ETH)
    if (hdr->proto == PICO_IDETH_ARP)
        return pico_arp_receive(f);
#endif

#if defined (PICO_SUPPORT_IPV4)
    if (hdr->proto == PICO_IDETH_IPV4)
        return pico_ipv4_ethernet_receive(f);
#endif

#if defined (PICO_SUPPORT_IPV6)
    if (hdr->proto == PICO_IDETH_IPV6)
        return pico_ipv6_ethernet_receive(f);
#endif

    pico_frame_discard(f);
    return -1;
}

static void pico_ll_check_bcast(struct pico_frame *f)
{
    struct pico_eth_hdr *hdr = (struct pico_eth_hdr *) f->datalink_hdr;
    /* Indicate a link layer broadcast packet */
    if (memcmp(hdr->daddr, PICO_ETHADDR_ALL, PICO_SIZE_ETH) == 0)
        f->flags |= PICO_FRAME_FLAG_BCAST;
}

int32_t pico_ethernet_receive(struct pico_frame *f)
{
    struct pico_eth_hdr *hdr;
    if (!f || !f->dev || !f->datalink_hdr)
    {
        pico_frame_discard(f);
        return -1;
    }

    hdr = (struct pico_eth_hdr *) f->datalink_hdr;
    if ((memcmp(hdr->daddr, f->dev->eth->mac.addr, PICO_SIZE_ETH) != 0) &&
        (memcmp(hdr->daddr, PICO_ETHADDR_MCAST, PICO_SIZE_MCAST) != 0) &&
#ifdef PICO_SUPPORT_IPV6
        (memcmp(hdr->daddr, PICO_ETHADDR_MCAST6, PICO_SIZE_MCAST6) != 0) &&
#endif
        (memcmp(hdr->daddr, PICO_ETHADDR_ALL, PICO_SIZE_ETH) != 0))
    {
        pico_frame_discard(f);
        return -1;
    }

    pico_ll_check_bcast(f);
    return pico_ll_receive(f);
}

struct pico_eth *pico_ethernet_mcast_translate(struct pico_frame *f, uint8_t *pico_mcast_mac)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

    /* place 23 lower bits of IP in lower 23 bits of MAC */
    pico_mcast_mac[5] = (long_be(hdr->dst.addr) & 0x000000FFu);
    pico_mcast_mac[4] = (uint8_t)((long_be(hdr->dst.addr) & 0x0000FF00u) >> 8u);
    pico_mcast_mac[3] = (uint8_t)((long_be(hdr->dst.addr) & 0x007F0000u) >> 16u);

    return (struct pico_eth *)pico_mcast_mac;
}


#ifdef PICO_SUPPORT_IPV6
struct pico_eth *pico_ethernet_mcast6_translate(struct pico_frame *f, uint8_t *pico_mcast6_mac)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;

    /* first 2 octets are 0x33, last four are the last four of dst */
    pico_mcast6_mac[5] = hdr->dst.addr[PICO_SIZE_IP6 - 1];
    pico_mcast6_mac[4] = hdr->dst.addr[PICO_SIZE_IP6 - 2];
    pico_mcast6_mac[3] = hdr->dst.addr[PICO_SIZE_IP6 - 3];
    pico_mcast6_mac[2] = hdr->dst.addr[PICO_SIZE_IP6 - 4];

    return (struct pico_eth *)pico_mcast6_mac;
}
#endif

struct pico_eth *pico_ethernet_ipv6_dst(struct pico_frame *f)
{
    struct pico_eth *dstmac = NULL;
    #ifdef PICO_SUPPORT_IPV6
    if (destination_is_mcast(f)) {
        uint8_t pico_mcast6_mac[6] = {
            0x33, 0x33, 0x00, 0x00, 0x00, 0x00
        };
        dstmac = pico_ethernet_mcast6_translate(f, pico_mcast6_mac);
    } else {
        dstmac = pico_ipv6_get_neighbor(f);
    }

    #else
    (void)f;
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    #endif
    return dstmac;
}



/* This is called by dev loop in order to ensure correct ethernet addressing.
 * Returns 0 if the destination is unknown, and -1 if the packet is not deliverable
 * due to ethernet addressing (i.e., no arp association was possible.
 *
 * Only IP packets must pass by this. ARP will always use direct dev->send() function, so
 * we assume IP is used.
 */

static int32_t pico_ethsend_local(struct pico_frame *f, struct pico_eth_hdr *hdr, int *ret)
{
    /* Check own mac */
    if(!memcmp(hdr->daddr, hdr->saddr, PICO_SIZE_ETH)) {
        dbg("sending out packet destined for our own mac\n");
        *ret = (int32_t)pico_ethernet_receive(f);
        return 1;
    }

    return 0;
}

static int32_t pico_ethsend_bcast(struct pico_frame *f, int *ret)
{
    if (IS_LIMITED_BCAST(f)) {
        *ret = pico_device_broadcast(f);
        return 1;
    }

    return 0;
}

static int32_t pico_ethsend_dispatch(struct pico_frame *f, int *ret)
{
    *ret = f->dev->send(f->dev, f->start, (int) f->len);
    if (*ret <= 0)
        return 0;
    else {
        pico_frame_discard(f);
        return 1;
    }
}




/* This function looks for the destination mac address
 * in order to send the frame being processed.
 */

int32_t MOCKABLE pico_ethernet_send(struct pico_frame *f)
{
    const struct pico_eth *dstmac = NULL;
    int ret = -1;
    uint16_t proto = PICO_IDETH_IPV4;



#ifdef PICO_SUPPORT_IPV6
    /* Step 1: If the frame has an IPv6 packet,
     * destination address is taken from the ND tables
     */
    if (IS_IPV6(f)) {
        dstmac = pico_ethernet_ipv6_dst(f);
        if (!dstmac) {
            /* When the dest mac is not available, frame is postponed.
             * ND is handling it now. No need to discard. */
            pico_ipv6_nd_postpone(f);
            return 0;
        }

        proto = PICO_IDETH_IPV6;
    }
    else
#endif

    /* In case of broadcast (IPV4 only), dst mac is FF:FF:... */
    if (IS_BCAST(f) || destination_is_bcast(f))
        dstmac = (const struct pico_eth *) PICO_ETHADDR_ALL;

    /* In case of multicast, dst mac is translated from the group address */
    else if (destination_is_mcast(f)) {
        uint8_t pico_mcast_mac[6] = {
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x00
        };
        dstmac = pico_ethernet_mcast_translate(f, pico_mcast_mac);
    }

#if (defined PICO_SUPPORT_IPV4)
    else {
        dstmac = pico_arp_get(f);
        /* At this point, ARP will discard the frame in any case.
         * It is safe to return without discarding.
         */
        if (!dstmac) {
            pico_arp_postpone(f);
            return 0;
        }
    }
#endif

    /* This sets destination and source address, then pushes the packet to the device. */
    if (dstmac && (f->start > f->buffer) && ((f->start - f->buffer) >= PICO_SIZE_ETHHDR)) {
        struct pico_eth_hdr *hdr;
        f->start -= PICO_SIZE_ETHHDR;
        f->len += PICO_SIZE_ETHHDR;
        f->datalink_hdr = f->start;
        hdr = (struct pico_eth_hdr *) f->datalink_hdr;
        memcpy(hdr->saddr, f->dev->eth->mac.addr, PICO_SIZE_ETH);
        memcpy(hdr->daddr, dstmac, PICO_SIZE_ETH);
        hdr->proto = proto;

        if (pico_ethsend_local(f, hdr, &ret) || pico_ethsend_bcast(f, &ret) || pico_ethsend_dispatch(f, &ret)) {
            /* one of the above functions has disposed of the frame accordingly. (returned != 0)
             * It is safe to directly return the number of bytes processed here.
             * */
            return (int32_t)ret;
        }
    }

    /* In all other cases,  it's up to us to get rid of the frame. */
    pico_frame_discard(f);
    return -1;
}

#endif /* PICO_SUPPORT_ETH */


void pico_store_network_origin(void *src, struct pico_frame *f)
{
  #ifdef PICO_SUPPORT_IPV4
    struct pico_ip4 *ip4;
  #endif

  #ifdef PICO_SUPPORT_IPV6
    struct pico_ip6 *ip6;
  #endif

  #ifdef PICO_SUPPORT_IPV4
    if (IS_IPV4(f)) {
        struct pico_ipv4_hdr *hdr;
        hdr = (struct pico_ipv4_hdr *) f->net_hdr;
        ip4 = (struct pico_ip4 *) src;
        ip4->addr = hdr->src.addr;
    }

  #endif
  #ifdef PICO_SUPPORT_IPV6
    if (IS_IPV6(f)) {
        struct pico_ipv6_hdr *hdr;
        hdr = (struct pico_ipv6_hdr *) f->net_hdr;
        ip6 = (struct pico_ip6 *) src;
        memcpy(ip6->addr, hdr->src.addr, PICO_SIZE_IP6);
    }

  #endif
}

int pico_address_compare(union pico_address *a, union pico_address *b, uint16_t proto)
{
    #ifdef PICO_SUPPORT_IPV6
    if (proto == PICO_PROTO_IPV6) {
        return pico_ipv6_compare(&a->ip6, &b->ip6);
    }

    #endif
    #ifdef PICO_SUPPORT_IPV4
    if (proto == PICO_PROTO_IPV4) {
        return pico_ipv4_compare(&a->ip4, &b->ip4);
    }

    #endif
    return 0;

}


/* LOWEST LEVEL: interface towards devices. */
/* Device driver will call this function which returns immediately.
 * Incoming packet will be processed later on in the dev loop.
 */
int32_t pico_stack_recv(struct pico_device *dev, uint8_t *buffer, uint32_t len)
{
    struct pico_frame *f;
    int32_t ret;
    if (len <= 0)
        return -1;

    f = pico_frame_alloc(len);
    if (!f)
    {
        dbg("Cannot alloc incoming frame!\n");
        return -1;
    }

    /* Association to the device that just received the frame. */
    f->dev = dev;

    /* Setup the start pointer, length. */
    f->start = f->buffer;
    f->len = f->buffer_len;
    if (f->len > 8) {
        uint32_t rand, mid_frame = (f->buffer_len >> 2) << 1;
        mid_frame -= (mid_frame % 4);
        memcpy(&rand, f->buffer + mid_frame, sizeof(uint32_t));
        pico_rand_feed(rand);
    }

    memcpy(f->buffer, buffer, len);
    ret = pico_enqueue(dev->q_in, f);
    if (ret <= 0) {
        pico_frame_discard(f);
    }

    return ret;
}

static int32_t _pico_stack_recv_zerocopy(struct pico_device *dev, uint8_t *buffer, uint32_t len, int ext_buffer)
{
    struct pico_frame *f;
    int ret;
    if (len <= 0)
        return -1;

    f = pico_frame_alloc_skeleton(len, ext_buffer);
    if (!f)
    {
        dbg("Cannot alloc incoming frame!\n");
        return -1;
    }

    if (pico_frame_skeleton_set_buffer(f, buffer) < 0)
    {
        dbg("Invalid zero-copy buffer!\n");
        PICO_FREE(f->usage_count);
        PICO_FREE(f);
        return -1;
    }

    f->dev = dev;
    ret = pico_enqueue(dev->q_in, f);
    if (ret <= 0) {
        pico_frame_discard(f);
    }

    return ret;
}

int32_t pico_stack_recv_zerocopy(struct pico_device *dev, uint8_t *buffer, uint32_t len)
{
    return _pico_stack_recv_zerocopy(dev, buffer, len, 0);
}

int32_t pico_stack_recv_zerocopy_ext_buffer(struct pico_device *dev, uint8_t *buffer, uint32_t len)
{
    return _pico_stack_recv_zerocopy(dev, buffer, len, 1);
}

int32_t pico_sendto_dev(struct pico_frame *f)
{
    if (!f->dev) {
        pico_frame_discard(f);
        return -1;
    } else {
        if (f->len > 8) {
            uint32_t rand, mid_frame = (f->buffer_len >> 2) << 1;
            mid_frame -= (mid_frame % 4);
            memcpy(&rand, f->buffer + mid_frame, sizeof(uint32_t));
            pico_rand_feed(rand);
        }

        return pico_enqueue(f->dev->q_out, f);
    }
}

struct pico_timer
{
    void *arg;
    void (*timer)(pico_time timestamp, void *arg);
};

struct pico_timer_ref
{
    pico_time expire;
    struct pico_timer *tmr;
};

typedef struct pico_timer_ref pico_timer_ref;

DECLARE_HEAP(pico_timer_ref, expire);

static heap_pico_timer_ref *Timers;

void pico_check_timers(void)
{
    struct pico_timer *t;
    struct pico_timer_ref tref_unused, *tref = heap_first(Timers);
    pico_tick = PICO_TIME_MS();
    while((tref) && (tref->expire < pico_tick)) {
        t = tref->tmr;
        if (t && t->timer)
            t->timer(pico_tick, t->arg);

        if (t)
            PICO_FREE(t);

        t = NULL;
        heap_peek(Timers, &tref_unused);
        tref = heap_first(Timers);
    }
}

void pico_timer_cancel(struct pico_timer *t)
{
    uint32_t i;
    struct pico_timer_ref *tref = Timers->top;
    if (!t)
        return;

    for (i = 1; i <= Timers->n; i++) {
        if (tref[i].tmr == t) {
            Timers->top[i].tmr = NULL;
            PICO_FREE(t);
            break;
        }
    }
}

#define PROTO_DEF_NR      11
#define PROTO_DEF_AVG_NR  4
#define PROTO_DEF_SCORE   32
#define PROTO_MIN_SCORE   32
#define PROTO_MAX_SCORE   128
#define PROTO_LAT_IND     3   /* latency indication 0-3 (lower is better latency performance), x1, x2, x4, x8 */
#define PROTO_MAX_LOOP    (PROTO_MAX_SCORE << PROTO_LAT_IND) /* max global loop score, so per tick */

static int calc_score(int *score, int *index, int avg[][PROTO_DEF_AVG_NR], int *ret)
{
    int temp, i, j, sum;
    int max_total = PROTO_MAX_LOOP, total = 0;

    /* dbg("USED SCORES> "); */

    for (i = 0; i < PROTO_DEF_NR; i++) {

        /* if used looped score */
        if (ret[i] < score[i]) {
            temp = score[i] - ret[i]; /* remaining loop score */

            /* dbg("%3d - ",temp); */

            if (index[i] >= PROTO_DEF_AVG_NR)
                index[i] = 0;   /* reset index */

            j = index[i];
            avg[i][j] = temp;

            index[i]++;

            if (ret[i] == 0 && ((score[i] * 2) <= PROTO_MAX_SCORE) && ((total + (score[i] * 2)) < max_total)) { /* used all loop score -> increase next score directly */
                score[i] *= 2;
                total += score[i];
                continue;
            }

            sum = 0;
            for (j = 0; j < PROTO_DEF_AVG_NR; j++)
                sum += avg[i][j]; /* calculate sum */

            sum /= 4;           /* divide by 4 to get average used score */

            /* criterion to increase next loop score */
            if (sum > (score[i] - (score[i] / 4))  && ((score[i] * 2) <= PROTO_MAX_SCORE) && ((total + (score[i] / 2)) < max_total)) { /* > 3/4 */
                score[i] *= 2; /* double loop score */
                total += score[i];
                continue;
            }

            /* criterion to decrease next loop score */
            if ((sum < (score[i] / 4)) && ((score[i] / 2) >= PROTO_MIN_SCORE)) { /* < 1/4 */
                score[i] /= 2; /* half loop score */
                total += score[i];
                continue;
            }

            /* also add non-changed scores */
            total += score[i];
        }
        else if (ret[i] == score[i]) {
            /* no used loop score - gradually decrease */

            /*  dbg("%3d - ",0); */

            if (index[i] >= PROTO_DEF_AVG_NR)
                index[i] = 0;   /* reset index */

            j = index[i];
            avg[i][j] = 0;

            index[i]++;

            sum = 0;
            for (j = 0; j < PROTO_DEF_AVG_NR; j++)
                sum += avg[i][j]; /* calculate sum */

            sum /= 2;          /* divide by 4 to get average used score */

            if ((sum == 0) && ((score[i] / 2) >= PROTO_MIN_SCORE)) {
                score[i] /= 2; /* half loop score */
                total += score[i];
                for (j = 0; j < PROTO_DEF_AVG_NR; j++)
                    avg[i][j] = score[i];
            }

        }
    }
    /* dbg("\n"); */

    return 0;
}



/*

         .
       .vS.
     <aoSo.
    .XoS22.
    .S2S22.             ._...              ......            ..._.
   :=|2S2X2|=++;      <vSX2XX2z+          |vSSSXSSs>.      :iXXZUZXXe=
   )2SS2SS2S2S2I    =oS2S2S2S2X22;.    _vuXS22S2S2S22i  ._wZZXZZZXZZXZX=
   )22S2S2S2S2Sl    |S2S2S22S2SSSXc:  .S2SS2S2S22S2SS= .]#XZZZXZXZZZZZZ:
   )oSS2SS2S2Sol     |2}!"""!32S22S(. uS2S2Se**12oS2e  ]dXZZXX2?YYXXXZ*
   .:2S2So:..-.      .      :]S2S2e;=X2SS2o     .)oc  ]XZZXZ(     =nX:
    .S2S22.          ___s_i,.)oS2So(;2SS2So,       `  3XZZZZc,      -
    .S2SSo.        =oXXXSSS2XoS2S2o( XS2S2XSos;.      ]ZZZZXXXX|=
    .S2S22.      .)S2S2S22S2S2S2S2o( "X2SS2S2S2Sus,,  +3XZZZZZXZZoos_
    .S2S22.     .]2S2SS22S222S2SS2o(  ]S22S2S2S222So   :3XXZZZZZZZZXXv
    .S2S22.     =u2SS2e"~---"{2S2So(   -"12S2S2SSS2Su.   "?SXXXZXZZZZXo
    .S2SSo.     )SS22z;      :S2S2o(       ={vS2S2S22v      .<vXZZZZZZZ;
    .S2S2S:     ]oSS2c;      =22S2o(          -"S2SS2n          ~4XXZXZ(
    .2S2S2i     )2S2S2[.    .)XS2So(  <;.      .2S2S2o :<.       ]XZZZX(
     nX2S2S,,_s_=3oSS2SoaasuXXS2S2o( .oXoasi_aioSSS22l.]dZoaas_aadXZZXZ'
     vS2SSSXXX2; )S2S2S2SoS2S2S2S2o( iS2S222XSoSS22So.)nXZZXXXZZXXZZXZo
     x32S22S2Sn  -+S2S2S2S2So22S2So( 12S2SS2S2SS22S}- )SXXZZZZZZZZZXX!-
      .)S22222i    .i2S2S2o>;:S2S2o(  .<vSoSoSo2S(;     :nXXXXXZXXX(
       .-~~~~-        --- .   - -        --~~~--           --^^~~-
                                  .


   ... curious about our source code? We are hiring! mailto:<recruiting@tass.be>


 */

void pico_stack_tick(void)
{
    static int score[PROTO_DEF_NR] = {
        PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE, PROTO_DEF_SCORE
    };
    static int index[PROTO_DEF_NR] = {
        0, 0, 0, 0, 0, 0
    };
    static int avg[PROTO_DEF_NR][PROTO_DEF_AVG_NR];
    static int ret[PROTO_DEF_NR] = {
        0
    };

    pico_check_timers();

    /* dbg("LOOP_SCORES> %3d - %3d - %3d - %3d - %3d - %3d - %3d - %3d - %3d - %3d - %3d\n",score[0],score[1],score[2],score[3],score[4],score[5],score[6],score[7],score[8],score[9],score[10]); */

    /* score = pico_protocols_loop(100); */

    ret[0] = pico_devices_loop(score[0], PICO_LOOP_DIR_IN);
    pico_rand_feed((uint32_t)ret[0]);

    ret[1] = pico_protocol_datalink_loop(score[1], PICO_LOOP_DIR_IN);
    pico_rand_feed((uint32_t)ret[1]);

    ret[2] = pico_protocol_network_loop(score[2], PICO_LOOP_DIR_IN);
    pico_rand_feed((uint32_t)ret[2]);

    ret[3] = pico_protocol_transport_loop(score[3], PICO_LOOP_DIR_IN);
    pico_rand_feed((uint32_t)ret[3]);


    ret[5] = score[5];
#if defined (PICO_SUPPORT_IPV4) || defined (PICO_SUPPORT_IPV6)
#if defined (PICO_SUPPORT_TCP) || defined (PICO_SUPPORT_UDP)
    ret[5] = pico_sockets_loop(score[5]); /* swapped */
    pico_rand_feed((uint32_t)ret[5]);
#endif
#endif

    ret[4] = pico_protocol_socket_loop(score[4], PICO_LOOP_DIR_IN);
    pico_rand_feed((uint32_t)ret[4]);


    ret[6] = pico_protocol_socket_loop(score[6], PICO_LOOP_DIR_OUT);
    pico_rand_feed((uint32_t)ret[6]);

    ret[7] = pico_protocol_transport_loop(score[7], PICO_LOOP_DIR_OUT);
    pico_rand_feed((uint32_t)ret[7]);

    ret[8] = pico_protocol_network_loop(score[8], PICO_LOOP_DIR_OUT);
    pico_rand_feed((uint32_t)ret[8]);

    ret[9] = pico_protocol_datalink_loop(score[9], PICO_LOOP_DIR_OUT);
    pico_rand_feed((uint32_t)ret[9]);

    ret[10] = pico_devices_loop(score[10], PICO_LOOP_DIR_OUT);
    pico_rand_feed((uint32_t)ret[10]);

    /* calculate new loop scores for next iteration */
    calc_score(score, index, (int (*)[])avg, ret);
}

void pico_stack_loop(void)
{
    while(1) {
        pico_stack_tick();
        PICO_IDLE();
    }
}

MOCKABLE struct pico_timer *pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    struct pico_timer *t = PICO_ZALLOC(sizeof(struct pico_timer));
    struct pico_timer_ref tref;
    if (!t) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    tref.expire = PICO_TIME_MS() + expire;
    t->arg = arg;
    t->timer = timer;
    tref.tmr = t;
    heap_insert(Timers, &tref);
    if (Timers->n > PICO_MAX_TIMERS) {
        dbg("Warning: I have %d timers\n", (int)Timers->n);
    }

    return t;
}

int pico_stack_init(void)
{

#ifdef PICO_SUPPORT_IPV4
    pico_protocol_init(&pico_proto_ipv4);
#endif

#ifdef PICO_SUPPORT_IPV6
    pico_protocol_init(&pico_proto_ipv6);
#endif

#ifdef PICO_SUPPORT_ICMP4
    pico_protocol_init(&pico_proto_icmp4);
#endif

#ifdef PICO_SUPPORT_ICMP6
    pico_protocol_init(&pico_proto_icmp6);
#endif

#ifdef PICO_SUPPORT_IGMP
    pico_protocol_init(&pico_proto_igmp);
#endif

#ifdef PICO_SUPPORT_UDP
    pico_protocol_init(&pico_proto_udp);
#endif

#ifdef PICO_SUPPORT_TCP
    pico_protocol_init(&pico_proto_tcp);
#endif

#ifdef PICO_SUPPORT_DNS_CLIENT
    pico_dns_client_init();
#endif

    pico_rand_feed(123456);

    /* Initialize timer heap */
    Timers = heap_init();
    if (!Timers)
        return -1;

#if ((defined PICO_SUPPORT_IPV4) && (defined PICO_SUPPORT_ETH))
    /* Initialize ARP module */
    pico_arp_init();
#endif

#ifdef PICO_SUPPORT_IPV6
    /* Initialize Neighbor discovery module */
    pico_ipv6_nd_init();
#endif
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    return 0;
}

