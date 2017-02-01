/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   .

   Authors: Kristof Roelants, Brecht Van Cauwenberghe,
         Simon Maes, Philippe Mariman
 *********************************************************************/

#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_tcp.h"
#include "pico_udp.h"
#include "pico_ipv4.h"
#include "pico_addressing.h"
#include "pico_nat.h"

#ifdef PICO_SUPPORT_IPV4
#ifdef PICO_SUPPORT_NAT

#ifdef DEBUG_NAT
#define nat_dbg dbg
#else
#define nat_dbg(...) do {} while(0)
#endif

#define PICO_NAT_TIMEWAIT  240000 /* msec (4 mins) */

#define PICO_NAT_INBOUND   0
#define PICO_NAT_OUTBOUND  1

struct pico_nat_tuple {
    uint8_t proto;
    uint16_t conn_active : 11;
    uint16_t portforward : 1;
    uint16_t rst : 1;
    uint16_t syn : 1;
    uint16_t fin_in : 1;
    uint16_t fin_out : 1;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t nat_port;
    struct pico_ip4 src_addr;
    struct pico_ip4 dst_addr;
    struct pico_ip4 nat_addr;
};

static struct pico_ipv4_link *nat_link = NULL;

static int nat_cmp_natport(struct pico_nat_tuple *a, struct pico_nat_tuple *b)
{

    if (a->nat_port < b->nat_port)
        return -1;

    if (a->nat_port > b->nat_port)

        return 1;

    return 0;

}

static int nat_cmp_srcport(struct pico_nat_tuple *a, struct pico_nat_tuple *b)
{

    if (a->src_port < b->src_port)
        return -1;

    if (a->src_port > b->src_port)

        return 1;

    return 0;

}

static int nat_cmp_proto(struct pico_nat_tuple *a, struct pico_nat_tuple *b)
{
    if (a->proto < b->proto)
        return -1;

    if (a->proto > b->proto)
        return 1;

    return 0;
}

static int nat_cmp_address(struct pico_nat_tuple *a, struct pico_nat_tuple *b)
{
    return pico_ipv4_compare(&a->src_addr, &b->src_addr);
}

static int nat_cmp_inbound(void *ka, void *kb)
{
    struct pico_nat_tuple *a = ka, *b = kb;
    int cport = nat_cmp_natport(a, b);
    if (cport)
        return cport;

    return nat_cmp_proto(a, b);
}


static int nat_cmp_outbound(void *ka, void *kb)
{
    struct pico_nat_tuple *a = ka, *b = kb;
    int caddr, cport;

    caddr = nat_cmp_address(a, b);
    if (caddr)
        return caddr;

    cport = nat_cmp_srcport(a, b);

    if (cport)
        return cport;

    return nat_cmp_proto(a, b);
}

static PICO_TREE_DECLARE(NATOutbound, nat_cmp_outbound);
static PICO_TREE_DECLARE(NATInbound, nat_cmp_inbound);

void pico_ipv4_nat_print_table(void)
{
    struct pico_nat_tuple *t = NULL;
    struct pico_tree_node *index = NULL;
    (void)t;

    nat_dbg("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    nat_dbg("+                                                        NAT table                                                       +\n");
    nat_dbg("+------------------------------------------------------------------------------------------------------------------------+\n");
    nat_dbg("+ src_addr | src_port | dst_addr | dst_port | nat_addr | nat_port | proto | conn active | FIN1 | FIN2 | SYN | RST | FORW +\n");
    nat_dbg("+------------------------------------------------------------------------------------------------------------------------+\n");

    pico_tree_foreach(index, &NATOutbound)
    {
        t = index->keyValue;
        nat_dbg("+ %08X |  %05u   | %08X |  %05u   | %08X |  %05u   |  %03u  |     %03u     |   %u  |   %u  |  %u  |  %u  |   %u  +\n",
                long_be(t->src_addr.addr), t->src_port, long_be(t->dst_addr.addr), t->dst_port, long_be(t->nat_addr.addr), t->nat_port,
                t->proto, t->conn_active, t->fin_in, t->fin_out, t->syn, t->rst, t->portforward);
    }
    nat_dbg("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

/*
   2 options:
    find on nat_port and proto
    find on src_addr, src_port and proto
   zero the unused parameters
 */
static struct pico_nat_tuple *pico_ipv4_nat_find_tuple(uint16_t nat_port, struct pico_ip4 *src_addr, uint16_t src_port, uint8_t proto)
{
    struct pico_nat_tuple *found = NULL, test = {
        0
    };

    test.nat_port = nat_port;
    test.src_port = src_port;
    test.proto = proto;
    if (src_addr)
        test.src_addr = *src_addr;

    if (nat_port)
        found = pico_tree_findKey(&NATInbound, &test);
    else
        found = pico_tree_findKey(&NATOutbound, &test);

    if (found)
        return found;
    else
        return NULL;
}

int pico_ipv4_nat_find(uint16_t nat_port, struct pico_ip4 *src_addr, uint16_t src_port, uint8_t proto)
{
    struct pico_nat_tuple *t = NULL;

    t = pico_ipv4_nat_find_tuple(nat_port, src_addr, src_port, proto);
    if (t)
        return 1;
    else
        return 0;
}

static struct pico_nat_tuple *pico_ipv4_nat_add(struct pico_ip4 dst_addr, uint16_t dst_port, struct pico_ip4 src_addr, uint16_t src_port,
                                                struct pico_ip4 nat_addr, uint16_t nat_port, uint8_t proto)
{
    struct pico_nat_tuple *t = PICO_ZALLOC(sizeof(struct pico_nat_tuple));
    if (!t) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    t->dst_addr = dst_addr;
    t->dst_port = dst_port;
    t->src_addr = src_addr;
    t->src_port = src_port;
    t->nat_addr = nat_addr;
    t->nat_port = nat_port;
    t->proto = proto;
    t->conn_active = 1;
    t->portforward = 0;
    t->rst = 0;
    t->syn = 0;
    t->fin_in = 0;
    t->fin_out = 0;

    if (pico_tree_insert(&NATOutbound, t)) {
        PICO_FREE(t);
        return NULL;
    }

    if (pico_tree_insert(&NATInbound, t)) {
        pico_tree_delete(&NATOutbound, t);
        PICO_FREE(t);
        return NULL;
    }

    return t;
}

static int pico_ipv4_nat_del(uint16_t nat_port, uint8_t proto)
{
    struct pico_nat_tuple *t = NULL;
    t = pico_ipv4_nat_find_tuple(nat_port, NULL, 0, proto);
    if (t) {
        pico_tree_delete(&NATOutbound, t);
        pico_tree_delete(&NATInbound, t);
        PICO_FREE(t);
    }

    return 0;
}

static struct pico_trans *pico_nat_generate_tuple_trans(struct pico_ipv4_hdr *net, struct pico_frame *f)
{
    struct pico_trans *trans = NULL;
    switch (net->proto) {
    case PICO_PROTO_TCP:
    {
        struct pico_tcp_hdr *tcp = (struct pico_tcp_hdr *)f->transport_hdr;
        trans = (struct pico_trans *)&tcp->trans;
        break;
    }
    case PICO_PROTO_UDP:
    {
        struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
        trans = (struct pico_trans *)&udp->trans;
        break;
    }
    case PICO_PROTO_ICMP4:
        /* XXX: implement */
        break;
    }
    return trans;
}

static struct pico_nat_tuple *pico_ipv4_nat_generate_tuple(struct pico_frame *f)
{
    struct pico_trans *trans = NULL;
    struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;
    uint16_t nport = 0;
    uint8_t retry = 32;

    /* generate NAT port */
    do {
        uint32_t rand = pico_rand();
        nport = (uint16_t) (rand & 0xFFFFU);
        nport = (uint16_t)((nport % (65535 - 1024)) + 1024U);
        nport = short_be(nport);

        if (pico_is_port_free(net->proto, nport, NULL, &pico_proto_ipv4))
            break;
    } while (--retry);

    if (!retry)
        return NULL;

    trans = pico_nat_generate_tuple_trans(net, f);
    if(!trans)
        return NULL;

    return pico_ipv4_nat_add(net->dst, trans->dport, net->src, trans->sport, nat_link->address, nport, net->proto);
    /* XXX return pico_ipv4_nat_add(nat_link->address, port, net->src, trans->sport, net->proto); */
}

static inline void pico_ipv4_nat_set_tcp_flags(struct pico_nat_tuple *t, struct pico_frame *f, uint8_t direction)
{
    struct pico_tcp_hdr *tcp = (struct pico_tcp_hdr *)f->transport_hdr;
    if (tcp->flags & PICO_TCP_SYN)
        t->syn = 1;

    if (tcp->flags & PICO_TCP_RST)
        t->rst = 1;

    if ((tcp->flags & PICO_TCP_FIN) && (direction == PICO_NAT_INBOUND))
        t->fin_in = 1;

    if ((tcp->flags & PICO_TCP_FIN) && (direction == PICO_NAT_OUTBOUND))
        t->fin_out = 1;
}

static int pico_ipv4_nat_sniff_session(struct pico_nat_tuple *t, struct pico_frame *f, uint8_t direction)
{
    struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;

    switch (net->proto) {
    case PICO_PROTO_TCP:
    {
        pico_ipv4_nat_set_tcp_flags(t, f, direction);
        break;
    }

    case PICO_PROTO_UDP:
        t->conn_active = 1;
        break;

    case PICO_PROTO_ICMP4:
        /* XXX: implement */
        break;

    default:
        return -1;
    }

    return 0;
}

static void pico_ipv4_nat_table_cleanup(pico_time now, void *_unused)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_nat_tuple *t = NULL;
    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(_unused);
    nat_dbg("NAT: before table cleanup:\n");
    pico_ipv4_nat_print_table();

    pico_tree_foreach_reverse_safe(index, &NATOutbound, _tmp)
    {
        t = index->keyValue;
        switch (t->proto)
        {
        case PICO_PROTO_TCP:
            if (t->portforward)
                break;
            else if (t->conn_active == 0 || t->conn_active > 360) /* conn active for > 24 hours */
                pico_ipv4_nat_del(t->nat_port, t->proto);
            else if (t->rst || (t->fin_in && t->fin_out))
                t->conn_active = 0;
            else
                t->conn_active++;

            break;

        case PICO_PROTO_UDP:
            if (t->portforward)
                break;
            else if (t->conn_active > 1)
                pico_ipv4_nat_del(t->nat_port, t->proto);
            else
                t->conn_active++;

            break;

        case PICO_PROTO_ICMP4:
            if (t->conn_active > 1)
                pico_ipv4_nat_del(t->nat_port, t->proto);
            else
                t->conn_active++;
            break;

        default:
            /* unknown protocol in NAT table, delete when it has existed NAT_TIMEWAIT */
            if (t->conn_active > 1)
                pico_ipv4_nat_del(t->nat_port, t->proto);
            else
                t->conn_active++;
        }
    }

    nat_dbg("NAT: after table cleanup:\n");
    pico_ipv4_nat_print_table();
    if (!pico_timer_add(PICO_NAT_TIMEWAIT, pico_ipv4_nat_table_cleanup, NULL)) {
        nat_dbg("NAT: Failed to start cleanup timer\n");
        /* TODO no more NAT table cleanup now */
    }
}

int pico_ipv4_port_forward(struct pico_ip4 nat_addr, uint16_t nat_port, struct pico_ip4 src_addr, uint16_t src_port, uint8_t proto, uint8_t flag)
{
    struct pico_nat_tuple *t = NULL;
    struct pico_ip4 any_addr = {
        0
    };
    uint16_t any_port = 0;

    switch (flag)
    {
    case PICO_NAT_PORT_FORWARD_ADD:
        t = pico_ipv4_nat_add(any_addr, any_port, src_addr, src_port, nat_addr, nat_port, proto);
        if (!t) {
            pico_err = PICO_ERR_EAGAIN;
            return -1;
        }

        t->portforward = 1;
        break;

    case PICO_NAT_PORT_FORWARD_DEL:
        return pico_ipv4_nat_del(nat_port, proto);

    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    pico_ipv4_nat_print_table();
    return 0;
}

int pico_ipv4_nat_inbound(struct pico_frame *f, struct pico_ip4 *link_addr)
{
    struct pico_nat_tuple *tuple = NULL;
    struct pico_trans *trans = NULL;
    struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;

    if (!pico_ipv4_nat_is_enabled(link_addr))
        return -1;

    switch (net->proto) {
#ifdef PICO_SUPPORT_TCP
    case PICO_PROTO_TCP:
    {
        struct pico_tcp_hdr *tcp = (struct pico_tcp_hdr *)f->transport_hdr;
        trans = (struct pico_trans *)&tcp->trans;
        tuple = pico_ipv4_nat_find_tuple(trans->dport, 0, 0, net->proto);
        if (!tuple)
            return -1;

        /* replace dst IP and dst PORT */
        net->dst = tuple->src_addr;
        trans->dport = tuple->src_port;
        /* recalculate CRC */
        tcp->crc = 0;
        tcp->crc = short_be(pico_tcp_checksum_ipv4(f));
        break;
    }
#endif
#ifdef PICO_SUPPORT_UDP
    case PICO_PROTO_UDP:
    {
        struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
        trans = (struct pico_trans *)&udp->trans;
        tuple = pico_ipv4_nat_find_tuple(trans->dport, 0, 0, net->proto);
        if (!tuple)
            return -1;

        /* replace dst IP and dst PORT */
        net->dst = tuple->src_addr;
        trans->dport = tuple->src_port;
        /* recalculate CRC */
        udp->crc = 0;
        udp->crc = short_be(pico_udp_checksum_ipv4(f));
        break;
    }
#endif
    case PICO_PROTO_ICMP4:
        /* XXX reimplement */
        break;

    default:
        nat_dbg("NAT ERROR: inbound NAT on erroneous protocol\n");
        return -1;
    }

    pico_ipv4_nat_sniff_session(tuple, f, PICO_NAT_INBOUND);
    net->crc = 0;
    net->crc = short_be(pico_checksum(net, f->net_len));

    nat_dbg("NAT: inbound translation {dst.addr, dport}: {%08X,%u} -> {%08X,%u}\n",
            tuple->nat_addr.addr, short_be(tuple->nat_port), tuple->src_addr.addr, short_be(tuple->src_port));

    return 0;
}

int pico_ipv4_nat_outbound(struct pico_frame *f, struct pico_ip4 *link_addr)
{
    struct pico_nat_tuple *tuple = NULL;
    struct pico_trans *trans = NULL;
    struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;

    if (!pico_ipv4_nat_is_enabled(link_addr))
        return -1;

    switch (net->proto) {
#ifdef PICO_SUPPORT_TCP
    case PICO_PROTO_TCP:
    {
        struct pico_tcp_hdr *tcp = (struct pico_tcp_hdr *)f->transport_hdr;
        trans = (struct pico_trans *)&tcp->trans;
        tuple = pico_ipv4_nat_find_tuple(0, &net->src, trans->sport, net->proto);
        if (!tuple)
            tuple = pico_ipv4_nat_generate_tuple(f);

        /* replace src IP and src PORT */
        net->src = tuple->nat_addr;
        trans->sport = tuple->nat_port;
        /* recalculate CRC */
        tcp->crc = 0;
        tcp->crc = short_be(pico_tcp_checksum_ipv4(f));
        break;
    }
#endif
#ifdef PICO_SUPPORT_UDP
    case PICO_PROTO_UDP:
    {
        struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
        trans = (struct pico_trans *)&udp->trans;
        tuple = pico_ipv4_nat_find_tuple(0, &net->src, trans->sport, net->proto);
        if (!tuple)
            tuple = pico_ipv4_nat_generate_tuple(f);

        /* replace src IP and src PORT */
        net->src = tuple->nat_addr;
        trans->sport = tuple->nat_port;
        /* recalculate CRC */
        udp->crc = 0;
        udp->crc = short_be(pico_udp_checksum_ipv4(f));
        break;
    }
#endif
    case PICO_PROTO_ICMP4:
        /* XXX reimplement */
        break;

    default:
        nat_dbg("NAT ERROR: outbound NAT on erroneous protocol\n");
        return -1;
    }

    pico_ipv4_nat_sniff_session(tuple, f, PICO_NAT_OUTBOUND);
    net->crc = 0;
    net->crc = short_be(pico_checksum(net, f->net_len));

    nat_dbg("NAT: outbound translation {src.addr, sport}: {%08X,%u} -> {%08X,%u}\n",
            tuple->src_addr.addr, short_be(tuple->src_port), tuple->nat_addr.addr, short_be(tuple->nat_port));

    return 0;
}

int pico_ipv4_nat_enable(struct pico_ipv4_link *link)
{
    if (link == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (!pico_timer_add(PICO_NAT_TIMEWAIT, pico_ipv4_nat_table_cleanup, NULL)) {
        nat_dbg("NAT: Failed to start cleanup timer\n");
        return -1;
    }

    nat_link = link;

    return 0;
}

int pico_ipv4_nat_disable(void)
{
    nat_link = NULL;
    return 0;
}

int pico_ipv4_nat_is_enabled(struct pico_ip4 *link_addr)
{
    if (!nat_link)
        return 0;

    if (nat_link->address.addr != link_addr->addr)
        return 0;

    return 1;
}

#endif
#endif
