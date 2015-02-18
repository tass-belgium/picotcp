/*********************************************************************
   PicoTCP. Copyright (c) 2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

  Author: Daniele Lacamera <daniele.lacamera@altran.com>
 *********************************************************************/
#include <pico_stack.h>
#include <pico_tree.h>
#include <pico_socket.h>
#include <pico_aodv.h>
#include <pico_device.h>

#include <pico_ipv4.h>
#define AODV_MAX_PKT (64)
static const struct pico_ip4 HOST_NETMASK = {
    0xffffffff
};

static const struct pico_ip4 ANY_HOST = {
    0x0
};

static uint32_t pico_aodv_local_id = 0;

static int aodv_node_compare(void *ka, void *kb)
{
    struct pico_aodv_node *a = ka, *b = kb;
    if (a->dest.ip4.addr < b->dest.ip4.addr)
        return -1;
    if (b->dest.ip4.addr < a->dest.ip4.addr)
        return 1;
    return 0;
}

static int aodv_dev_cmp(void *ka, void *kb)
{
    struct pico_device *a = ka, *b = kb;
    if (a->hash < b->hash)
        return -1;

    if (a->hash > b->hash)
        return 1;

    return 0;
}

PICO_TREE_DECLARE(aodv_nodes, aodv_node_compare);
PICO_TREE_DECLARE(aodv_devices, aodv_dev_cmp);

static struct pico_socket *aodv_socket = NULL;

static struct pico_aodv_node *get_node_by_addr(const union pico_address *addr)
{
    struct pico_aodv_node search;
    memcpy(&search.dest, addr, sizeof(union pico_address));
    return pico_tree_findKey(&aodv_nodes, &search);

}

static void pico_aodv_set_dev(struct pico_device *dev)
{
    pico_ipv4_route_set_bcast_link(pico_ipv4_link_by_dev(dev));
}


static int aodv_peer_refresh(struct pico_aodv_node *node, uint32_t seq)
{
    if ((0 == node->valid_dseq) || (pico_seq_compare(seq, node->dseq) > 0)) {
        node->dseq = seq;
        node->last_seen = PICO_TIME_MS();
        return 0;
    }
    return -1;
}

static void aodv_elect_route(struct pico_aodv_node *node, union pico_address *gw, int metric, struct pico_device *dev)
{
    metric++;
    if (metric < node->metric) {
        pico_ipv4_route_del(node->dest.ip4, HOST_NETMASK, node->metric);
        if (!gw) {
            pico_ipv4_route_add(node->dest.ip4, HOST_NETMASK, ANY_HOST, 1, pico_ipv4_link_by_dev(dev));
            node->metric = 1;
        } else {
            node->metric = (uint16_t)metric;
            pico_ipv4_route_add(node->dest.ip4, HOST_NETMASK, gw->ip4, metric, NULL);
        }
        node->active = 1;
    }
}

static struct pico_aodv_node *aodv_peer_new(union pico_address *addr)
{
    struct pico_aodv_node *node = PICO_ZALLOC(sizeof(struct pico_aodv_node));
    if (!node)
        return NULL;
    memcpy(&node->dest, addr, sizeof(union pico_address));
    pico_tree_insert(&aodv_nodes, node);
    return node;
}


static struct pico_aodv_node *aodv_peer_eval(union pico_address *addr, uint32_t seq)
{
    struct pico_aodv_node *node = NULL; 
    node = get_node_by_addr(addr);
    if (!node) {
        node = aodv_peer_new(addr);
    }
    if (node && aodv_peer_refresh(node, long_be(seq)) == 0)
        return node;
    return NULL;
}

/* Parser functions */

static void aodv_recv_valid_rreq(struct pico_aodv_node *node)
{
    struct pico_device *dev;
    dev = pico_ipv4_link_find(&node->dest.ip4);
    if (dev) {
        /* Case 1: destination is ourselves. Send reply. */
    } else if (node->active) {
        /* Case 2: we have a possible route. Send reply. */
    } else {
        /* Case 3: destination unknown. Evaluate forwarding. */
    }
}

static void aodv_parse_rreq(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    struct pico_aodv_rreq *req = (struct pico_aodv_rreq *) buf;
    struct pico_aodv_node *node = NULL; 
    union pico_address orig;
    if (len != sizeof(struct pico_aodv_rreq))
        return;

    orig.ip4.addr = req->orig;
    node = aodv_peer_eval(&orig, req->oseq);
    if (!node)
        return;
    aodv_elect_route(node, from, req->hop_count, msginfo->dev);

    aodv_recv_valid_rreq(node);
}

static void aodv_parse_rrep(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    struct pico_aodv_rrep *rep = (struct pico_aodv_rrep *) buf;
    struct pico_aodv_node *node = NULL; 
    union pico_address dest;
    if (len != sizeof(struct pico_aodv_rrep))
        return;

    dest.ip4.addr = rep->dest;
    node = aodv_peer_eval(&dest, rep->dseq);
    if (!node)
        return;
    dest.ip4.addr = node->dest.ip4.addr;
    aodv_elect_route(node, from, rep->hop_count, msginfo->dev);
}

static void aodv_parse_rerr(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    if ((uint32_t)len < sizeof(struct pico_aodv_rerr) ||  
            (((uint32_t)len - sizeof(struct pico_aodv_rerr)) % sizeof(struct pico_aodv_unreachable)) > 0)
        return;
    (void)from;
    (void)buf;
    (void)len;
    (void)msginfo;
    /* TODO: invalidate routes... */
}

static void aodv_parse_rack(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    if (len != sizeof(struct pico_aodv_rack))
        return;
    (void)from;
    (void)buf;
    (void)len;
    (void)msginfo;
}

struct aodv_parser_s {
    void (*call)(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo);
};

struct aodv_parser_s aodv_parser[5] = {
    {.call = NULL},
    {.call = aodv_parse_rreq },
    {.call = aodv_parse_rrep },
    {.call = aodv_parse_rerr },
    {.call = aodv_parse_rack }
};


static void pico_aodv_parse(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    if ((buf[0] < 1) || (buf[0] > 4)) {
        /* Type is invalid. Discard silently. */
        return;
    }
    aodv_parser[buf[0]].call(from, buf, len, msginfo);
}

static void pico_aodv_socket_callback(uint16_t ev, struct pico_socket *s)
{
    static uint8_t aodv_pkt[AODV_MAX_PKT];
    static union pico_address from;
    static struct pico_msginfo msginfo;
    uint16_t sport;
    int r;
    if (s != aodv_socket)
        return;
    if (ev & PICO_SOCK_EV_RD) {
        r = pico_socket_recvfrom_extended(s, aodv_pkt, AODV_MAX_PKT, &from, &sport, &msginfo);
        if (r <= 0)
            return;
        dbg("Received AODV packet: %d bytes \n", r);
        pico_aodv_parse(&from, aodv_pkt, r, &msginfo);
    }
}

static void aodv_make_rreq(struct pico_aodv_node *node, struct pico_aodv_rreq *req)
{
    req->type = AODV_TYPE_RREQ;
    req->req_flags |= short_be(AODV_RREQ_FLAG_G); /* RFC3561 $6.3: we SHOULD set G flag as originators */
    if (!node->valid_dseq) {
        req->req_flags |= short_be(AODV_RREQ_FLAG_U); /* no known dseq, mark as U */
        req->dseq = 0; /* Unknown */
    } else {
        req->dseq = long_be(node->dseq);
    }
    /* Hop count = 0; */
    req->rreq_id = long_be(pico_aodv_local_id);
    req->dest = node->dest.ip4.addr;
    req->oseq = long_be(pico_aodv_local_id);
}

static int aodv_send_req(struct pico_aodv_node *node)
{
    struct pico_device *dev;
    struct pico_tree_node *index;
    struct pico_ip4 all_bcast = { .addr = 0xFFFFFFFFu };
    static struct pico_aodv_rreq rreq;
    int n = 0;
    struct pico_ipv4_link *ip4l = NULL;

    if (pico_tree_empty(&aodv_devices))
        return n;

    if (!aodv_socket) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    pico_aodv_local_id++;
    aodv_make_rreq(node, &rreq);
    pico_tree_foreach(index, &aodv_devices){
        dev = index->keyValue;
        pico_aodv_set_dev(dev);
        ip4l = pico_ipv4_link_by_dev(dev);
        if (ip4l) {
            rreq.orig = ip4l->address.addr;
            pico_socket_sendto(aodv_socket, &rreq, sizeof(rreq), &all_bcast, short_be(PICO_AODV_PORT));
            n++;
        }
    }
    return n;   
}

int pico_aodv_init(void) 
{
    struct pico_ip4 any = { .addr = 0u};
    uint16_t port = short_be(PICO_AODV_PORT);
    if (aodv_socket) {
        pico_err = PICO_ERR_EADDRINUSE;
        return -1;
    }
    aodv_socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, pico_aodv_socket_callback);
    if (!aodv_socket)
        return -1;

    if (pico_socket_bind(aodv_socket, &any, &port) != 0) {
        uint16_t err = pico_err;
        pico_socket_close(aodv_socket);
        pico_err = err;
        aodv_socket = NULL;
        return -1;
    }
    pico_aodv_local_id = pico_rand();
    return 0;
}


int pico_aodv_add(struct pico_device *dev)
{
    return (pico_tree_insert(&aodv_devices, dev))?(0):(-1);
}

int pico_aodv_lookup(const union pico_address *addr)
{
    struct pico_aodv_node *node = get_node_by_addr(addr);
    if (!node) {
        node = PICO_ZALLOC(sizeof(struct pico_aodv_node));
        if (!node)
            return -1;
        memcpy(&node->dest, addr, sizeof(union pico_address));
    }
    if (aodv_send_req(node) > 0)
        return 0;
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

