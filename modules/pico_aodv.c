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
static struct pico_ip4 all_bcast = { .addr = 0xFFFFFFFFu };

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


static int aodv_peer_refresh(struct pico_aodv_node *node, uint32_t seq, int neighbor)
{
    if (neighbor || (0 == node->valid_dseq) || (pico_seq_compare(seq, node->dseq) > 0)) {
        node->dseq = seq;
        node->valid_dseq = 1;
        node->last_seen = PICO_TIME_MS();
        return 0;
    }
    return -1;
}

static void aodv_elect_route(struct pico_aodv_node *node, union pico_address *gw, uint8_t metric, struct pico_device *dev)
{
    metric++;
    if (!node->active || metric < node->metric) {
        pico_ipv4_route_del(node->dest.ip4, HOST_NETMASK, node->metric);
        if (!gw) {
            pico_ipv4_route_add(node->dest.ip4, HOST_NETMASK, ANY_HOST, 1, pico_ipv4_link_by_dev(dev));
            node->metric = 1;
        } else {
            node->metric = metric;
            pico_ipv4_route_add(node->dest.ip4, HOST_NETMASK, gw->ip4, metric, NULL);
        }
        node->active = 1;
    }
}

static struct pico_aodv_node *aodv_peer_new(const union pico_address *addr)
{
    struct pico_aodv_node *node = PICO_ZALLOC(sizeof(struct pico_aodv_node));
    if (!node)
        return NULL;
    memcpy(&node->dest, addr, sizeof(union pico_address));
    pico_tree_insert(&aodv_nodes, node);
    return node;
}


static struct pico_aodv_node *aodv_peer_eval(union pico_address *addr, uint32_t seq, int neighbor, int valid_seq)
{
    struct pico_aodv_node *node = NULL; 
    node = get_node_by_addr(addr);
    if (!node) {
        node = aodv_peer_new(addr);
    }

    if (!valid_seq)
        return node;

    if (node && aodv_peer_refresh(node, long_be(seq), neighbor) == 0)
        return node;
    return NULL;
}

void aodv_forward(void *pkt, struct pico_msginfo *info, int reply)
{
    struct pico_aodv_node *orig;
    union pico_address orig_addr;
    struct pico_tree_node *index;
    struct pico_device *dev;
    pico_time now;
    int size;

    printf("Forwarding %s packet\n", reply?"REPLY":"REQUEST");

    if (reply) {
        struct pico_aodv_rrep *rep = (struct pico_aodv_rrep *)pkt;
        orig_addr.ip4.addr = rep->dest;
        rep->hop_count++;
        size = sizeof(struct pico_aodv_rrep);
    } else {
        struct pico_aodv_rreq *req = (struct pico_aodv_rreq *)pkt;
        orig_addr.ip4.addr = req->orig;
        req->hop_count++;
        size = sizeof(struct pico_aodv_rreq);
    }

    orig = get_node_by_addr(&orig_addr);
    if (!orig)
        orig = aodv_peer_new(&orig_addr);
    if (!orig)
        return;

    now = PICO_TIME_MS();

    if ( ((orig->fwd_time == 0) || ((now - orig->fwd_time) > AODV_NET_TRAVERSAL_TIME)) && (--info->ttl > 0)) {
        orig->fwd_time = now;
        info->dev = NULL;
        pico_tree_foreach(index, &aodv_devices){
            dev = index->keyValue;
            pico_aodv_set_dev(dev);
            pico_socket_sendto_extended(aodv_socket, pkt, size, &all_bcast, short_be(PICO_AODV_PORT), info);
            printf("Forwarding %s: complete! ==== \n", reply?"REPLY":"REQUEST");
        }
    }
}

static uint32_t aodv_lifetime(struct pico_aodv_node *node)
{
    uint32_t lifetime;
    pico_time now = PICO_TIME_MS();
    if (!node->last_seen)
        node->last_seen = now;

    if ((now - node->last_seen) > AODV_ACTIVE_ROUTE_TIMEOUT)
        return 0;

    lifetime = AODV_ACTIVE_ROUTE_TIMEOUT - (uint32_t)(now - node->last_seen);
    return lifetime;
}

static void aodv_send_reply(struct pico_aodv_node *node, struct pico_aodv_rreq *req, int node_is_local, struct pico_msginfo *info)
{
    struct pico_aodv_rrep reply;
    union pico_address dest;
    reply.type = AODV_TYPE_RREP;
    reply.hop_count = 0;
    reply.dest = req->dest;
    reply.dseq = req->dseq;
    reply.orig = req->orig;

    dest.ip4.addr = 0xFFFFFFFF; /* wide broadcast */

    if (short_be(req->req_flags) & AODV_RREQ_FLAG_G)
        dest.ip4.addr = req->orig;
    else 
        pico_aodv_set_dev(info->dev);

    if (node_is_local) {
        reply.lifetime = long_be(AODV_MY_ROUTE_TIMEOUT);
        reply.dseq = long_be(++pico_aodv_local_id);
        pico_socket_sendto(aodv_socket, &reply, sizeof(reply), &dest, short_be(PICO_AODV_PORT));
    } else if (((short_be(req->req_flags) & AODV_RREQ_FLAG_D) == 0) && (node->valid_dseq)) {
        reply.lifetime = long_be(aodv_lifetime(node));
        reply.hop_count = (uint8_t)((uint8_t)reply.hop_count + (uint8_t)node->metric);
        reply.dseq = long_be(node->dseq);
        printf("Generating RREQ for node %x, id=%x\n", reply.dest, reply.dseq);
        pico_socket_sendto(aodv_socket, &reply, sizeof(reply), &dest, short_be(PICO_AODV_PORT));
    }
}

/* Parser functions */

static void aodv_recv_valid_rreq(struct pico_aodv_node *node, struct pico_aodv_rreq *req, struct pico_msginfo *info)
{
    struct pico_device *dev;
    dev = pico_ipv4_link_find(&node->dest.ip4);
    if (dev || node->active) {
        /* if destination is ourselves, or we have a possible route: Send reply. */
        aodv_send_reply(node, req, dev != NULL, info);
    } else {
        /* destination unknown. Evaluate forwarding. */
        aodv_forward(req, info, 0);
    }
}

static void aodv_parse_rreq(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    struct pico_aodv_rreq *req = (struct pico_aodv_rreq *) buf;
    struct pico_aodv_node *node = NULL; 
    union pico_address orig;
    (void)from;
    if (len != sizeof(struct pico_aodv_rreq))
        return;

    orig.ip4.addr = req->orig;
    node = aodv_peer_eval(&orig, req->oseq, 1, 1); /* Evaluate neighbor. */
    if (!node) {
        printf("RREQ: Neighbor is not valid. oseq=%d, stored dseq: %d\n", long_be(req->oseq), node->dseq);
        return;
    }
    aodv_elect_route(node, NULL, 1, msginfo->dev);

    orig.ip4.addr = req->dest;
    node = aodv_peer_eval(&orig, req->dseq, 0, !(req->req_flags & short_be(AODV_RREQ_FLAG_U)));
    if (!node)
        node = aodv_peer_new(&orig);
    if (!node)
        return;
    aodv_recv_valid_rreq(node, req, msginfo);
}

static void aodv_parse_rrep(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    struct pico_aodv_rrep *rep = (struct pico_aodv_rrep *) buf;
    struct pico_aodv_node *node = NULL; 
    union pico_address dest;
    struct pico_device *dev = NULL;
    if (len != sizeof(struct pico_aodv_rrep))
        return;

    dest.ip4.addr = rep->dest;
    dev = pico_ipv4_link_find(&dest.ip4);

    if (dev) /* Our reply packet got rebounced, no useful information here, no need to fwd. */
        return;

    printf("::::::::::::: Parsing RREP for node %08x\n", rep->dest);
    node = aodv_peer_eval(&dest, rep->dseq, 0, 1);
    if (node) {
        printf("::::::::::::: Node found. Electing route and forwarding.\n");
        dest.ip4.addr = node->dest.ip4.addr;
        aodv_elect_route(node, from, rep->hop_count, msginfo->dev);
        aodv_forward(rep, msginfo, 1);
    }
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
    pico_ipv4_route_add(from->ip4, HOST_NETMASK, ANY_HOST, 1, pico_ipv4_link_by_dev(msginfo->dev));
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
    memset(req, 0, sizeof(struct pico_aodv_rreq));
    req->type = AODV_TYPE_RREQ;

    if (!node->valid_dseq) {
        req->req_flags |= short_be(AODV_RREQ_FLAG_U); /* no known dseq, mark as U */
        req->dseq = 0; /* Unknown */
    } else {
        req->dseq = long_be(node->dseq);
        req->req_flags |= short_be(AODV_RREQ_FLAG_G); /* RFC3561 $6.3: we SHOULD set G flag as originators */
    }
    /* Hop count = 0; */
    req->rreq_id = long_be(++pico_aodv_local_id);
    req->dest = node->dest.ip4.addr;
    req->oseq = long_be(pico_aodv_local_id);
}

static void aodv_retrans_rreq(pico_time now, void *arg)
{
    struct pico_aodv_node *node = (struct pico_aodv_node *)arg;
    struct pico_device *dev;
    struct pico_tree_node *index;
    static struct pico_aodv_rreq rreq;
    struct pico_ipv4_link *ip4l = NULL;
    struct pico_msginfo info = {
        .dev = NULL, .tos = 0, .ttl = AODV_TTL_START
    };
    (void)now;

    memset(&rreq, 0, sizeof(rreq));

    if (node->active) {
        node->ring_ttl = 0;
        return;
    }

    if (node->ring_ttl >= AODV_TTL_THRESHOLD) {
        node->ring_ttl = AODV_NET_DIAMETER;
        printf("----------- DIAMETER reached.\n");
    }


    if (node->rreq_retry > AODV_RREQ_RETRIES) {
        node->rreq_retry = 0;
        node->ring_ttl = 0;
        printf("Node is unreachable.\n");
        return;
    }

    if (node->ring_ttl == AODV_NET_DIAMETER) {
        node->rreq_retry++; 
        printf("Retry #%d\n", node->rreq_retry);
    }

    aodv_make_rreq(node, &rreq);
    info.ttl = (uint8_t)node->ring_ttl; 
    pico_tree_foreach(index, &aodv_devices){
        dev = index->keyValue;
        pico_aodv_set_dev(dev);
        ip4l = pico_ipv4_link_by_dev(dev);
        if (ip4l) {
            rreq.orig = ip4l->address.addr;
            pico_socket_sendto_extended(aodv_socket, &rreq, sizeof(rreq), &all_bcast, short_be(PICO_AODV_PORT), &info);
        }
    }
    if (node->ring_ttl < AODV_NET_DIAMETER)
        node->ring_ttl += AODV_TTL_INCREMENT;
    pico_timer_add((pico_time)AODV_RING_TRAVERSAL_TIME(node->ring_ttl), aodv_retrans_rreq, node);
}

static int aodv_send_req(struct pico_aodv_node *node)
{
    struct pico_device *dev;
    struct pico_tree_node *index;
    static struct pico_aodv_rreq rreq;
    int n = 0;
    struct pico_ipv4_link *ip4l = NULL;
    struct pico_msginfo info = {
        .dev = NULL, .tos = 0, .ttl = AODV_TTL_START
    };
    memset(&rreq, 0, sizeof(rreq));

    if (pico_tree_empty(&aodv_devices))
        return n;

    if (!aodv_socket) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    aodv_make_rreq(node, &rreq);
    pico_tree_foreach(index, &aodv_devices){
        dev = index->keyValue;
        pico_aodv_set_dev(dev);
        ip4l = pico_ipv4_link_by_dev(dev);
        if (ip4l) {
            rreq.orig = ip4l->address.addr;
            pico_socket_sendto_extended(aodv_socket, &rreq, sizeof(rreq), &all_bcast, short_be(PICO_AODV_PORT), &info);
            n++;
        }
    }
    pico_timer_add(AODV_PATH_DISCOVERY_TIME, aodv_retrans_rreq, node);
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
    if (!node)
        node = aodv_peer_new(addr);
    if (!node)
        return -1;

    if (node->ring_ttl < AODV_TTL_START) {
        node->ring_ttl = AODV_TTL_START;
        aodv_send_req(node);
        return 0;
    }
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

