/*********************************************************************
   PicoTCP. Copyright (c) 2015-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   .

   Author: Daniele Lacamera <daniele.lacamera@altran.com>
 *********************************************************************/
#include <pico_stack.h>
#include <pico_tree.h>
#include <pico_socket.h>
#include <pico_aodv.h>
#include <pico_device.h>

#include <pico_ipv4.h>
#ifdef PICO_SUPPORT_IPV4

#ifdef DEBUG_AODV
    #define pico_aodv_dbg dbg
#else
    #define pico_aodv_dbg(...) do {} while(0)
#endif

#define AODV_MAX_PKT (64)
static const struct pico_ip4 HOST_NETMASK = {
    0xffffffff
};
static struct pico_ip4 all_bcast = {
    .addr = 0xFFFFFFFFu
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

static PICO_TREE_DECLARE(aodv_nodes, aodv_node_compare);
static PICO_TREE_DECLARE(aodv_devices, aodv_dev_cmp);

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
    if ((0 == (node->flags & PICO_AODV_NODE_SYNC)) || (pico_seq_compare(seq, node->dseq) > 0)) {
        node->dseq = seq;
        node->flags |= PICO_AODV_NODE_SYNC;
        node->last_seen = PICO_TIME_MS();
        return 0;
    }

    return -1;
}

static void aodv_elect_route(struct pico_aodv_node *node, union pico_address *gw, uint8_t metric, struct pico_device *dev)
{
    metric++;
    if (!(PICO_AODV_ACTIVE(node)) || metric < node->metric) {
        pico_ipv4_route_del(node->dest.ip4, HOST_NETMASK, node->metric);
        if (!gw) {
            pico_ipv4_route_add(node->dest.ip4, HOST_NETMASK, ANY_HOST, 1, pico_ipv4_link_by_dev(dev));
            node->metric = 1;
        } else {
            node->metric = metric;
            pico_ipv4_route_add(node->dest.ip4, HOST_NETMASK, gw->ip4, metric, NULL);
        }
    }
}

static struct pico_aodv_node *aodv_peer_new(const union pico_address *addr)
{
    struct pico_aodv_node *node = PICO_ZALLOC(sizeof(struct pico_aodv_node));
    if (!node)
        return NULL;

    memcpy(&node->dest, addr, sizeof(union pico_address));

    if (pico_tree_insert(&aodv_nodes, node)) {
    	PICO_FREE(node);
    	return NULL;
    }

    return node;
}


static struct pico_aodv_node *aodv_peer_eval(union pico_address *addr, uint32_t seq, int valid_seq)
{
    struct pico_aodv_node *node = NULL;
    node = get_node_by_addr(addr);
    if (!node) {
        node = aodv_peer_new(addr);
    }

    if (!valid_seq)
        return node;

    if (node && (aodv_peer_refresh(node, long_be(seq)) == 0))
        return node;

    return NULL;
}

static void aodv_forward(void *pkt, struct pico_msginfo *info, int reply)
{
    struct pico_aodv_node *orig;
    union pico_address orig_addr;
    struct pico_tree_node *index;
    struct pico_device *dev;
    pico_time now;
    int size;

    pico_aodv_dbg("Forwarding %s packet\n", reply ? "REPLY" : "REQUEST");

    if (reply) {
        struct pico_aodv_rrep *rep = (struct pico_aodv_rrep *)pkt;
        orig_addr.ip4.addr = rep->dest;
        rep->hop_count++;
        pico_aodv_dbg("RREP hop count: %d\n", rep->hop_count);
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

    pico_aodv_dbg("Forwarding %s: last fwd_time: %lu now: %lu ttl: %d ==== \n", reply ? "REPLY" : "REQUEST", orig->fwd_time, now, info->ttl);
    if (((orig->fwd_time == 0) || ((now - orig->fwd_time) > AODV_NODE_TRAVERSAL_TIME)) && (--info->ttl > 0)) {
        orig->fwd_time = now;
        info->dev = NULL;
        pico_tree_foreach(index, &aodv_devices){
            dev = index->keyValue;
            pico_aodv_set_dev(dev);
            pico_socket_sendto_extended(aodv_socket, pkt, size, &all_bcast, short_be(PICO_AODV_PORT), info);
            pico_aodv_dbg("Forwarding %s: complete! ==== \n", reply ? "REPLY" : "REQUEST");
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
    union pico_address oaddr;
    struct pico_aodv_node *orig;
    oaddr.ip4.addr = req->orig;
    orig = get_node_by_addr(&oaddr);
    reply.type = AODV_TYPE_RREP;
    reply.dest = req->dest;
    reply.dseq = req->dseq;
    reply.orig = req->orig;
    if (!orig)
        return;

    reply.hop_count = (uint8_t)(orig->metric - 1u);


    dest.ip4.addr = 0xFFFFFFFF; /* wide broadcast */

    if (short_be(req->req_flags) & AODV_RREQ_FLAG_G) {
        dest.ip4.addr = req->orig;
    } else {
        pico_aodv_set_dev(info->dev);
    }

    if (node_is_local) {
        reply.lifetime = long_be(AODV_MY_ROUTE_TIMEOUT);
        reply.dseq = long_be(++pico_aodv_local_id);
        pico_socket_sendto(aodv_socket, &reply, sizeof(reply), &dest, short_be(PICO_AODV_PORT));
    } else if (((short_be(req->req_flags) & AODV_RREQ_FLAG_D) == 0) && (node->flags & PICO_AODV_NODE_SYNC)) {
        reply.lifetime = long_be(aodv_lifetime(node));
        reply.dseq = long_be(node->dseq);
        pico_aodv_dbg("Generating RREP for node %x, id=%x\n", reply.dest, reply.dseq);
        pico_socket_sendto(aodv_socket, &reply, sizeof(reply), &dest, short_be(PICO_AODV_PORT));
    }

    pico_aodv_dbg("no rrep generated.\n");
}

/* Parser functions */

static int aodv_send_req(struct pico_aodv_node *node);

static void aodv_reverse_path_discover(pico_time now, void *arg)
{
    struct pico_aodv_node *origin = (struct pico_aodv_node *)arg;
    (void)now;
    pico_aodv_dbg("Sending G RREQ to ORIGIN (metric = %d).\n", origin->metric);
    origin->ring_ttl = origin->metric;
    aodv_send_req(origin);
}

static void aodv_recv_valid_rreq(struct pico_aodv_node *node, struct pico_aodv_rreq *req, struct pico_msginfo *info)
{
    struct pico_device *dev;
    dev = pico_ipv4_link_find(&node->dest.ip4);
    pico_aodv_dbg("Valid req.\n");
    if (dev || PICO_AODV_ACTIVE(node)) {
        /* if destination is ourselves, or we have a possible route: Send reply. */
        aodv_send_reply(node, req, dev != NULL, info);
        if (dev) {
            /* if really for us, we need to build the return route. Initiate a gratuitous request. */
            union pico_address origin_addr;
            struct pico_aodv_node *origin;
            origin_addr.ip4.addr = req->orig;
            origin = get_node_by_addr(&origin_addr);
            if (origin) {
                origin->flags |= PICO_AODV_NODE_ROUTE_DOWN;
                if (!pico_timer_add(AODV_PATH_DISCOVERY_TIME, aodv_reverse_path_discover, origin)) {
                    pico_aodv_dbg("AODV: Failed to start path discovery timer\n");
                }
            }
        }

        pico_aodv_dbg("Replied.\n");
    } else {
        /* destination unknown. Evaluate forwarding. */
        pico_aodv_dbg(" == Forwarding == .\n");
        aodv_forward(req, info, 0);
    }
}


static void aodv_parse_rreq(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    struct pico_aodv_rreq *req = (struct pico_aodv_rreq *) buf;
    struct pico_aodv_node *node = NULL;
    struct pico_device *dev;
    union pico_address orig, dest;
    (void)from;
    if (len != (int)sizeof(struct pico_aodv_rreq))
        return;

    orig.ip4.addr = req->orig;
    dev = pico_ipv4_link_find(&orig.ip4);
    if (dev) {
        pico_aodv_dbg("RREQ <-- myself\n");
        return;
    }

    node = aodv_peer_eval(&orig, req->oseq, 1);
    if (!node) {
        pico_aodv_dbg("RREQ: Neighbor is not valid. oseq=%d\n", long_be(req->oseq));
        return;
    }

    if (req->hop_count > 0)
        aodv_elect_route(node, from, req->hop_count, msginfo->dev);
    else
        aodv_elect_route(node, NULL, 0, msginfo->dev);

    dest.ip4.addr = req->dest;
    node = aodv_peer_eval(&dest, req->dseq, !(req->req_flags & short_be(AODV_RREQ_FLAG_U)));
    if (!node) {
        node = aodv_peer_new(&dest);
        pico_aodv_dbg("RREQ: New peer! %08x\n", dest.ip4.addr);
    }

    if (!node)
        return;

    aodv_recv_valid_rreq(node, req, msginfo);
}

static void aodv_parse_rrep(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    struct pico_aodv_rrep *rep = (struct pico_aodv_rrep *) buf;
    struct pico_aodv_node *node = NULL;
    union pico_address dest;
    union pico_address orig;
    struct pico_device *dev = NULL;
    if (len != (int)sizeof(struct pico_aodv_rrep))
        return;

    dest.ip4.addr = rep->dest;
    orig.ip4.addr = rep->orig;
    dev = pico_ipv4_link_find(&dest.ip4);

    if (dev) /* Our reply packet got rebounced, no useful information here, no need to fwd. */
        return;

    pico_aodv_dbg("::::::::::::: Parsing RREP for node %08x\n", rep->dest);
    node = aodv_peer_eval(&dest, rep->dseq, 1);
    if (node) {
        pico_aodv_dbg("::::::::::::: Node found. Electing route and forwarding.\n");
        dest.ip4.addr = node->dest.ip4.addr;
        if (rep->hop_count > 0)
            aodv_elect_route(node, from, rep->hop_count, msginfo->dev);
        else
            aodv_elect_route(node, NULL, 0, msginfo->dev);

        /* If we are the final destination for the reply (orig), no need to forward. */
        if (pico_ipv4_link_find(&orig.ip4)) {
            node->flags |= PICO_AODV_NODE_ROUTE_UP;
        } else {
            aodv_forward(rep, msginfo, 1);
        }
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
    /* TODO: invalidate routes. This only makes sense if we are using HELLO messages. */
}

static void aodv_parse_rack(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    if (len != (int)sizeof(struct pico_aodv_rack))
        return;

    (void)from;
    (void)buf;
    (void)len;
    (void)msginfo;
}

struct aodv_parser_s {
    void (*call)(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo);
};

static struct aodv_parser_s aodv_parser[5] = {
    {.call = NULL},
    {.call = aodv_parse_rreq },
    {.call = aodv_parse_rrep },
    {.call = aodv_parse_rerr },
    {.call = aodv_parse_rack }
};


static void pico_aodv_parse(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo)
{
    struct pico_aodv_node *node;
    uint8_t hopcount = 0;
    if ((buf[0] < 1) || (buf[0] > 4)) {
        /* Type is invalid. Discard silently. */
        return;
    }

    if (buf[0] == AODV_TYPE_RREQ) {
        hopcount = ((struct pico_aodv_rreq *)buf)->hop_count;
    }

    if (buf[0] == AODV_TYPE_RREP) {
        hopcount = ((struct pico_aodv_rrep *)buf)->hop_count;
    }

    node = aodv_peer_eval(from, 0, 0);
    if (!node)
        node = aodv_peer_new(from);

    if (node && (hopcount == 0)) {
        aodv_elect_route(node, NULL, hopcount, msginfo->dev);
    }

    pico_aodv_dbg("Received AODV packet, ttl = %d\n", msginfo->ttl);
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

        pico_aodv_dbg("Received AODV packet: %d bytes \n", r);

        pico_aodv_parse(&from, aodv_pkt, r, &msginfo);
    }
}

static void aodv_make_rreq(struct pico_aodv_node *node, struct pico_aodv_rreq *req)
{
    memset(req, 0, sizeof(struct pico_aodv_rreq));
    req->type = AODV_TYPE_RREQ;

    if (0 == (node->flags & PICO_AODV_NODE_SYNC)) {
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

    if (node->flags & PICO_AODV_NODE_ROUTE_UP) {
        pico_aodv_dbg("------------------------------------------------------ Node %08x already active.\n", node->dest.ip4.addr);
        return;
    }

    if (node->ring_ttl > AODV_TTL_THRESHOLD) {
        node->ring_ttl = AODV_NET_DIAMETER;
        pico_aodv_dbg("----------- DIAMETER reached.\n");
    }


    if (node->rreq_retry > AODV_RREQ_RETRIES) {
        node->rreq_retry = 0;
        node->ring_ttl = 0;
        pico_aodv_dbg("Node is unreachable.\n");
        node->flags &= (uint16_t)(~PICO_AODV_NODE_ROUTE_DOWN);
        return;
    }

    if (node->ring_ttl == AODV_NET_DIAMETER) {
        node->rreq_retry++;
        pico_aodv_dbg("Retry #%d\n", node->rreq_retry);
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
        node->ring_ttl = (uint8_t)(node->ring_ttl + AODV_TTL_INCREMENT);

    if (!pico_timer_add((pico_time)AODV_RING_TRAVERSAL_TIME(node->ring_ttl), aodv_retrans_rreq, node)) {
        pico_aodv_dbg("AODV: Failed to start retransmission timer\n");
    }
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

    if (PICO_AODV_ACTIVE(node))
        return 0;

    node->flags |= PICO_AODV_NODE_REQUESTING;

    if (pico_tree_empty(&aodv_devices))
        return n;

    if (!aodv_socket) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (node->flags & PICO_AODV_NODE_ROUTE_DOWN) {
        info.ttl = node->metric;
    }

    aodv_make_rreq(node, &rreq);
    pico_tree_foreach(index, &aodv_devices) {
        dev = index->keyValue;
        pico_aodv_set_dev(dev);
        ip4l = pico_ipv4_link_by_dev(dev);
        if (ip4l) {
            rreq.orig = ip4l->address.addr;
            pico_socket_sendto_extended(aodv_socket, &rreq, sizeof(rreq), &all_bcast, short_be(PICO_AODV_PORT), &info);
            n++;
        }
    }
    if (!pico_timer_add((pico_time)AODV_RING_TRAVERSAL_TIME(1), aodv_retrans_rreq, node)) {
        pico_aodv_dbg("AODV: Failed to start retransmission timer\n");
        return -1;
    }
    return n;
}

static void pico_aodv_expired(struct pico_aodv_node *node)
{
    node->flags |= PICO_AODV_NODE_UNREACH;
    node->flags &= (uint8_t)(~PICO_AODV_NODE_ROUTE_UP);
    node->flags &= (uint8_t)(~PICO_AODV_NODE_ROUTE_DOWN);
    pico_ipv4_route_del(node->dest.ip4, HOST_NETMASK, node->metric);
    node->ring_ttl = 0;
    /* TODO: send err */

}

static void pico_aodv_collector(pico_time now, void *arg)
{
    struct pico_tree_node *index;
    struct pico_aodv_node *node;
    (void)arg;
    (void)now;
    pico_tree_foreach(index, &aodv_nodes){
        node = index->keyValue;
        if (PICO_AODV_ACTIVE(node)) {
            uint32_t lifetime = aodv_lifetime(node);
            if (lifetime == 0)
                pico_aodv_expired(node);
        }
    }
    if (!pico_timer_add(AODV_HELLO_INTERVAL, pico_aodv_collector, NULL)) {
        pico_aodv_dbg("AODV: Failed to start collector timer\n");
        /* TODO what to do now? garbage collection will not be restarted, leading to memory leaks */
    }
}

MOCKABLE int pico_aodv_init(void)
{
    struct pico_ip4 any = {
        0
    };
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
    if (!pico_timer_add(AODV_HELLO_INTERVAL, pico_aodv_collector, NULL)) {
        pico_aodv_dbg("AODV: Failed to start collector timer\n");
        pico_socket_close(aodv_socket);
        aodv_socket = NULL;
        return -1;
    }
    return 0;
}


int pico_aodv_add(struct pico_device *dev)
{
    return (pico_tree_insert(&aodv_devices, dev)) ? (0) : (-1);
}

void pico_aodv_refresh(const union pico_address *addr)
{
    struct pico_aodv_node *node = get_node_by_addr(addr);
    if (node) {
        node->last_seen = PICO_TIME_MS();
    }
}

int pico_aodv_lookup(const union pico_address *addr)
{
    struct pico_aodv_node *node = get_node_by_addr(addr);
    if (!node)
        node = aodv_peer_new(addr);

    if (!node)
        return -1;

    if ((node->flags & PICO_AODV_NODE_ROUTE_UP) || (node->flags & PICO_AODV_NODE_ROUTE_DOWN))
        return 0;

    if (node->ring_ttl < AODV_TTL_START) {
        node->ring_ttl = AODV_TTL_START;
        aodv_send_req(node);
        return 0;
    }

    pico_err = PICO_ERR_EINVAL;
    return -1;
}

#else

int pico_aodv_init(void)
{
    return -1;
}

int pico_aodv_add(struct pico_device *dev)
{
    (void)dev;
    return -1;
}

int pico_aodv_lookup(const union pico_address *addr)
{
    (void)addr;
    return -1;
}

void pico_aodv_refresh(const union pico_address *addr)
{
    (void)addr;
}

#endif
