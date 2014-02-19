/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Kristof Roelants, Joris Renckens
 *********************************************************************/

#include "pico_config.h"
#include "pico_tree.h"
#include "pico_ipv6_nd.h"
#include "pico_icmp6.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_device.h"
#include "pico_eth.h"

#ifdef PICO_SUPPORT_IPV6

/* configuration */
#define PICO_ND_MAX_FRAMES_QUEUED      3 /* max frames queued while awaiting address resolution */

/* RFC constants */
#define PICO_ND_MAX_SOLICIT            3
#define PICO_ND_MAX_NEIGHBOR_ADVERT    3
#define PICO_ND_DELAY_FIRST_PROBE_TIME 5000 /* msec */

/* neighbor discovery options */
#define PICO_ND_OPT_LLADDR_SRC         1
#define PICO_ND_OPT_LLADDR_TGT         2
#define PICO_ND_OPT_PREFIX             3
#define PICO_ND_OPT_REDIRECT           4
#define PICO_ND_OPT_MTU                5

/* neighbor cache states */
#define PICO_ND_STATE_INCOMPLETE       0
#define PICO_ND_STATE_REACHABLE        1
#define PICO_ND_STATE_STALE            2
#define PICO_ND_STATE_DELAY            3
#define PICO_ND_STATE_PROBE            4

/* advertisement flags */
#define PICO_ND_ROUTER_BIT             31
#define PICO_ND_SOLICITED_BIT          30
#define PICO_ND_OVERRIDE_BIT           29
#define IS_ROUTER(x) (long_be(x->msg.info.neigh_adv.rsor) & (unsigned)(1 << PICO_ND_ROUTER_BIT)) /* router flag set? */
#define IS_SOLICITED(x) (long_be(x->msg.info.neigh_adv.rsor) & (1 << PICO_ND_SOLICITED_BIT)) /* solicited flag set? */
#define IS_OVERRIDE(x) (long_be(x->msg.info.neigh_adv.rsor) & (1 << PICO_ND_OVERRIDE_BIT)) /* override flag set? */

#define PICO_ND_PREFIX_LIFETIME_INF    0xFFFFFFFF
#define PICO_ND_DESTINATION_LRU_TIME   600 /* secs (10min) */

#define nd_dbg(...) do {} while(0)

struct pico_neighbor {
    uint8_t state;
    uint8_t isrouter : 1;
    uint8_t isprobing : 1;
    uint8_t failure_count;
    pico_time state_timestamp;
    pico_time rate_timestamp;
    struct pico_ip6 neighbor;
    struct pico_ip6 host;
    struct pico_eth mac;
    struct pico_device *dev;
    struct pico_queue pending;
};

struct pico_router {
    uint8_t valid : 1;
    pico_time invalidation_time;
    struct pico_neighbor *neighbor;
};

struct pico_prefix {
    uint8_t valid : 1;
    pico_time invalidation_time;
    struct pico_ip6 prefix;
};

struct pico_destination {
    pico_time timestamp;
    uint32_t mtu;
    struct pico_ip6 dest;
    struct pico_ip6 nexthop;
};

/* prototpye declaration */
static int pico_nd_send_solicitation(struct pico_neighbor *n, struct pico_frame *f, struct pico_ip6 *dst, uint8_t type);
static struct pico_router *pico_nd_find_router(struct pico_ip6 *router);

static int nd_neighbor_compare(void *ka, void *kb)
{
    struct pico_neighbor *a = ka, *b = kb;
    uint32_t *a_addr = (uint32_t *)a->neighbor.addr, *b_addr = (uint32_t *)b->neighbor.addr;
    int i = 0;

    for (i = 0; i < 4; ++i) {
        if (long_be(a_addr[i]) < long_be(b_addr[i]))
            return -1;

        if (long_be(a_addr[i]) > long_be(b_addr[i]))
            return 1;
    }
    return 0;
}
/* neighbor cache */
PICO_TREE_DECLARE(NDNeighbors, nd_neighbor_compare);

static struct pico_neighbor *pico_nd_find_neighbor(struct pico_ip6 *dst)
{
    struct pico_neighbor *found = NULL, test = {
        0
    };

    test.neighbor = *dst;
    found = pico_tree_findKey(&NDNeighbors, &test);
    if (found)
        return found;
    else
        return NULL;
}

static struct pico_neighbor *pico_nd_lookup(struct pico_ip6 *dst)
{
    return pico_nd_find_neighbor(dst);
}

static struct pico_neighbor *pico_nd_add_neighbor(struct pico_ip6 *host, struct pico_ip6 *neighbor, uint8_t state, struct pico_device *dev)
{
    struct pico_neighbor *n = NULL;

    n = pico_zalloc(sizeof(struct pico_neighbor));
    if (!n)
        return NULL;

    n->state = state;
    n->isrouter = 0;
    n->isprobing = 0;
    n->failure_count = 0;
    n->state_timestamp = PICO_TIME_MS();
    n->rate_timestamp = 0;
    n->neighbor = *neighbor;
    n->host = *host;
    n->dev = dev;
    n->pending.max_frames = PICO_ND_MAX_FRAMES_QUEUED;
    pico_tree_insert(&NDNeighbors, n);
    return n;
}

static int pico_nd_del_neighbor(struct pico_ip6 *neighbor)
{
    struct pico_neighbor test = {
        0
    }, *found = NULL;
    struct pico_router *r = NULL;
    struct pico_frame *f = NULL;

    if (!neighbor)
        return -1;

    test.neighbor = *neighbor;
    found = pico_tree_findKey(&NDNeighbors, &test);
    if (!found)
        return -1;

    f = pico_dequeue(&found->pending);
    while (f) {
        pico_notify_dest_unreachable(f);
        pico_frame_discard(f);
        f = pico_dequeue(&found->pending);
    }
    r = pico_nd_find_router(&found->neighbor);
    if (r)
        r->neighbor = NULL;

    pico_tree_delete(&NDNeighbors, found);
    pico_free(found);
    return 0;
}

static int nd_router_compare(void *ka, void *kb)
{
    struct pico_router *a = ka, *b = kb;
    struct pico_neighbor *a_neigh = a->neighbor, *b_neigh = b->neighbor;

    if (a_neigh < b_neigh)
        return -1;

    if (a_neigh > b_neigh)
        return 1;

    return 0;
}
/* default router list */
PICO_TREE_DECLARE(NDRouters, nd_router_compare);

static struct pico_router *pico_nd_find_router(struct pico_ip6 *router)
{
    struct pico_neighbor *n = NULL;
    struct pico_router *found = NULL, test = {
        0
    };

    n = pico_nd_find_neighbor(router);
    if (!n)
        return NULL;

    test.neighbor = n;
    found = pico_tree_findKey(&NDRouters, &test);
    if (found)
        return found;
    else
        return NULL;
}

static int pico_nd_del_router(struct pico_router *r)
{
    struct pico_router test = {
        0
    }, *found = NULL;

    if (!r)
        return -1;

    test.neighbor = r->neighbor;
    found = pico_tree_findKey(&NDRouters, &test);
    if (!found)
        return -1;

    pico_tree_delete(&NDRouters, found);
    pico_free(found);

    return 0;
}

static void pico_nd_router_timer(pico_time now, void *arg)
{

    struct pico_router *r = (struct pico_router *)arg;

    IGNORE_PARAMETER(now);

    if (!r->valid || r->invalidation_time <= PICO_TIME())
        pico_nd_del_router(r);
    else /* restart a timer for the remaining time */
        pico_timer_add((r->invalidation_time - PICO_TIME()) * 1000, &pico_nd_router_timer, r);
}

static int pico_nd_add_router(struct pico_neighbor *router, uint16_t lifetime)
{
    struct pico_router *r = NULL;

    r = pico_zalloc(sizeof(struct pico_router));
    if (!r)
        return 0;

    r->valid = 1;
    r->neighbor = router;
    r->invalidation_time = PICO_TIME() + short_be(lifetime);
    pico_tree_insert(&NDRouters, r);
    pico_timer_add((uint32_t)(short_be(lifetime) * 1000), &pico_nd_router_timer, r);
    return 1;
}

static int nd_prefix_compare(void *ka, void *kb)
{
    struct pico_prefix *a = ka, *b = kb;
    uint32_t *a_addr = (uint32_t *)a->prefix.addr, *b_addr = (uint32_t *)b->prefix.addr;
    int i = 0;

    for (i = 0; i < 4; ++i) {
        if (long_be(a_addr[i]) < long_be(b_addr[i]))
            return -1;

        if (long_be(a_addr[i]) > long_be(b_addr[i]))
            return 1;
    }
    return 0;
}
/* prefix list */
PICO_TREE_DECLARE(NDPrefix, nd_prefix_compare);

static struct pico_prefix *pico_nd_find_prefix(struct pico_ip6 *prefix)
{
    struct pico_prefix *found = NULL, test = {
        0
    };

    test.prefix = *prefix;
    found = pico_tree_findKey(&NDPrefix, &test);
    if (found)
        return found;
    else
        return NULL;
}

static int pico_nd_del_prefix(struct pico_ip6 *prefix)
{
    struct pico_prefix test = {
        0
    }, *found = NULL;

    if (!prefix)
        return -1;

    test.prefix = *prefix;
    found = pico_tree_findKey(&NDPrefix, &test);
    if (!found)
        return -1;

    pico_tree_delete(&NDPrefix, found);
    pico_free(found);
    return 0;
}

static void pico_nd_prefix_timer(pico_time now, void *arg)
{
    struct pico_prefix *p = (struct pico_prefix *)arg;

    IGNORE_PARAMETER(now);

    if (!p->valid || p->invalidation_time <= PICO_TIME())
        pico_nd_del_prefix(&p->prefix);
    else /* restart a timer for the remaining time */
        pico_timer_add((p->invalidation_time - PICO_TIME()) * 1000, &pico_nd_prefix_timer, p);
}

static struct pico_prefix *pico_nd_add_prefix(struct pico_ip6 *prefix, uint32_t valid_time)
{
    struct pico_prefix *p = NULL;

    p = pico_zalloc(sizeof(struct pico_prefix));
    if (!p)
        return NULL;

    p->valid = 1;
    p->prefix = *prefix;
    p->invalidation_time = PICO_TIME() + long_be(valid_time);
    pico_tree_insert(&NDPrefix, p);

    if (long_be(valid_time) < PICO_ND_PREFIX_LIFETIME_INF) {
        pico_timer_add(long_be(valid_time) * 1000, &pico_nd_prefix_timer, p);
    }

    return p;
}

static int nd_destination_compare(void *ka, void *kb)
{
    struct pico_destination *a = ka, *b = kb;
    uint32_t *a_addr = (uint32_t *)a->dest.addr, *b_addr = (uint32_t *)b->dest.addr;
    int i = 0;

    for (i = 0; i < 4; ++i) {
        if (long_be(a_addr[i]) < long_be(b_addr[i]))
            return -1;

        if (long_be(a_addr[i]) > long_be(b_addr[i]))
            return 1;
    }
    return 0;
}
/* prefix list */
PICO_TREE_DECLARE(NDDestinations, nd_destination_compare);

static struct pico_destination *pico_nd_find_destination(struct pico_ip6 *dest)
{
    struct pico_destination *found = NULL, test = {
        0
    };

    test.dest = *dest;
    found = pico_tree_findKey(&NDDestinations, &test);
    if (found)
        return found;
    else
        return NULL;
}

static int pico_nd_del_destination(struct pico_ip6 *dest)
{
    struct pico_destination *found = NULL, test = {
        0
    };

    if (!dest)
        return -1;

    test.dest = *dest;
    found = pico_tree_findKey(&NDDestinations, &test);
    if (!found)
        return -1;

    pico_tree_delete(&NDDestinations, found);
    pico_free(found);
    return 0;
}

static struct pico_destination *pico_nd_add_destination(struct pico_ip6 *dest, struct pico_ip6 *nexthop)
{
    struct pico_destination *d = NULL;

    d = pico_zalloc(sizeof(struct pico_destination));
    if (!d)
        return NULL;

    d->dest = *dest;
    d->nexthop = *nexthop;
    d->timestamp = PICO_TIME();
    d->mtu = PICO_ETH_MTU;
    pico_tree_insert(&NDDestinations, d);

    return d;
}

static void pico_nd_destination_garbage_collect(pico_time now, void *arg)
{
    struct pico_destination *d = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;

    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(arg);

    pico_tree_foreach_safe(index, &NDDestinations, _tmp)
    {
        d = index->keyValue;
        if (PICO_TIME() > d->timestamp + PICO_ND_DESTINATION_LRU_TIME)
            pico_nd_del_destination(&d->dest);
    }
    pico_timer_add(PICO_ND_DESTINATION_LRU_TIME * 1000, pico_nd_destination_garbage_collect, NULL);
}

static void pico_nd_pending(pico_time now, void *arg)
{
    struct pico_neighbor *n = NULL;
    struct pico_frame *f = NULL;

    IGNORE_PARAMETER(now);

    n = (struct pico_neighbor *)arg;
    if (!n)
        return;

    if (n->state != PICO_ND_STATE_REACHABLE) {
        if (pico_nd_send_solicitation(n, NULL, &n->neighbor, PICO_ICMP6_ND_SOLICITED) == 0)
            pico_timer_add(n->dev->hostvars.retranstime, &pico_nd_pending, n);
    } else {
        f = pico_dequeue(&n->pending);
        while (f) {
            pico_ethernet_send(f);
            f = pico_dequeue(&n->pending);
        }
    }

    return;
}

static void pico_nd_first_probe(pico_time now, void *arg)
{
    struct pico_neighbor *n = NULL;

    IGNORE_PARAMETER(now);

    n = (struct pico_neighbor *)arg;
    if (!n)
        return;

    /* RFC4861 $7.3.3
     * The first time a node sends a packet to a neighbor whose entry is
     * STALE, the sender changes the state to DELAY and sets a timer to
     * expire in DELAY_FIRST_PROBE_TIME seconds.  If the entry is still in
     * the DELAY state when the timer expires, the entry's state changes to
     * PROBE.
     */
    if (n->state == PICO_ND_STATE_DELAY) {
        n->state = PICO_ND_STATE_PROBE;
        n->state_timestamp = PICO_TIME_MS();
    }

    return;
}

static void pico_nd_probe(pico_time now, void *arg)
{
    struct pico_neighbor *n = NULL;

    IGNORE_PARAMETER(now);

    n = (struct pico_neighbor *)arg;
    if (!n)
        return;

    if (n->state == PICO_ND_STATE_REACHABLE) {
        n->isprobing = 0;
        return;
    }

    if (pico_nd_send_solicitation(n, NULL, &n->neighbor, PICO_ICMP6_ND_UNICAST) == 0)
        pico_timer_add(n->dev->hostvars.retranstime, &pico_nd_probe, n);

    return;
}

static int pico_nd_send_solicitation(struct pico_neighbor *n, struct pico_frame *f, struct pico_ip6 *dst, uint8_t type)
{
    struct pico_frame *p = NULL;
    struct pico_device *dev = NULL;

    if (f) { /* solicitation triggered by traffic */
        dev = f->dev;
        if (pico_queue_peek(&n->pending) == NULL) { /* if no packets queued */
            pico_timer_add(dev->hostvars.retranstime, &pico_nd_pending, n);
        }

        if (pico_enqueue(&n->pending, f) < 0) { /* if PICO_ND_MAX_QUEUED reached */
            p = pico_dequeue(&n->pending);
            pico_frame_discard(p);
            pico_enqueue(&n->pending, f);
        }
    } else { /* solicitation triggered by timer */
        dev = n->dev;
    }

    /* RFC4861 $7.2.1
     * while awaiting a response, the sender SHOULD retransmit neighbor
     * solicitation messages approximately every RetransTimer milliseconds,
     * even in the absence of additional traffic to the neighbor.
     * retransmissions MUST be rate-limited to at most one solicitation per
     * neighbor every RetransTimer milliseconds.
     */
    if (n->rate_timestamp != 0 && PICO_TIME_MS() - n->rate_timestamp < dev->hostvars.retranstime)
        return 0;

    n->rate_timestamp = PICO_TIME_MS();

    if (n->failure_count++ < PICO_ND_MAX_SOLICIT) {
        dbg ("================= NS REQUIRED: %d =============\n", n->failure_count);
        pico_icmp6_neighbor_solicitation(dev, dst, type);
    } else {
        dbg("ND: Destination Unreachable\n");
        pico_nd_del_neighbor(dst);
        return -1;
    }

    return 0;
}

int pico_nd_neigh_sol_recv(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_icmp6_opt_lladdr *opt = NULL;
    struct pico_neighbor *neighbor = NULL;
    struct pico_ipv6_link *link = NULL;
    int optlen = 0, type = 0, len = 0;
    uint8_t *option = NULL;

    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (ipv6_hdr->hop != 255 || icmp6_hdr->code != 0)
        goto out;

#ifdef PICO_SUPPORT_CRC
    if (pico_icmp6_checksum(f) != 0)
        goto out;
#endif

    if (f->transport_len < PICO_ICMP6HDR_NEIGH_SOL_SIZE)
        goto out;

    if (pico_ipv6_is_multicast(icmp6_hdr->msg.info.neigh_adv.target.addr))
        goto out;

    if (pico_ipv6_is_unspecified(ipv6_hdr->src.addr) && !pico_ipv6_is_solicited(ipv6_hdr->dst.addr))
        goto out;

    /* valid solicitation */

    /* RFC 4861 $7.1.1 + $7.2.3.
     * The contents of any defined options that are not specified to be used
     * with Neighbor Advertisement messages MUST be ignored and the packet
     * processed as normal. The only defined option that may appear is the
     * Target Link-Layer Address option.
     */
    optlen = f->transport_len - PICO_ICMP6HDR_NEIGH_ADV_SIZE;
    if (optlen)
        option = icmp6_hdr->msg.info.neigh_sol.options;

    while (optlen) {
        type = ((struct pico_icmp6_opt_lladdr *)option)->type;
        len = ((struct pico_icmp6_opt_lladdr *)option)->len;
        optlen -= len * 8; /* len in units of 8 octets */
        if (!len)
            goto out;

        if (type == PICO_ND_OPT_LLADDR_SRC) {
            opt = (struct pico_icmp6_opt_lladdr *)option;
            break;
        } else if (optlen > 0) {
            option += len * 8;
        } else { /* no source link-layer address option */
            opt = NULL;
        }
    }
    /* XXX target is valid unicast or ->anycast<- address assigned to the receiving interface */
    /* target is a tentative address on which duplicate address detection is being performed */
    /* XXX pico_ipv6_link_istentative? */
    link = pico_ipv6_link_get(&icmp6_hdr->msg.info.neigh_adv.target);
    if (!link)
        goto out;

    if (pico_ipv6_is_unicast(icmp6_hdr->msg.info.neigh_adv.target.addr))
        if(link->dev != f->dev)
            goto out;

    if (!pico_ipv6_is_unspecified(ipv6_hdr->src.addr) && opt) {
        neighbor = pico_nd_find_neighbor(&ipv6_hdr->src);
        if (!neighbor) {
            /* neighbor->isrouter set to false */
            pico_nd_add_neighbor(&ipv6_hdr->dst, &ipv6_hdr->src, PICO_ND_STATE_STALE, f->dev);
        } else {
            if (memcmp(opt->addr.mac.addr, neighbor->mac.addr, PICO_SIZE_ETH)) {
                neighbor->mac = opt->addr.mac;
                neighbor->state = PICO_ND_STATE_STALE;
                neighbor->state_timestamp = PICO_TIME_MS();
            }

            /* neighbor->isrouter unmodified */
        }
    } else {
        /* MUST NOT create or update the neighbor cache */

    }

    pico_icmp6_neighbor_advertisement(f, &icmp6_hdr->msg.info.neigh_adv.target);

    pico_frame_discard(f);
    return 0;

out:
    pico_frame_discard(f);
    return -1;
}

int pico_nd_neigh_adv_recv(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_icmp6_opt_lladdr *opt = NULL;
    struct pico_neighbor *neighbor = NULL;
    struct pico_ipv6_link *link = NULL;
    int optlen = 0, type = 0, len = 0, in_cache = 0;
    uint8_t *option = NULL;

    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (ipv6_hdr->hop != 255 || pico_icmp6_checksum(f) != 0 || icmp6_hdr->code != 0)
        goto out;

    if (f->transport_len < PICO_ICMP6HDR_NEIGH_ADV_SIZE)
        goto out;

    if (pico_ipv6_is_multicast(icmp6_hdr->msg.info.neigh_adv.target.addr))
        goto out;

    if (pico_ipv6_is_multicast(ipv6_hdr->dst.addr) && IS_SOLICITED(icmp6_hdr))
        goto out;

    /* valid advertisement */

    link = pico_ipv6_link_istentative(&icmp6_hdr->msg.info.neigh_adv.target);
    if (link)
        link->isduplicate = 1;

    neighbor = pico_nd_find_neighbor(&icmp6_hdr->msg.info.neigh_adv.target);
    if (!neighbor)
        goto out;

    /* RFC 4861 $7.1.2 + $7.2.5.
     * The contents of any defined options that are not specified to be used
     * with Neighbor Advertisement messages MUST be ignored and the packet
     * processed as normal. The only defined option that may appear is the
     * Target Link-Layer Address option.
     */
    optlen = f->transport_len - PICO_ICMP6HDR_NEIGH_ADV_SIZE;
    if (optlen)
        option = icmp6_hdr->msg.info.neigh_adv.options;

    while (optlen) {
        type = ((struct pico_icmp6_opt_lladdr *)option)->type;
        len = ((struct pico_icmp6_opt_lladdr *)option)->len;
        optlen -= len * 8; /* len in units of 8 octets */
        if (!len)
            goto out;

        if (type == PICO_ND_OPT_LLADDR_TGT) {
            opt = (struct pico_icmp6_opt_lladdr *)option;
            in_cache = !memcmp(opt->addr.mac.addr, neighbor->mac.addr, PICO_SIZE_ETH);
            break;
        } else if (optlen > 0) {
            option += len * 8;
        } else { /* no target link-layer address option */
            opt = NULL;
        }
    }
    if (neighbor->state == PICO_ND_STATE_INCOMPLETE) {
        if (!opt)
            goto out;

        neighbor->mac = opt->addr.mac;
        neighbor->state_timestamp = PICO_TIME_MS();

        /* is a response to a solicitation? */
        if (IS_SOLICITED(icmp6_hdr))
            neighbor->state = PICO_ND_STATE_REACHABLE;
        else
            neighbor->state = PICO_ND_STATE_STALE;

        if (IS_ROUTER(icmp6_hdr))
            neighbor->isrouter = 1;
        else
            neighbor->isrouter = 0;
    }
    else { /* any other state than INCOMPLETE */
        if (!IS_OVERRIDE(icmp6_hdr) && opt && !in_cache) {
            if (neighbor->state == PICO_ND_STATE_REACHABLE) {
                neighbor->state = PICO_ND_STATE_STALE;
                neighbor->state_timestamp = PICO_TIME_MS();
            } /* else { MUST NOT update the cache } */

        }
        else if (IS_OVERRIDE(icmp6_hdr) || !opt || in_cache) {
            if (opt && !in_cache)
                neighbor->mac = opt->addr.mac;

            if (IS_SOLICITED(icmp6_hdr)) {
                neighbor->state = PICO_ND_STATE_REACHABLE;
                neighbor->state_timestamp = PICO_TIME_MS();
            } else if (!IS_SOLICITED(icmp6_hdr) && opt && !in_cache) {
                neighbor->state = PICO_ND_STATE_STALE;
                neighbor->state_timestamp = PICO_TIME_MS();
            } else {
                /* neighbor->state unmodified */
            }

            if (IS_ROUTER(icmp6_hdr)) {
                neighbor->isrouter = 1;
            } else {
                if (neighbor->isrouter == 1) {
                    /* XXX RFC4861 $7.2.5
                     *     In those cases where the IsRouter flag changes from TRUE to FALSE
                     *     as a result of this update, the node MUST remove that router from the
                     *     Default Router List and update the Destination Cache entries
                     *     for all destinations using that neighbor as a router
                     */
                    struct pico_router *r = NULL;
                    r = pico_nd_find_router(&neighbor->neighbor);
                    if (r)
                        pico_nd_del_router(r);
                }

                neighbor->isrouter = 0;
            }
        }
        else {
            /* do nothing */
        }
    }

    pico_frame_discard(f);
    return 0;

out:
    pico_frame_discard(f);
    return -1;
}

int pico_nd_router_sol_recv(struct pico_frame *f)
{
    /* RFC 4861 $6.1.1 Hosts MUST silently discard any received router solicitations */
    pico_frame_discard(f);
    return 0;
}

int pico_nd_router_adv_recv(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_icmp6_opt_na *option = NULL;
    struct pico_icmp6_opt_lladdr *lladdr = NULL;
    struct pico_icmp6_opt_prefix *prefix = NULL;
    struct pico_icmp6_opt_mtu *mtu = NULL;
    struct pico_nd_hostvars *hostvars = NULL;
    struct pico_neighbor *n = NULL;
    struct pico_router *r = NULL;
    struct pico_prefix *p = NULL;
    int optlen = 0;

    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (ipv6_hdr->hop != 255 || pico_icmp6_checksum(f) != 0 || icmp6_hdr->code != 0)
        goto out;

    if (f->transport_len < PICO_ICMP6HDR_ROUTER_ADV_SIZE)
        goto out;

    if (!pico_ipv6_is_linklocal(ipv6_hdr->src.addr))
        goto out;

    /* valid advertisement */

    n = pico_nd_find_neighbor(&ipv6_hdr->src);
    r = pico_nd_find_router(&ipv6_hdr->src);
    if (!r) {
        if (icmp6_hdr->msg.info.router_adv.life_time != 0) {
            if (!n) {
                n = pico_nd_add_neighbor(&ipv6_hdr->dst, &ipv6_hdr->src, PICO_ND_STATE_STALE, f->dev);
                if (!n)
                    goto out;
            }

            if (!pico_nd_add_router(n, icmp6_hdr->msg.info.router_adv.life_time))
                dbg("Default router not added: lack of memory!\n");
        }
        else {
            /* A Lifetime of 0 indicates that the router is not a default router and
             * SHOULD NOT appear on the default router list */
            goto out;
        }
    }
    else {
        if (icmp6_hdr->msg.info.router_adv.life_time != 0) {
            if (!r->neighbor) {
                if (!n) {
                    n = pico_nd_add_neighbor(&ipv6_hdr->dst, &ipv6_hdr->src, PICO_ND_STATE_STALE, f->dev);
                    if (!n)
                        goto out;
                }

                r->neighbor = n;
            }

            r->valid = 1;
            r->invalidation_time = PICO_TIME() + short_be(icmp6_hdr->msg.info.router_adv.life_time);
        }
        else { /* time-out entry */
            r->valid = 0;
        }
    }

    /* host variables */
    hostvars = &f->dev->hostvars;
    if (icmp6_hdr->msg.info.router_adv.hop != 0)
        hostvars->hoplimit = icmp6_hdr->msg.info.router_adv.hop;

    if (icmp6_hdr->msg.info.router_adv.retrans_time != 0)
        hostvars->retranstime = long_be(icmp6_hdr->msg.info.router_adv.retrans_time);

    if (icmp6_hdr->msg.info.router_adv.reachable_time != 0 && long_be(icmp6_hdr->msg.info.router_adv.reachable_time) != hostvars->basetime) {
        hostvars->basetime = long_be(icmp6_hdr->msg.info.router_adv.reachable_time);
        /* value between 0.5 and 1.5 times basetime */
        hostvars->reachabletime = ((5 + (pico_rand() % 10)) * long_be(icmp6_hdr->msg.info.router_adv.reachable_time)) / 10;
    }

    /* advertisement options */
    while (optlen < (f->transport_len - PICO_ICMP6HDR_ROUTER_ADV_SIZE)) {
        option = (struct pico_icmp6_opt_na *)(icmp6_hdr->msg.info.router_adv.options + optlen);

        if (option->len == 0)
            goto out;

        if (n)
            n->isrouter = 1;

        switch (option->type) {
        case PICO_ND_OPT_LLADDR_SRC:
            lladdr = (struct pico_icmp6_opt_lladdr *)option;
            if (!n) {
                n = pico_nd_add_neighbor(&ipv6_hdr->dst, &ipv6_hdr->src, PICO_ND_STATE_STALE, f->dev);
            } else {
                if (memcmp(n->mac.addr, lladdr->addr.mac.addr, PICO_SIZE_ETH)) {
                    n->state = PICO_ND_STATE_STALE;
                    n->state_timestamp = PICO_TIME_MS();
                }
            }

            n->mac = lladdr->addr.mac;
            n->isrouter = 1;
            break;

        case PICO_ND_OPT_PREFIX:
            prefix = (struct pico_icmp6_opt_prefix *)option;
            if (prefix->onlink) {
                if (pico_ipv6_is_linklocal(prefix->prefix.addr))
                    break;

                p = pico_nd_find_prefix(&prefix->prefix);
                if (p) {
                    if (prefix->val_lifetime != 0) {
                        p->valid = 1;
                        p->invalidation_time = PICO_TIME() + long_be(prefix->val_lifetime);
                    } else { /* time-out entry */
                        p->valid = 0;
                    }
                }
                else {
                    if (prefix->val_lifetime != 0)
                        pico_nd_add_prefix(&prefix->prefix, prefix->val_lifetime);
                }
            }

            break;

        case PICO_ND_OPT_MTU:
            mtu = (struct pico_icmp6_opt_mtu *)option;
            if (PICO_IPV6_MIN_MTU <= long_be(mtu->mtu) && long_be(mtu->mtu) <= PICO_ETH_MTU)
                hostvars->mtu = long_be(mtu->mtu);

            break;
        }
        optlen += option->len * 8;
    }
    pico_frame_discard(f);
    return 0;

out:
    pico_frame_discard(f);
    return -1;
}

int pico_nd_redirect_recv(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_icmp6_opt_na *option = NULL;
    struct pico_icmp6_opt_lladdr *lladdr = NULL;
    struct pico_neighbor *n = NULL;
    struct pico_destination *d = NULL;
    int optlen = 0;

    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (ipv6_hdr->hop != 255 || pico_icmp6_checksum(f) != 0 || icmp6_hdr->code != 0)
        goto out;

    if (f->transport_len < PICO_ICMP6HDR_REDIRECT_SIZE)
        goto out;

    if (!pico_ipv6_is_linklocal(ipv6_hdr->src.addr))
        goto out;

    if (pico_ipv6_is_multicast(icmp6_hdr->msg.info.redirect.dest.addr))
        goto out;

    if (!pico_ipv6_is_linklocal(icmp6_hdr->msg.info.redirect.target.addr) &&
        memcmp(icmp6_hdr->msg.info.redirect.target.addr, icmp6_hdr->msg.info.redirect.dest.addr, PICO_SIZE_IP6))
        goto out;

    /* XXX: RFC4861 $8.1
     * The IP source address of the Redirect is the same as the current
     * first-hop router for the specified ICMP Destination Address.
     */
    /* valid advertisement */

    d = pico_nd_find_destination(&icmp6_hdr->msg.info.redirect.dest);
    if (d) {
        d->nexthop = icmp6_hdr->msg.info.redirect.target;
    } else {
        if (!pico_nd_add_destination(&icmp6_hdr->msg.info.redirect.dest, &icmp6_hdr->msg.info.redirect.target))
            goto out;
    }

    n = pico_nd_find_neighbor(&icmp6_hdr->msg.info.redirect.target);
    /* redirect options */
    while (optlen < (f->transport_len - PICO_ICMP6HDR_REDIRECT_SIZE)) {
        option = (struct pico_icmp6_opt_na *)(icmp6_hdr->msg.info.redirect.options + optlen);

        if (option->len == 0)
            goto out;

        switch (option->type) {
        case PICO_ND_OPT_LLADDR_TGT:
            lladdr = (struct pico_icmp6_opt_lladdr *)option;
            if (!n) {
                n = pico_nd_add_neighbor(&ipv6_hdr->dst, &icmp6_hdr->msg.info.redirect.target, PICO_ND_STATE_STALE, f->dev);
            } else {
                if (memcmp(n->mac.addr, lladdr->addr.mac.addr, PICO_SIZE_ETH)) {
                    n->state = PICO_ND_STATE_STALE;
                    n->state_timestamp = PICO_TIME_MS();
                }
            }

            n->mac = lladdr->addr.mac;
            break;

        case PICO_ND_OPT_REDIRECT:
            /* no use yet */
            break;

        default:
            /* option should not appear, but continue */
            break;
        }
        optlen += option->len * 8;
    }
    /* target != dest? */
    if (memcmp(icmp6_hdr->msg.info.redirect.target.addr, icmp6_hdr->msg.info.redirect.dest.addr, PICO_SIZE_IP6)) {
        if (!n)
            n = pico_nd_add_neighbor(&ipv6_hdr->dst, &icmp6_hdr->msg.info.redirect.target, PICO_ND_STATE_INCOMPLETE, f->dev);

        n->isrouter = 1;
    }

    pico_frame_discard(f);
    return 0;

out:
    pico_frame_discard(f);
    return -1;
}

struct pico_eth *pico_nd_get(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    struct pico_ipv6_link *l = NULL;
    struct pico_neighbor *n = NULL;
    struct pico_ip6 gateway = {{0}}, addr = {{0}};

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;

    if (pico_ipv6_link_istentative(&hdr->src))
        return NULL;

    /* address belongs to ourself? */
    l = pico_ipv6_link_get(&hdr->dst);
    if (l)
        return &l->dev->eth->mac;

    /* use gateway, or is dst local (gateway == 0) */
    gateway = pico_ipv6_route_get_gateway(&hdr->dst);
    if (memcmp(gateway.addr, PICO_IP6_ANY, PICO_SIZE_IP6) == 0)
        addr = hdr->dst;
    else
        addr = gateway;

    n = pico_nd_lookup(&addr);
    if (!n) {
        n = pico_nd_add_neighbor(&hdr->src, &addr, PICO_ND_STATE_INCOMPLETE, f->dev);
        if (!n)
            return NULL;
    }

    /* RFC4861 $7.3.3
     * While reasserting a neighbor's reachability, a node continues sending
     * packets to that neighbor using the cached link-layer address.  If no
     * traffic is sent to a neighbor, no probes are sent.
     */
    switch (n->state)
    {
    case PICO_ND_STATE_INCOMPLETE:
        pico_nd_send_solicitation(n, f, &addr, PICO_ICMP6_ND_SOLICITED);
        return NULL;

    case PICO_ND_STATE_STALE:
        n->state = PICO_ND_STATE_DELAY;
        n->state_timestamp = PICO_TIME_MS();
        pico_timer_add(PICO_ND_DELAY_FIRST_PROBE_TIME, &pico_nd_first_probe, n);
        break;

    case PICO_ND_STATE_REACHABLE:
        n->failure_count = 0;
        if (PICO_TIME_MS() - n->state_timestamp > f->dev->hostvars.reachabletime) {
            n->state = PICO_ND_STATE_STALE;
            n->state_timestamp = PICO_TIME_MS();
        }

        break;

    case PICO_ND_STATE_PROBE:
        if (!n->isprobing) {
            n->isprobing = 1;
            pico_timer_add(n->dev->hostvars.retranstime, &pico_nd_probe, n);
        }

        break;

    case PICO_ND_STATE_DELAY:
        /* RFC4861 $7.3.2
         * the DELAY state is an optimization that gives upper-layer protocols
         * additional time to provide reachability confirmation in those cases
         * where ReachableTime milliseconds have passed since the last
         * confirmation due to lack of recent traffic.
         */
        break;

    default:
        break;
    }
    return &n->mac;
}

void pico_nd_init(void)
{
    /* garbage collect Least Recently Used (LRU) */
    pico_timer_add(PICO_ND_DESTINATION_LRU_TIME * 1000, pico_nd_destination_garbage_collect, NULL);
    /* XXX: garbage collect neighbor cache? if pico_nd_get stops being called for the entry it could live indefinitely */
}
#endif /* PICO_SUPPORT_IPV6 */
