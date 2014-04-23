/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

Authors: Daniele Lacamera
 *********************************************************************/

#include "pico_config.h"
#include "pico_tree.h"
#include "pico_ipv6_nd.h"
#include "pico_icmp6.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_device.h"
#include "pico_eth.h"
#include "pico_addressing.h"

#ifdef PICO_SUPPORT_IPV6

/* configuration */
#define PICO_ND_MAX_FRAMES_QUEUED      3 /* max frames queued while awaiting address resolution */

/* RFC constants */
#define PICO_ND_MAX_SOLICIT            3
#define PICO_ND_MAX_NEIGHBOR_ADVERT    3
#define PICO_ND_DELAY_INCOMPLETE       1000 /* msec */
#define PICO_ND_DELAY_FIRST_PROBE_TIME 5000 /* msec */

/* neighbor discovery options */
#define PICO_ND_OPT_LLADDR_SRC         1
#define PICO_ND_OPT_LLADDR_TGT         2
#define PICO_ND_OPT_PREFIX             3
#define PICO_ND_OPT_REDIRECT           4
#define PICO_ND_OPT_MTU                5

/* advertisement flags */
#define PICO_ND_ROUTER_BIT             31u
#define PICO_ND_SOLICITED_BIT          30u
#define PICO_ND_OVERRIDE_BIT           29u
#define IS_ROUTER(x) (long_be(x->msg.info.neigh_adv.rsor) & (1u << PICO_ND_ROUTER_BIT)) /* router flag set? */
#define IS_SOLICITED(x) (long_be(x->msg.info.neigh_adv.rsor) & (1u << PICO_ND_SOLICITED_BIT)) /* solicited flag set? */
#define IS_OVERRIDE(x) (long_be(x->msg.info.neigh_adv.rsor) & (1u << PICO_ND_OVERRIDE_BIT)) /* override flag set? */

#define PICO_ND_PREFIX_LIFETIME_INF    0xFFFFFFFFu
#define PICO_ND_DESTINATION_LRU_TIME   600000u /* msecs (10min) */

#define nd_dbg(...) do {} while(0)


enum pico_ipv6_neighbor_state {
    PICO_ND_STATE_INCOMPLETE = 0,
    PICO_ND_STATE_REACHABLE,
    PICO_ND_STATE_STALE,
    PICO_ND_STATE_DELAY,
    PICO_ND_STATE_PROBE
};

struct pico_ipv6_neighbor {
    enum pico_ipv6_neighbor_state state;
    struct pico_ip6 address;
    struct pico_eth mac;
    struct pico_device *dev;
    uint16_t is_router;
    uint16_t failure_count;
    pico_time expire;
};

int pico_ipv6_neighbor_compare(void *ka, void *kb)
{
    struct pico_ipv6_neighbor *a = ka, *b = kb;
    return pico_ipv6_compare(&a->address, &b->address);
}


PICO_TREE_DECLARE(NCache, pico_ipv6_neighbor_compare);

static struct pico_ipv6_neighbor *pico_nd_find_neighbor(struct pico_ip6 *dst)
{
    struct pico_ipv6_neighbor test = { 0 };

    test.address = *dst;
    return pico_tree_findKey(&NCache, &test);
}

static struct pico_ipv6_neighbor *pico_nd_add(struct pico_ip6 *addr, struct pico_device *dev)
{
    struct pico_ipv6_neighbor *n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
    char address[120];
    if (!n)
        return NULL;
    pico_ipv6_to_string(address,addr->addr);
    nd_dbg("Adding address %s to cache...\n", address);
    memcpy(&n->address, addr, sizeof(struct pico_ip6));
    n->dev = dev;
    pico_tree_insert(&NCache, n);
    return n;
}

static void pico_nd_new_expire_time(struct pico_ipv6_neighbor *n)
{
    if (n->state == PICO_ND_STATE_INCOMPLETE)
        n->expire = PICO_TIME_MS() + PICO_ND_DELAY_INCOMPLETE;
    else if (n->state == PICO_ND_STATE_REACHABLE)
        n->expire = PICO_TIME_MS() + PICO_ND_DESTINATION_LRU_TIME;
    else if (n->state == PICO_ND_STATE_STALE) 
        n->expire = PICO_TIME_MS() + PICO_ND_DELAY_FIRST_PROBE_TIME;
    else
        n->expire = n->dev->hostvars.retranstime + PICO_TIME_MS();
    nd_dbg("Expiring in %lu ms \n", n->expire - PICO_TIME_MS());
}

static void pico_nd_new_expire_state(struct pico_ipv6_neighbor *n)
{
    if (n->state > PICO_ND_STATE_INCOMPLETE && n->state < PICO_ND_STATE_PROBE)
        n->state++;
}

static void pico_nd_discover(struct pico_ipv6_neighbor *n)
{
    if (n->expire != 0ull)
        return;
    if (++n->failure_count > PICO_ND_MAX_SOLICIT) {
        pico_tree_delete(&NCache, n);
        return;
    }
    if (n->state == PICO_ND_STATE_INCOMPLETE) {
        pico_icmp6_neighbor_solicitation(n->dev, &n->address, PICO_ICMP6_ND_SOLICITED);
    } else {
        pico_icmp6_neighbor_solicitation(n->dev, &n->address, PICO_ICMP6_ND_UNICAST);
    }
    pico_nd_new_expire_state(n);
    pico_nd_new_expire_time(n);
}


static struct pico_eth *pico_nd_get_neighbor(struct pico_ip6 *addr, struct pico_ipv6_neighbor *n, struct pico_device *dev)
{
    if (!n) {
        n = pico_nd_add(addr, dev);
        pico_nd_discover(n);
        return NULL;
    }
    if (n->state == PICO_ND_STATE_INCOMPLETE) {
        return NULL;
    }
    return &n->mac;

}
       

static struct pico_eth *pico_nd_get(struct pico_ip6 *address, struct pico_device *dev)
{
    struct pico_ip6 gateway = {{0}}, addr = {{0}};

    /* should we use gateway, or is dst local (gateway == 0)? */
    gateway = pico_ipv6_route_get_gateway(address);
    if (memcmp(gateway.addr, PICO_IP6_ANY, PICO_SIZE_IP6) == 0)
        addr = *address;
    else
        addr = gateway;
    return pico_nd_get_neighbor(&addr, pico_nd_find_neighbor(&addr), dev);
}

static int neigh_options(struct pico_frame *f, struct pico_icmp6_opt_lladdr *opt, uint8_t expected_opt)
{
    /* RFC 4861 $7.1.2 + $7.2.5.
     *  * The contents of any defined options that are not specified to be used
     *  * with Neighbor Advertisement messages MUST be ignored and the packet
     *  * processed as normal. The only defined option that may appear is the
     *  * Target Link-Layer Address option.
     *  */
    int optlen = 0;
    uint8_t *option = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    int len;
    uint8_t type;

    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    optlen = f->transport_len - PICO_ICMP6HDR_NEIGH_ADV_SIZE;
    if (optlen)
        option = icmp6_hdr->msg.info.neigh_adv.options;


    while (optlen) {
        type = ((struct pico_icmp6_opt_lladdr *)option)->type;
        len = ((struct pico_icmp6_opt_lladdr *)option)->len;
        optlen -= len * 8; /* len in units of 8 octets */
        if (len <= 0)
            return -1;

        if (type == expected_opt) {
            memcpy(opt, (struct pico_icmp6_opt_lladdr *)option, sizeof(struct pico_icmp6_opt_lladdr));
            break;
        } else if (optlen > 0) {
            option += len * 8;
        } else { /* no target link-layer address option */
            return -1;
        }
    }
    return 0;
}

static int neigh_adv_complete(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt)
{
    if (!opt)
        return -1;
    memcpy(n->mac.addr, opt->addr.mac.addr, PICO_SIZE_ETH);
    return 0;
}

static void neigh_adv_reconfirm_router_option(struct pico_ipv6_neighbor *n, unsigned int isRouter)
{
    if (!isRouter && n->is_router) {
        /* TODO: delete all routes going through this gateway */
    }
}


static int neigh_adv_reconfirm(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt, struct pico_icmp6_hdr *hdr)
{
    if (!IS_OVERRIDE(hdr)) {
        if (memcmp(opt->addr.mac.addr, n->mac.addr, PICO_SIZE_ETH) != 0)
            n->state = PICO_ND_STATE_STALE;
    } else {
        n->mac = opt->addr.mac;
    }
    neigh_adv_reconfirm_router_option(n, IS_ROUTER(hdr));
    return 0;
}

static void neigh_adv_check_solicited(struct pico_icmp6_hdr *ic6, struct pico_ipv6_neighbor *n)
{
    /* is a response to a solicitation? */
    if (IS_SOLICITED(ic6)) {
        n->state = PICO_ND_STATE_REACHABLE;
        n->failure_count = 0;
    } else {
        n->state = PICO_ND_STATE_STALE;
    }
    pico_nd_new_expire_time(n);
}

static int neigh_adv_process(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_neighbor *n = NULL;
    struct pico_icmp6_opt_lladdr opt = { 0 };

    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;


    n = pico_nd_find_neighbor(&icmp6_hdr->msg.info.neigh_adv.target);
    if (!n)
        return -1;

    if (neigh_options(f, &opt, PICO_ND_OPT_LLADDR_TGT) < 0)
        return -1;
    if (n->state == PICO_ND_STATE_INCOMPLETE)
        neigh_adv_complete(n, &opt);
    else
        neigh_adv_reconfirm(n, &opt, icmp6_hdr);
    neigh_adv_check_solicited(icmp6_hdr, n);
    return 0;

}

static struct pico_ipv6_neighbor *neighbor_from_sol_new(struct pico_ip6 *ip, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev)
{
    struct pico_ipv6_neighbor *n = NULL;
    n = pico_nd_add(ip, dev);
    if (!n)
        return NULL;
    memcpy(n->mac.addr, opt->addr.mac.addr, PICO_SIZE_ETH);
    n->state = PICO_ND_STATE_REACHABLE;
    return n;
}

static void neighbor_from_sol(struct pico_ip6 *ip, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev)
{
    struct pico_ipv6_neighbor *n = NULL;
    /* Hello, neighbor! */
    if (!pico_ipv6_is_unspecified(ip->addr) && opt) {
        n = pico_nd_find_neighbor(ip);
        if (!n) {
            n = neighbor_from_sol_new(ip, opt, dev);
        } else if (memcmp(opt->addr.mac.addr, n->mac.addr, PICO_SIZE_ETH)) {
            memcpy(n->mac.addr, opt->addr.mac.addr, PICO_SIZE_ETH);
            n->state = PICO_ND_STATE_STALE;
        }
        if (!n)
            return;
        pico_nd_new_expire_time(n);
    }
}

static int neigh_sol_process(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_icmp6_opt_lladdr opt = { 0 };
    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    neigh_options(f, &opt, PICO_ND_OPT_LLADDR_SRC);
    neighbor_from_sol(&ipv6_hdr->src, &opt, f->dev);
    if (!pico_ipv6_link_get(&icmp6_hdr->msg.info.neigh_adv.target)) { /* Not for us. */
        return -1;
    }

    pico_icmp6_neighbor_advertisement(f,  &icmp6_hdr->msg.info.neigh_adv.target);
    return 0;
}

static int icmp6_initial_checks(struct pico_frame *f)
{
    /* Common "step 0" validation */
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;

    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;

    if (ipv6_hdr->hop != 255 || pico_icmp6_checksum(f) != 0 || icmp6_hdr->code != 0)
        return -1;
    return 0;
}

static int neigh_adv_mcast_validity_check(struct pico_frame *f)
{
    /* Step 3 validation */
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;

    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (pico_ipv6_is_multicast(ipv6_hdr->dst.addr) && IS_SOLICITED(icmp6_hdr))
        return -1;
    return 0;
}

static int neigh_sol_mcast_validity_check(struct pico_frame *f)
{
    /* Step 3 validation */
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    if (pico_ipv6_is_unspecified(ipv6_hdr->src.addr) && !pico_ipv6_is_solicited(ipv6_hdr->dst.addr))
        return -1;
    return 0;
}

static int neigh_adv_validity_checks(struct pico_frame *f)
{
    /* Step 2 validation */
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    if (f->transport_len < PICO_ICMP6HDR_NEIGH_SOL_SIZE)
        return -1;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (pico_ipv6_is_multicast(icmp6_hdr->msg.info.neigh_adv.target.addr))
        return -1;
    return neigh_sol_mcast_validity_check(f);
}

static int neigh_sol_validity_checks(struct pico_frame *f) 
{
    /* Step 2 validation */
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    if (f->transport_len < PICO_ICMP6HDR_NEIGH_ADV_SIZE)
        return -1;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (pico_ipv6_is_multicast(icmp6_hdr->msg.info.neigh_adv.target.addr))
        return -1;
    return neigh_adv_mcast_validity_check(f);
}

static int neigh_adv_checks(struct pico_frame *f)
{
    /* Step 1 validation */
    if (icmp6_initial_checks(f) < 0)
        return -1;
    return neigh_adv_validity_checks(f);
}


static int pico_nd_router_sol_recv(struct pico_frame *f)
{
    /* Host only: router solicitation is discarded. */
    (void)f;
    return 0;
}

static int pico_nd_router_adv_recv(struct pico_frame *f)
{
    (void)f;
    /* TODO */
    return 0;
}

static int pico_nd_neigh_sol_recv(struct pico_frame *f)
{
    if (icmp6_initial_checks(f) < 0)
        return -1;
    if (neigh_sol_validity_checks(f) < 0)
        return -1;
    return neigh_sol_process(f);

}

static int pico_nd_neigh_adv_recv(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_link *link = NULL;

    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (neigh_adv_checks(f) < 0) {
        return -1;
    }

    link = pico_ipv6_link_istentative(&icmp6_hdr->msg.info.neigh_adv.target);
    if (link)
        link->isduplicate = 1;

    return neigh_adv_process(f);
}

static int pico_nd_redirect_recv(struct pico_frame *f)
{
    (void)f;
    /* TODO */
    return 0;
}

static void pico_ipv6_nd_timer_callback(pico_time now, void *arg)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv6_neighbor *n;

    (void)arg;
    pico_tree_foreach_safe(index, &NCache, _tmp)
    {
        n = index->keyValue;
        if ( now > n->expire) {
            n->expire = 0ull;
            pico_nd_discover(n);
        }
    }

    pico_timer_add(200, pico_ipv6_nd_timer_callback, NULL);
}


/* Public API */

struct pico_eth *pico_ipv6_get_neighbor(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    struct pico_ipv6_link *l = NULL;
    if (!f)
        return NULL;

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    /* If we are still probing for Duplicate Address, abort now. */
    if (pico_ipv6_link_istentative(&hdr->src))
        return NULL;

    /* address belongs to ourselves? */
    l = pico_ipv6_link_get(&hdr->dst);
    if (l)
        return &l->dev->eth->mac;

    return pico_nd_get(&hdr->dst, f->dev);
}

int pico_ipv6_nd_recv(struct pico_frame *f)
{

    struct pico_icmp6_hdr *hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    int ret = -1;
    switch(hdr->type) {
        case PICO_ICMP6_ROUTER_SOL:
            nd_dbg("ICMP6: received ROUTER SOL\n");
            ret = pico_nd_router_sol_recv(f);
            break;

        case PICO_ICMP6_ROUTER_ADV:
            ret = pico_nd_router_adv_recv(f);
            break;

        case PICO_ICMP6_NEIGH_SOL:
            nd_dbg("ICMP6: received NEIGH SOL\n");
            ret = pico_nd_neigh_sol_recv(f);
            break;

        case PICO_ICMP6_NEIGH_ADV:
            nd_dbg("ICMP6: received NEIGH ADV\n");
            ret = pico_nd_neigh_adv_recv(f);
            break;

        case PICO_ICMP6_REDIRECT:
            ret = pico_nd_redirect_recv(f);
            break;
    }
    pico_frame_discard(f);
    return ret;
}

void pico_ipv6_nd_init(void)
{
    pico_timer_add(200, pico_ipv6_nd_timer_callback, NULL);
}

#endif
