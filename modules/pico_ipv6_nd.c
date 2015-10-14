/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/

#include "pico_config.h"
#include "pico_tree.h"
#include "pico_icmp6.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_device.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"

#ifdef PICO_SUPPORT_IPV6


#define nd_dbg(...) do {} while(0)

static struct pico_frame *frames_queued_v6[PICO_ND_MAX_FRAMES_QUEUED] = { 0 };


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

static int pico_ipv6_neighbor_compare(void *ka, void *kb)
{
    struct pico_ipv6_neighbor *a = ka, *b = kb;
    return pico_ipv6_compare(&a->address, &b->address);
}


PICO_TREE_DECLARE(NCache, pico_ipv6_neighbor_compare);

static struct pico_ipv6_neighbor *pico_nd_find_neighbor(struct pico_ip6 *dst)
{
    struct pico_ipv6_neighbor test = {
        0
    };

    test.address = *dst;
    return pico_tree_findKey(&NCache, &test);
}

static void pico_ipv6_nd_queued_trigger(void)
{
    int i;
    struct pico_frame *f;
    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; i++)
    {
        f = frames_queued_v6[i];
        if (f) {
            (void)pico_ethernet_send(f);
            if(frames_queued_v6[i])
              pico_frame_discard(frames_queued_v6[i]);
            frames_queued_v6[i] = NULL;
        }
    }
}

static void ipv6_duplicate_detected(struct pico_ipv6_link *l)
{
    struct pico_device *dev;
    int is_ll = pico_ipv6_is_linklocal(l->address.addr);
    dev = l->dev;
    dbg("IPV6: Duplicate address detected. Removing link.\n");
    pico_ipv6_link_del(l->dev, l->address);
    if (is_ll)
        pico_device_ipv6_random_ll(dev);
}

static struct pico_ipv6_neighbor *pico_nd_add(struct pico_ip6 *addr, struct pico_device *dev)
{
    struct pico_ipv6_neighbor *n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
    char address[120];
    if (!n)
        return NULL;

    pico_ipv6_to_string(address, addr->addr);
    nd_dbg("Adding address %s to cache...\n", address);
    memcpy(&n->address, addr, sizeof(struct pico_ip6));
    n->dev = dev;
    pico_tree_insert(&NCache, n);
    return n;
}

static void pico_ipv6_nd_unreachable(struct pico_ip6 *a)
{
    int i;
    struct pico_frame *f;
    struct pico_ipv6_hdr *hdr;
    struct pico_ip6 dst;
    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; i++)
    {
        f = frames_queued_v6[i];
        if (f) {
            hdr = (struct pico_ipv6_hdr *) f->net_hdr;
            dst = pico_ipv6_route_get_gateway(&hdr->dst);
            if (pico_ipv6_is_unspecified(dst.addr))
                dst = hdr->dst;

            if (memcmp(dst.addr, a->addr, PICO_SIZE_IP6) == 0) {
                if (!pico_source_is_local(f)) {
                    pico_notify_dest_unreachable(f);
                }

                pico_frame_discard(f);
                frames_queued_v6[i] = NULL;
            }
        }
    }
}

static void pico_nd_new_expire_time(struct pico_ipv6_neighbor *n)
{
    if (n->state == PICO_ND_STATE_REACHABLE)
        n->expire = PICO_TIME_MS() + PICO_ND_REACHABLE_TIME;
    else if ((n->state == PICO_ND_STATE_DELAY) || (n->state == PICO_ND_STATE_STALE))
        n->expire = PICO_TIME_MS() + PICO_ND_DELAY_FIRST_PROBE_TIME;
    else {
        n->expire = n->dev->hostvars.retranstime + PICO_TIME_MS();
    }
}

static void pico_nd_discover(struct pico_ipv6_neighbor *n)
{
    char IPADDR[64];
    if (n->expire != (pico_time)0)
        return;

    pico_ipv6_to_string(IPADDR, n->address.addr);
    /* dbg("Sending NS for %s\n", IPADDR); */
    if (++n->failure_count > PICO_ND_MAX_SOLICIT)
        return;

    if (n->state == PICO_ND_STATE_INCOMPLETE) {
        pico_icmp6_neighbor_solicitation(n->dev, &n->address, PICO_ICMP6_ND_SOLICITED);
    } else {
        pico_icmp6_neighbor_solicitation(n->dev, &n->address, PICO_ICMP6_ND_UNICAST);
    }

    pico_nd_new_expire_time(n);
}

static struct pico_eth *pico_nd_get_neighbor(struct pico_ip6 *addr, struct pico_ipv6_neighbor *n, struct pico_device *dev)
{
    /* dbg("Finding neighbor %02x:...:%02x, state = %d\n", addr->addr[0], addr->addr[15], n?n->state:-1); */

    if (!n) {
        n = pico_nd_add(addr, dev);
        pico_nd_discover(n);
        return NULL;
    }

    if (n->state == PICO_ND_STATE_INCOMPLETE) {
        return NULL;
    }

    if (n->state == PICO_ND_STATE_STALE) {
        n->state = PICO_ND_STATE_DELAY;
        pico_nd_new_expire_time(n);
    }

    if (n->state != PICO_ND_STATE_REACHABLE)
        pico_nd_discover(n);

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
    int found = 0;

    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    optlen = f->transport_len - PICO_ICMP6HDR_NEIGH_ADV_SIZE;
    if (optlen)
        option = ((uint8_t *)&icmp6_hdr->msg.info.neigh_adv) + sizeof(struct neigh_adv_s);

    while (optlen > 0) {
        type = ((struct pico_icmp6_opt_lladdr *)option)->type;
        len = ((struct pico_icmp6_opt_lladdr *)option)->len;
        optlen -= len << 3; /* len in units of 8 octets */
        if (len <= 0)
            return -1; /* malformed option. */

        if (type == expected_opt) {
            if (found > 0)
                return -1; /* malformed option: option is there twice. */

            memcpy(opt, (struct pico_icmp6_opt_lladdr *)option, (size_t)(len << 3));
            found++;
        }

        if (optlen > 0) {
            option += len << 3;
        } else { /* parsing options: terminated. */
            return found;
        }
    }
    return found;
}

static void pico_ipv6_neighbor_update(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt)
{
    memcpy(n->mac.addr, opt->addr.mac.addr, PICO_SIZE_ETH);
}

static int pico_ipv6_neighbor_compare_stored(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt)
{
    return memcmp(n->mac.addr, opt->addr.mac.addr, PICO_SIZE_ETH);
}

static void neigh_adv_reconfirm_router_option(struct pico_ipv6_neighbor *n, unsigned int isRouter)
{
    if (!isRouter && n->is_router) {
        pico_ipv6_router_down(&n->address);
    }

    if (isRouter)
        n->is_router = 1;
    else
        n->is_router = 0;
}


static int neigh_adv_reconfirm_no_tlla(struct pico_ipv6_neighbor *n, struct pico_icmp6_hdr *hdr)
{
    if (IS_SOLICITED(hdr)) {
        n->state = PICO_ND_STATE_REACHABLE;
        n->failure_count = 0;
        pico_ipv6_nd_queued_trigger();
        pico_nd_new_expire_time(n);
        return 0;
    }

    return -1;
}


static int neigh_adv_reconfirm(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt, struct pico_icmp6_hdr *hdr)
{

    if (IS_SOLICITED(hdr) && !IS_OVERRIDE(hdr) && (pico_ipv6_neighbor_compare_stored(n, opt) == 0)) {
        n->state = PICO_ND_STATE_REACHABLE;
        n->failure_count = 0;
        pico_ipv6_nd_queued_trigger();
        pico_nd_new_expire_time(n);
        return 0;
    }

    if ((n->state == PICO_ND_STATE_REACHABLE) && IS_SOLICITED(hdr) && !IS_OVERRIDE(hdr)) {
        n->state = PICO_ND_STATE_STALE;
        return 0;
    }

    if (IS_SOLICITED(hdr) && IS_OVERRIDE(hdr)) {
        pico_ipv6_neighbor_update(n, opt);
        n->state = PICO_ND_STATE_REACHABLE;
        n->failure_count = 0;
        pico_ipv6_nd_queued_trigger();
        pico_nd_new_expire_time(n);
        return 0;
    }

    if (!IS_SOLICITED(hdr) && IS_OVERRIDE(hdr) && (pico_ipv6_neighbor_compare_stored(n, opt) != 0)) {
        pico_ipv6_neighbor_update(n, opt);
        n->state = PICO_ND_STATE_STALE;
        pico_ipv6_nd_queued_trigger();
        pico_nd_new_expire_time(n);
        return 0;
    }

    if ((n->state == PICO_ND_STATE_REACHABLE) && (!IS_SOLICITED(hdr)) && (!IS_OVERRIDE(hdr)) &&
        (pico_ipv6_neighbor_compare_stored(n, opt) != 0)) {

        /* I.  If the Override flag is clear and the supplied link-layer address
         *     differs from that in the cache, then one of two actions takes
         *     place:
         *     a. If the state of the entry is REACHABLE, set it to STALE, but
         *        do not update the entry in any other way.
         *     b. Otherwise, the received advertisement should be ignored and
         *        MUST NOT update the cache.
         */
        n->state = PICO_ND_STATE_STALE;
        pico_nd_new_expire_time(n);
        return 0;
    }

    return -1;
}

static void neigh_adv_process_incomplete(struct pico_ipv6_neighbor *n, struct pico_frame *f, struct pico_icmp6_opt_lladdr *opt)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    if (!n || !f)
        return;

    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;

    if (!icmp6_hdr)
        return;

    if (IS_SOLICITED(icmp6_hdr)) {
        n->state = PICO_ND_STATE_REACHABLE;
        n->failure_count = 0;
        pico_nd_new_expire_time(n);
    } else {
        n->state = PICO_ND_STATE_STALE;
    }

    if (opt)
        pico_ipv6_neighbor_update(n, opt);

    pico_ipv6_nd_queued_trigger();
}


static int neigh_adv_process(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_neighbor *n = NULL;
    struct pico_icmp6_opt_lladdr opt = {
        0
    };
    int optres = neigh_options(f, &opt, PICO_ND_OPT_LLADDR_TGT);
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;

    if (optres < 0) { /* Malformed packet: option field cannot be processed. */
        return -1;
    }

    n = pico_nd_find_neighbor(&icmp6_hdr->msg.info.neigh_adv.target);
    if (!n) {
        return 0;
    }

    if ((optres == 0) || IS_OVERRIDE(icmp6_hdr) || (pico_ipv6_neighbor_compare_stored(n, &opt) == 0)) {
        neigh_adv_reconfirm_router_option(n, IS_ROUTER(icmp6_hdr));
    }

    if ((optres > 0) && (n->state == PICO_ND_STATE_INCOMPLETE)) {
        neigh_adv_process_incomplete(n, f, &opt);
        return 0;
    }

    if (optres > 0)
        return neigh_adv_reconfirm(n, &opt, icmp6_hdr);
    else
        return neigh_adv_reconfirm_no_tlla(n, icmp6_hdr);

}



static struct pico_ipv6_neighbor *pico_ipv6_neighbor_from_sol_new(struct pico_ip6 *ip, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev)
{
    struct pico_ipv6_neighbor *n = NULL;
    n = pico_nd_add(ip, dev);
    if (!n)
        return NULL;

    memcpy(n->mac.addr, opt->addr.mac.addr, PICO_SIZE_ETH);
    n->state = PICO_ND_STATE_STALE;
    pico_ipv6_nd_queued_trigger();
    return n;
}

static void pico_ipv6_neighbor_from_unsolicited(struct pico_frame *f)
{
    struct pico_ipv6_neighbor *n = NULL;
    struct pico_icmp6_opt_lladdr opt = {
        0
    };
    struct pico_ipv6_hdr *ip = (struct pico_ipv6_hdr *)f->net_hdr;
    int valid_lladdr = neigh_options(f, &opt, PICO_ND_OPT_LLADDR_SRC);

    if (!pico_ipv6_is_unspecified(ip->src.addr) && (valid_lladdr > 0)) {
        n = pico_nd_find_neighbor(&ip->src);
        if (!n) {
            n = pico_ipv6_neighbor_from_sol_new(&ip->src, &opt, f->dev);
        } else if (memcmp(opt.addr.mac.addr, n->mac.addr, PICO_SIZE_ETH)) {
            pico_ipv6_neighbor_update(n, &opt);
            n->state = PICO_ND_STATE_STALE;
            pico_ipv6_nd_queued_trigger();
            pico_nd_new_expire_time(n);
        }

        if (!n)
            return;
    }
}

static int neigh_sol_detect_dad(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_link *link = NULL;
    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    link = pico_ipv6_link_istentative(&icmp6_hdr->msg.info.neigh_adv.target);
    if (link) {
        if (pico_ipv6_is_unicast(&ipv6_hdr->src))
        {
            /* RFC4862 5.4.3 : sender is performing address resolution,
             * our address is not yet valid, discard silently.
             */
            dbg("DAD:Sender performing AR\n");
        }

        else if (pico_ipv6_is_unspecified(ipv6_hdr->src.addr) &&
                 !pico_ipv6_is_allhosts_multicast(ipv6_hdr->dst.addr))
        {
            /* RFC4862 5.4.3 : sender is performing DaD */
            dbg("DAD:Sender performing DaD\n");
            ipv6_duplicate_detected(link);
        }

        return 0;
    }

    return -1; /* Current link is not tentative */
}

static int neigh_sol_process(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_link *link = NULL;
    int valid_lladdr;
    struct pico_icmp6_opt_lladdr opt = {
        0
    };
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;

    valid_lladdr = neigh_options(f, &opt, PICO_ND_OPT_LLADDR_SRC);
    pico_ipv6_neighbor_from_unsolicited(f);

    if ((valid_lladdr == 0) && (neigh_sol_detect_dad(f) == 0))
        return 0;

    if (valid_lladdr < 0)
        return -1; /* Malformed packet. */

    link = pico_ipv6_link_get(&icmp6_hdr->msg.info.neigh_adv.target);
    if (!link) { /* Not for us. */
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

    /* RFC4861 - 7.1.2 :
     *       - The IP Hop Limit field has a value of 255, i.e., the packet
     *               could not possibly have been forwarded by a router.
     *       - ICMP Checksum is valid.
     *       - ICMP Code is 0.
     */
    if (ipv6_hdr->hop != 255 || pico_icmp6_checksum(f) != 0 || icmp6_hdr->code != 0)
        return -1;

    return 0;
}

static int neigh_adv_option_len_validity_check(struct pico_frame *f)
{
    /* Step 4 validation */
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    uint8_t *opt;
    int optlen = f->transport_len - PICO_ICMP6HDR_NEIGH_ADV_SIZE;
    /* RFC4861 - 7.1.2 :
     *       - All included options have a length that is greater than zero.
     */
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    opt = ((uint8_t *)&icmp6_hdr->msg.info.neigh_adv) + sizeof(struct neigh_adv_s);

    while(optlen > 0) {
        int opt_size = (opt[1] << 3);
        if (opt_size == 0)
            return -1;

        opt = opt + opt_size;
        optlen -= opt_size;
    }
    return 0;
}

static int neigh_adv_mcast_validity_check(struct pico_frame *f)
{
    /* Step 3 validation */
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    /* RFC4861 - 7.1.2 :
     *       - If the IP Destination Address is a multicast address the
     *         Solicited flag is zero.
     */
    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (pico_ipv6_is_multicast(ipv6_hdr->dst.addr) && IS_SOLICITED(icmp6_hdr))
        return -1;

    return neigh_adv_option_len_validity_check(f);
}

static int neigh_adv_validity_checks(struct pico_frame *f)
{
    /* Step 2 validation */
    /* RFC4861 - 7.1.2:
     * - ICMP length (derived from the IP length) is 24 or more octets.
     */
    if (f->transport_len < PICO_ICMP6HDR_NEIGH_ADV_SIZE)
        return -1;

    return neigh_adv_mcast_validity_check(f);
}


static int neigh_sol_mcast_validity_check(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (pico_ipv6_is_solnode_multicast(icmp6_hdr->msg.info.neigh_sol.target.addr, f->dev) == 0)
        return -1;

    return 0;
}

static int neigh_sol_unicast_validity_check(struct pico_frame *f)
{
    struct pico_ipv6_link *link;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;

    link = pico_ipv6_link_by_dev(f->dev);
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    while(link) {
        if (pico_ipv6_compare(&link->address, &icmp6_hdr->msg.info.neigh_sol.target) == 0)
            return 0;

        link = pico_ipv6_link_by_dev_next(f->dev, link);
    }
    return -1;

}

static int neigh_sol_validate_unspec(struct pico_frame *f)
{
    /* RFC4861, 7.1.1:
     *
     * - If the IP source address is the unspecified address, the IP
     *   destination address is a solicited-node multicast address.
     *
     * - If the IP source address is the unspecified address, there is no
     *   source link-layer address option in the message.
     *
     */

    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)(f->net_hdr);
    struct pico_icmp6_opt_lladdr opt = {
        0
    };
    int valid_lladdr = neigh_options(f, &opt, PICO_ND_OPT_LLADDR_SRC);
    if (pico_ipv6_is_solnode_multicast(hdr->dst.addr, f->dev) == 0) {
        return -1;
    }

    if (valid_lladdr) {
        return -1;
    }

    return 0;
}

static int neigh_sol_validity_checks(struct pico_frame *f)
{
    /* Step 2 validation */
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)(f->net_hdr);
    if (f->transport_len < PICO_ICMP6HDR_NEIGH_ADV_SIZE)
        return -1;

    if ((pico_ipv6_is_unspecified(hdr->src.addr)) && (neigh_sol_validate_unspec(f) < 0))
    {
        return -1;
    }

    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    if (pico_ipv6_is_multicast(icmp6_hdr->msg.info.neigh_adv.target.addr)) {
        return neigh_sol_mcast_validity_check(f);
    }

    return neigh_sol_unicast_validity_check(f);
}

static int router_adv_validity_checks(struct pico_frame *f)
{
    /* Step 2 validation */
    if (f->transport_len < PICO_ICMP6HDR_ROUTER_ADV_SIZE)
        return -1;

    return 0;
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
    pico_ipv6_neighbor_from_unsolicited(f);
    /* Host only: router solicitation is discarded. */
    return 0;
}

static int radv_process(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    uint8_t *nxtopt, *opt_start;
    struct pico_ipv6_link *link;
    struct pico_ipv6_hdr *hdr;
    struct pico_ip6 zero = {
        .addr = {0}
    };
    int optlen;

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    optlen = f->transport_len - PICO_ICMP6HDR_ROUTER_ADV_SIZE;
    opt_start = ((uint8_t *)&icmp6_hdr->msg.info.router_adv) + sizeof(struct router_adv_s);
    nxtopt = opt_start;

    while (optlen > 0) {
        uint8_t *type = (uint8_t *)nxtopt;
        switch (*type) {
        case PICO_ND_OPT_PREFIX:
        {
            pico_time now = PICO_TIME_MS();
            struct pico_icmp6_opt_prefix *prefix =
                (struct pico_icmp6_opt_prefix *) nxtopt;
            /* RFC4862 5.5.3 */
            /* a) If the Autonomous flag is not set, silently ignore the Prefix
             *       Information option.
             */
            if (prefix->aac == 0)
                goto ignore_opt_prefix;

            /* b) If the prefix is the link-local prefix, silently ignore the
             *       Prefix Information option
             */
            if (pico_ipv6_is_linklocal(prefix->prefix.addr))
                goto ignore_opt_prefix;

            /* c) If the preferred lifetime is greater than the valid lifetime,
             *       silently ignore the Prefix Information option
             */
            if (long_be(prefix->pref_lifetime) > long_be(prefix->val_lifetime))
                goto ignore_opt_prefix;

            if (prefix->val_lifetime == 0)
                goto ignore_opt_prefix;


            if (prefix->prefix_len != 64) {
                return -1;
            }

            link = pico_ipv6_prefix_configured(&prefix->prefix);
            if (link) {
                pico_ipv6_lifetime_set(link, now + (pico_time)(1000 * (long_be(prefix->val_lifetime))));
                goto ignore_opt_prefix;
            }

            link = pico_ipv6_link_add_local(f->dev, &prefix->prefix);
            if (link) {
                pico_ipv6_lifetime_set(link, now + (pico_time)(1000 * (long_be(prefix->val_lifetime))));
                pico_ipv6_route_add(zero, zero, hdr->src, 10, link);
            }

ignore_opt_prefix:
            optlen -= (prefix->len << 3);
            nxtopt += (prefix->len << 3);
        }
        break;
        case PICO_ND_OPT_LLADDR_SRC:
        {
            struct pico_icmp6_opt_lladdr *lladdr_src =
                (struct pico_icmp6_opt_lladdr *) nxtopt;
            optlen -= (lladdr_src->len << 3);
            nxtopt += (lladdr_src->len << 3);
        }
        break;
        case PICO_ND_OPT_MTU:
        {
            struct pico_icmp6_opt_mtu *mtu =
                (struct pico_icmp6_opt_mtu *) nxtopt;
            /* Skip this */
            optlen -= (mtu->len << 3);
            nxtopt += (mtu->len << 3);
        }
        break;
        case PICO_ND_OPT_REDIRECT:
        {
            struct pico_icmp6_opt_redirect *redirect =
                (struct pico_icmp6_opt_redirect *) nxtopt;
            /* Skip this */
            optlen -= (redirect->len << 3);
            nxtopt += (redirect->len << 3);

        }
        break;
        case PICO_ND_OPT_RDNSS:
        {
            struct pico_icmp6_opt_rdnss *rdnss =
                (struct pico_icmp6_opt_rdnss *) nxtopt;
            /* Skip this */
            optlen -= (rdnss->len << 3);
            nxtopt += (rdnss->len << 3);
        }
        break;
        default:
            pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_IPV6OPT,
                                         (uint32_t)sizeof(struct pico_ipv6_hdr) + (uint32_t)PICO_ICMP6HDR_ROUTER_ADV_SIZE + (uint32_t)(nxtopt - opt_start));
            return -1;
        }
    }
    if (icmp6_hdr->msg.info.router_adv.retrans_time != 0u) {
        f->dev->hostvars.retranstime = long_be(icmp6_hdr->msg.info.router_adv.retrans_time);
    }

    return 0;
}


static int pico_nd_router_adv_recv(struct pico_frame *f)
{
    if (icmp6_initial_checks(f) < 0)
        return -1;

    if (router_adv_validity_checks(f) < 0)
        return -1;

    pico_ipv6_neighbor_from_unsolicited(f);
    return radv_process(f);
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
        ipv6_duplicate_detected(link);

    return neigh_adv_process(f);
}

static int pico_nd_redirect_recv(struct pico_frame *f)
{
    pico_ipv6_neighbor_from_unsolicited(f);
    /* TODO */
    return 0;
}

static void pico_ipv6_nd_timer_elapsed(pico_time now, struct pico_ipv6_neighbor *n)
{
    (void)now;
    switch(n->state) {
    case PICO_ND_STATE_INCOMPLETE:
    /* intentional fall through */
    case PICO_ND_STATE_PROBE:
        if (n->failure_count > PICO_ND_MAX_SOLICIT) {
            pico_ipv6_nd_unreachable(&n->address);
            pico_tree_delete(&NCache, n);
            PICO_FREE(n);
            return;
        }

        n->expire = 0ull;
        pico_nd_discover(n);
        break;

    case PICO_ND_STATE_REACHABLE:
        n->state = PICO_ND_STATE_STALE;
        /* dbg("IPv6_ND: neighbor expired!\n"); */
        return;

    case PICO_ND_STATE_STALE:
        break;

    case PICO_ND_STATE_DELAY:
        n->expire = 0ull;
        n->state = PICO_ND_STATE_PROBE;
        break;
    default:
        dbg("IPv6_ND: neighbor in wrong state!\n");
    }
    pico_nd_new_expire_time(n);
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
            pico_ipv6_nd_timer_elapsed(now, n);
        }
    }
    pico_timer_add(200, pico_ipv6_nd_timer_callback, NULL);
}

#define PICO_IPV6_ND_MIN_RADV_INTERVAL  (5000)
#define PICO_IPV6_ND_MAX_RADV_INTERVAL (15000)

static void pico_ipv6_nd_ra_timer_callback(pico_time now, void *arg)
{
    struct pico_tree_node *devindex = NULL;
    struct pico_tree_node *rindex = NULL;
    struct pico_device *dev;
    struct pico_ipv6_route *rt;
    struct pico_ip6 nm64 = { {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0 } };
    pico_time next_timer_expire = 0u;

    (void)arg;
    (void)now;
    pico_tree_foreach(rindex, &IPV6Routes)
    {
        rt = rindex->keyValue;
        if (pico_ipv6_compare(&nm64, &rt->netmask) == 0) {
            pico_tree_foreach(devindex, &Device_tree) {
                dev = devindex->keyValue;
                if ((!pico_ipv6_is_linklocal(rt->dest.addr)) && dev->hostvars.routing && (rt->link) && (dev != rt->link->dev)) {
                    pico_icmp6_router_advertisement(dev, &rt->dest);
                }
            }
        }
    }
    next_timer_expire = PICO_IPV6_ND_MIN_RADV_INTERVAL + (pico_rand() % (PICO_IPV6_ND_MAX_RADV_INTERVAL - PICO_IPV6_ND_MIN_RADV_INTERVAL));
    pico_timer_add(next_timer_expire, pico_ipv6_nd_ra_timer_callback, NULL);
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

void pico_ipv6_nd_postpone(struct pico_frame *f)
{
    int i;
    static int last_enq = -1;
    struct pico_frame *cp = pico_frame_copy(f);
    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; i++)
    {
        if (!frames_queued_v6[i]) {
            frames_queued_v6[i] = cp;
            last_enq = i;
            return;
        }
    }
    /* Overwrite the oldest frame in the buffer */
    if (++last_enq >= PICO_ND_MAX_FRAMES_QUEUED) {
        last_enq = 0;
    }

    if (frames_queued_v6[last_enq])
        pico_frame_discard(frames_queued_v6[last_enq]);

    frames_queued_v6[last_enq] = cp;
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
    pico_timer_add(200, pico_ipv6_nd_ra_timer_callback, NULL);
    pico_timer_add(1000, pico_ipv6_check_lifetime_expired, NULL);
}

#endif
