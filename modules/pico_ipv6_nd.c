/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

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
#include "pico_ethernet.h"
#include "pico_6lowpan.h"
#include "pico_6lowpan_ll.h"

#ifdef PICO_SUPPORT_IPV6

#ifdef DEBUG_IPV6_ND
#define nd_dbg dbg
#else
#define nd_dbg(...) do {} while(0)
#endif

#define ONE_MINUTE                          ((pico_time)(1000 * 60))

#ifdef PICO_SUPPORT_6LOWPAN
    #define MAX_RTR_SOLICITATIONS           (3)
    #define RTR_SOLICITATION_INTERVAL       (10000)
    #define MAX_RTR_SOLICITATION_INTERVAL   (60000)
#endif

static struct pico_frame *frames_queued_v6[PICO_ND_MAX_FRAMES_QUEUED] = {
    0
};

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
    union pico_hw_addr hwaddr;
    struct pico_device *dev;
    uint16_t is_router;
    uint16_t failure_count;
    pico_time expire;
};

/******************************************************************************
 *  Function prototypes
 ******************************************************************************/

#ifdef PICO_SUPPORT_6LOWPAN
static void pico_6lp_nd_deregister(struct pico_ipv6_link *);
static void pico_6lp_nd_unreachable_gateway(struct pico_ip6 *a);
static int pico_6lp_nd_neigh_adv_process(struct pico_frame *f);
static int neigh_sol_detect_dad_6lp(struct pico_frame *f);
#endif

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
            if (pico_datalink_send(f) <= 0)
                pico_frame_discard(f);
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
#ifdef PICO_SUPPORT_6LOWPAN
    if (PICO_DEV_IS_6LOWPAN(l->dev)) {
        pico_6lp_nd_deregister(l);
    }
#endif
    if (is_ll)
        pico_device_ipv6_random_ll(dev);
}

static struct pico_ipv6_neighbor *pico_nd_add(struct pico_ip6 *addr, struct pico_device *dev)
{
    struct pico_ipv6_neighbor *n;
    char address[120];
    /* Create a new NCE */
    n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
    if (!n)
        return NULL;
    pico_ipv6_to_string(address, addr->addr);
    memcpy(&n->address, addr, sizeof(struct pico_ip6));
    n->dev = dev;

    if (pico_tree_insert(&NCache, n)) {
        nd_dbg("IPv6 ND: Failed to insert neigbor in tree\n");
		PICO_FREE(n);
		return NULL;
	}

    return n;
}

static void pico_ipv6_nd_unreachable(struct pico_ip6 *a)
{
    int i;
    struct pico_frame *f;
    struct pico_ipv6_hdr *hdr;
    struct pico_ip6 dst;
#ifdef PICO_SUPPORT_6LOWPAN
    /* 6LP: Find any 6LoWPAN-hosts for which this address might have been a default gateway.
     * If such a host found, send a router solicitation again */
    pico_6lp_nd_unreachable_gateway(a);
#endif /* PICO_SUPPORT_6LOWPAN */
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

    if (!n) {
        return;
    } else {
        if (n->expire != (pico_time)0) {
            return;
        } else {
            pico_ipv6_to_string(IPADDR, n->address.addr);
            /* dbg("Sending NS for %s\n", IPADDR); */
            if (++n->failure_count > PICO_ND_MAX_SOLICIT)
                return;

            if (n->state == PICO_ND_STATE_INCOMPLETE) {
                pico_icmp6_neighbor_solicitation(n->dev, &n->address, PICO_ICMP6_ND_SOLICITED, &n->address);
            } else {
                pico_icmp6_neighbor_solicitation(n->dev, &n->address, PICO_ICMP6_ND_UNICAST, &n->address);
            }

            pico_nd_new_expire_time(n);
        }
    }
}

static struct pico_eth *pico_nd_get_neighbor(struct pico_ip6 *addr, struct pico_ipv6_neighbor *n, struct pico_device *dev)
{
    /* dbg("Finding neighbor %02x:...:%02x, state = %d\n", addr->addr[0], addr->addr[15], n?n->state:-1); */

    if (!n) {
        n = pico_nd_add(addr, dev);
        pico_nd_discover(n);
        return NULL;
    } else {
        if (n->state == PICO_ND_STATE_INCOMPLETE) {
            return NULL;
        } else if (n->state == PICO_ND_STATE_STALE) {
            n->state = PICO_ND_STATE_DELAY;
            pico_nd_new_expire_time(n);
        }

        if (n->state != PICO_ND_STATE_REACHABLE) {
            pico_nd_discover(n);
        }
    }
    return &n->hwaddr.mac;
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

static int nd_options(uint8_t *options, struct pico_icmp6_opt_lladdr *opt, uint8_t expected_opt, int optlen, int len)
{
    uint8_t type = 0;
    int found = 0;

    while (optlen > 0) {
        type = ((struct pico_icmp6_opt_lladdr *)options)->type;
        len = ((struct pico_icmp6_opt_lladdr *)options)->len;
        optlen -= len << 3; /* len in units of 8 octets */
        if (len <= 0)
            return -1; /* malformed option. */

        if (type == expected_opt) {
            if (found > 0)
                return -1; /* malformed option: option is there twice. */

            memcpy(opt, (struct pico_icmp6_opt_lladdr *)options, sizeof(struct pico_icmp6_opt_lladdr));
            found++;
        }

        if (optlen > 0) {
            options += len << 3;
        } else { /* parsing options: terminated. */
            return found;
        }
    }
    return found;
}

static int neigh_options(struct pico_frame *f, struct pico_icmp6_opt_lladdr *opt, uint8_t expected_opt)
{
    /* RFC 4861 $7.1.2 + $7.2.5.
     *  * The contents of any defined options that are not specified to be used
     *  * with Neighbor Advertisement messages MUST be ignored and the packet
     *  * processed as normal. The only defined option that may appear is the
     *  * Target Link-Layer Address option.
     *  */
    struct pico_icmp6_hdr *icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    uint8_t *option = NULL;
    int optlen = 0;
    int len = 0;

    optlen = f->transport_len - PICO_ICMP6HDR_NEIGH_ADV_SIZE;
    if (optlen)
        option = ((uint8_t *)&icmp6_hdr->msg.info.neigh_adv) + sizeof(struct neigh_adv_s);

    return nd_options(option, opt, expected_opt, optlen, len);
}

static size_t pico_hw_addr_len(struct pico_device *dev, struct pico_icmp6_opt_lladdr *opt)
{
    size_t len = PICO_SIZE_ETH;
#ifndef PICO_SUPPORT_6LOWPAN
    IGNORE_PARAMETER(dev);
    IGNORE_PARAMETER(opt);
#else
    if (PICO_DEV_IS_6LOWPAN(dev)) {
        if (1 == opt->len) {
            len = (size_t)SIZE_6LOWPAN_SHORT;
        } else {
            len = (size_t)SIZE_6LOWPAN_EXT;
        }
    }
#endif
    return len;
}

static void pico_ipv6_neighbor_update(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev)
{
    memcpy(n->hwaddr.data, opt->addr.data, pico_hw_addr_len(dev, opt));
}

static int pico_ipv6_neighbor_compare_stored(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev)
{
    return memcmp(n->hwaddr.data, opt->addr.data, pico_hw_addr_len(dev, opt));
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


static int neigh_adv_reconfirm(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt, struct pico_icmp6_hdr *hdr, struct pico_device *dev)
{

    if (IS_SOLICITED(hdr) && !IS_OVERRIDE(hdr) && (pico_ipv6_neighbor_compare_stored(n, opt, dev) == 0)) {
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
        pico_ipv6_neighbor_update(n, opt, dev);
        n->state = PICO_ND_STATE_REACHABLE;
        n->failure_count = 0;
        pico_ipv6_nd_queued_trigger();
        pico_nd_new_expire_time(n);
        return 0;
    }

    if (!IS_SOLICITED(hdr) && IS_OVERRIDE(hdr) && (pico_ipv6_neighbor_compare_stored(n, opt, dev) != 0)) {
        pico_ipv6_neighbor_update(n, opt, dev);
        n->state = PICO_ND_STATE_STALE;
        pico_ipv6_nd_queued_trigger();
        pico_nd_new_expire_time(n);
        return 0;
    }

    if ((n->state == PICO_ND_STATE_REACHABLE) && (!IS_SOLICITED(hdr)) && (!IS_OVERRIDE(hdr)) &&
        (pico_ipv6_neighbor_compare_stored(n, opt, dev) != 0)) {

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
    if (!n || !f) {
        return;
    } else {
        if (!(icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr))
            return;
        else {
            if (IS_SOLICITED(icmp6_hdr)) {
                n->state = PICO_ND_STATE_REACHABLE;
                n->failure_count = 0;
                pico_nd_new_expire_time(n);
            } else {
                n->state = PICO_ND_STATE_STALE;
            }

            if (opt)
                pico_ipv6_neighbor_update(n, opt, f->dev);

            pico_ipv6_nd_queued_trigger();
        }
    }
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

#ifdef PICO_SUPPORT_6LOWPAN
    if (PICO_DEV_IS_6LOWPAN(f->dev)) {
        /* 6LoWPAN: parse Address Registration Comfirmation(nothing on success, remove link on failure) */
        pico_6lp_nd_neigh_adv_process(f);
    }
#endif

    /* Check if there's a NCE in the cache */
    n = pico_nd_find_neighbor(&icmp6_hdr->msg.info.neigh_adv.target);
    if (!n) {
        return 0;
    }

    if ((optres == 0) || IS_OVERRIDE(icmp6_hdr) || (pico_ipv6_neighbor_compare_stored(n, &opt, f->dev) == 0)) {
        neigh_adv_reconfirm_router_option(n, IS_ROUTER(icmp6_hdr));
    }

    if ((optres > 0) && (n->state == PICO_ND_STATE_INCOMPLETE)) {
        neigh_adv_process_incomplete(n, f, &opt);
        return 0;
    }

    if (optres > 0)
        return neigh_adv_reconfirm(n, &opt, icmp6_hdr, f->dev);
    else
        return neigh_adv_reconfirm_no_tlla(n, icmp6_hdr);

}

static struct pico_ipv6_neighbor *pico_ipv6_neighbor_from_sol_new(struct pico_ip6 *ip, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev)
{
    size_t len = pico_hw_addr_len(dev, opt);
    struct pico_ipv6_neighbor *n = NULL;
    n = pico_nd_add(ip, dev);
    if (!n)
        return NULL;

    memcpy(n->hwaddr.data, opt->addr.data, len);
    memset(n->hwaddr.data + len, 0, sizeof(union pico_hw_addr) - len);
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
        } else if (memcmp(opt.addr.data, n->hwaddr.data, pico_hw_addr_len(f->dev, &opt))) {
            pico_ipv6_neighbor_update(n, &opt, f->dev);
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
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_ipv6_link *link = NULL;
    ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;

    if (!f->dev->mode) {
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

    if (!f->dev->mode && !valid_lladdr && (0 == neigh_sol_detect_dad(f)))
        return 0;
#ifdef PICO_SUPPORT_6LOWPAN
    else if (PICO_DEV_IS_6LOWPAN(f->dev)) {
        nd_dbg("[6LP-ND] Received Address Registration Option\n");
        neigh_sol_detect_dad_6lp(f);
    }
#endif

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

#ifdef PICO_SUPPORT_6LOWPAN
    /* Don't validate target address, the sol is always targeted at 6LBR so
     * no possible interface on the 6LBR can have the same address as specified in
     * the target */
    if (PICO_DEV_IS_6LOWPAN(f->dev))
        return 0;
#endif

    link = pico_ipv6_link_by_dev(f->dev);
    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    while(link) {
        /* RFC4861, 7.2.3:
         *
         *  - The Target Address is a "valid" unicast or anycast address
         *    assigned to the receiving interface [ADDRCONF],
         *  - The Target Address is a unicast or anycast address for which the
         *    node is offering proxy service, or
         *  - The Target Address is a "tentative" address on which Duplicate
         *    Address Detection is being performed
         */
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
    if (!f->dev->mode && pico_ipv6_is_solnode_multicast(hdr->dst.addr, f->dev) == 0) {
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

/*MARK*/
#ifdef PICO_SUPPORT_6LOWPAN
static void pico_6lp_nd_unreachable_gateway(struct pico_ip6 *a)
{
    struct pico_ipv6_route *route = NULL;
    struct pico_ipv6_link *local = NULL;
    struct pico_tree_node *node = NULL;
    struct pico_device *dev = NULL;

    /* RFC6775, 5.3:
     *  ... HOSTS need to intelligently retransmit RSs when one of its
     *  default routers becomes unreachable ...
     */
    pico_tree_foreach(node, &Device_tree) {
        if (PICO_DEV_IS_6LOWPAN(dev) && (!dev->hostvars.routing)) {
            /* Check if there's a gateway configured */
            route = pico_ipv6_gateway_by_dev(dev);
            while (route) {
                if (0 == pico_ipv6_compare(&route->gateway, a)) {
                    local = pico_ipv6_linklocal_get(dev);
                    pico_6lp_nd_start_soliciting(local, route);
                    break;
                }
                route = pico_ipv6_gateway_by_dev_next(dev, route);
            }
        }
    }
}

static int pico_6lp_nd_validate_sol_aro(struct pico_icmp6_opt_aro *aro)
{
    if (aro->len != 2 || aro->status != 0)
        return -1;
    return 0;
}

static int pico_6lp_nd_validate_adv_aro(struct pico_device *dev, struct pico_icmp6_opt_aro *aro, uint8_t *status)
{
    union pico_ll_addr addr, eui;

    /* RFC6775 - 5.5.2 :
     *      - If the length field is not two, the option is silently ignored.
     *      - If the EUI-64 field does not match the EUI-64 of the interface,
     *        the option is silently ignored.
     */
    if (aro->len != 2)
        return -1;

    /* TODO: Update to abstract address, e.g. remove dependency of '.pan' */
    eui.pan.addr._ext = aro->eui64;
    eui.pan.mode = AM_6LOWPAN_EXT;
    addr.pan.addr._ext = ((struct pico_6lowpan_info *)dev->eth)->addr_ext;
    addr.pan.mode = AM_6LOWPAN_EXT;

    if (dev && pico_6lowpan_lls[dev->mode].addr_cmp) {
        if (pico_6lowpan_lls[dev->mode].addr_cmp(&addr, &eui))
            return -1;
    } else {
        return -1;
    }

    *status = aro->status;
    return 0;
}

/* Deregisters a link from all default gateways */
static void pico_6lp_nd_deregister(struct pico_ipv6_link *l)
{
    struct pico_ipv6_route *gw = pico_ipv6_gateway_by_dev(l->dev);
    while (gw) {
        pico_icmp6_neighbor_solicitation(l->dev, &l->address, PICO_ICMP6_ND_DEREGISTER, &gw->gateway);
        gw = pico_ipv6_gateway_by_dev_next(l->dev, gw);
    }
}

/* Retransmits neighbors solicitations with address registration if ARO is not acknowledged */
static void pico_6lp_nd_register_try(pico_time now, void *arg)
{
    struct pico_ipv6_link *l = arg;
    struct pico_ipv6_route *gw = pico_ipv6_gateway_by_dev(l->dev);
    IGNORE_PARAMETER(now);
    while (gw) {
        l->istentative = 1;
        pico_icmp6_neighbor_solicitation(l->dev, &l->address, PICO_ICMP6_ND_DAD, &gw->gateway);
        gw = pico_ipv6_gateway_by_dev_next(l->dev, gw);
    }
    pico_timer_add(l->dev->hostvars.retranstime, pico_6lp_nd_register_try, l);
}

/* Tries to register a link with one or more of its default routers */
void pico_6lp_nd_register(struct pico_ipv6_link *link)
{
    /* RFC6775: When a host has configured a non-link-local IPv6 address, it registers that
     *      address with one or more of its default routers using the Address Registration
     *      Option (ARO) in an NS message. */
    pico_6lp_nd_register_try(PICO_TIME_MS(), link);
}

/* Check if there are default routers configured. If not, sent a router solicitation */
static void pico_6lp_nd_do_solicit(pico_time now, void *arg)
{
    struct pico_ipv6_route *gw = arg;
    struct pico_ip6 *dst = NULL;
    IGNORE_PARAMETER(now);

    if (!pico_ipv6_gateway_by_dev(gw->link->dev) && !gw->link->dev->hostvars.routing) {
        /* If the solicitation is to be sent unicast */
        if (!pico_ipv6_is_unspecified(gw->gateway.addr) && gw->retrans < MAX_RTR_SOLICITATIONS)
            dst = &gw->gateway;

        /* Exponential backoff */
        if (++gw->retrans == MAX_RTR_SOLICITATIONS) {
            gw->backoff <<= 1;
            if (gw->backoff >= MAX_RTR_SOLICITATION_INTERVAL)
                gw->backoff = (pico_time)MAX_RTR_SOLICITATION_INTERVAL;
        }

        /* If router list is empty, send router solicitation */
        pico_icmp6_router_solicitation(gw->link->dev, &gw->link->address, dst);

        /* Apply exponential retransmission timer, see RFC6775 5.3 */
        pico_timer_add(gw->backoff, pico_6lp_nd_do_solicit, gw);
        nd_dbg("[6LP-ND]$ No default routers configured, soliciting\n");
    } else {
        PICO_FREE(gw);
    }
}

/* Start transmitting repetitive router solicitations */
int pico_6lp_nd_start_soliciting(struct pico_ipv6_link *l, struct pico_ipv6_route *gw)
{
    struct pico_ipv6_route *dummy = PICO_ZALLOC(sizeof(struct pico_ipv6_route));
    struct pico_ip6 *dst = NULL;

    if (dummy) {
        if (gw) { // If the router solicitation has to be sent unicast ...
            dst = &gw->gateway; // ... the gateway is the destination
            memcpy(dummy->gateway.addr, gw->gateway.addr, PICO_SIZE_IP6); // and should be retrievable in the timer event
        }
        dummy->link = l; // the link that has to be reconfirmed as well.

        /* If router list is empty, send router solicitation */
        pico_icmp6_router_solicitation(l->dev, &l->address, dst);

        if (!l->dev->hostvars.routing) {
            dummy->retrans = 0;
            dummy->backoff = RTR_SOLICITATION_INTERVAL;
            if (!pico_timer_add(dummy->backoff, pico_6lp_nd_do_solicit, dummy)) {
                PICO_FREE(dummy);
                return -1;
            }
        } else {
            PICO_FREE(dummy);
        }
        return 0;
    }
    return -1;
}

/* Validate Neighbor advertisement mesaage */
static int pico_6lp_nd_neigh_adv_validate(struct pico_frame *f, uint8_t *status)
{
    struct pico_icmp6_hdr *icmp = (struct pico_icmp6_hdr *)f->transport_hdr;
    struct pico_icmp6_opt_aro *aro = (struct pico_icmp6_opt_aro *)((uint8_t *)&icmp->msg.info.neigh_adv + sizeof(struct neigh_sol_s));
    struct pico_ipv6_hdr *ip = (struct pico_ipv6_hdr *)f->net_hdr;

    /* 6LP: Target address cannot be MCAST and the Source IP-address cannot be UNSPECIFIED or MCAST */
    if (pico_ipv6_is_multicast(icmp->msg.info.neigh_adv.target.addr) || pico_ipv6_is_unspecified(ip->src.addr) ||
        pico_ipv6_is_multicast(ip->src.addr))
        return -1;

    return pico_6lp_nd_validate_adv_aro(f->dev, aro, status);
}

/* Process neighbor advertisement */
static int pico_6lp_nd_neigh_adv_process(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp = (struct pico_icmp6_hdr *)f->transport_hdr;
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    struct pico_ipv6_link *l = NULL;
    struct pico_ip6 zero = {
        .addr = {0}
    };
    uint8_t status = 0;

    if (pico_6lp_nd_neigh_adv_validate(f, &status)) {
        return -1;
    } else {
        l = pico_ipv6_link_get(&icmp->msg.info.neigh_adv.target);
        if (l)
            l->istentative = 0;
        else
            return -1;

        /* Globally routable address has been registered @ 6LoWPAN Border Router */
        if (1 == status) { // Duplicate address detected
            nd_dbg("[6LP-ND]: Registering routable address failed, removing link...\n");
            ipv6_duplicate_detected(l);
            return -1;
        } else if (2 == status) { // Router's NCE is full, remove router from default router list
            pico_ipv6_route_del(zero, zero, hdr->src, 10, l);
            pico_6lp_nd_start_soliciting(pico_ipv6_linklocal_get(l->dev), NULL);
        } else { // Registration success
            nd_dbg("[6LP-ND]: Registering routable address succeeded!\n");
        }
    }
    return 0;
}

/* Add a new 6LoWPAN neighbor with lifetime from ARO */
static struct pico_ipv6_neighbor *pico_nd_add_6lp(struct pico_ip6 naddr, struct pico_icmp6_opt_aro *aro, struct pico_device *dev)
{
    struct pico_ipv6_neighbor *new = NULL;

    if ((new = pico_nd_add(&naddr, dev))) {
        new->expire = PICO_TIME_MS() + (pico_time)(ONE_MINUTE * aro->lifetime);
        dbg("ARO Lifetime: %d minutes\n", aro->lifetime);
    } else {
        return NULL;
    }

    return new;
}

/* RFC6775 §6.5.2.  Returning Address Registration Errors */
static int neigh_sol_dad_reply(struct pico_frame *sol, struct pico_icmp6_opt_lladdr *sllao, struct pico_icmp6_opt_aro *aro, uint8_t status)
{
    uint8_t sllao_len = (uint8_t)(sllao->len * 8);
    struct pico_icmp6_hdr *icmp = NULL;
    struct pico_frame *adv = pico_frame_copy(sol);
    struct pico_ip6 ll = {{0xfe,0x80,0,0,0,0,0,0, 0,0,0,0,0,0,0,0}};
    size_t len = pico_hw_addr_len(sol->dev, sllao);
    union pico_ll_addr lladdr;

    if (!adv) {
        return -1;
    } else {
        icmp = (struct pico_icmp6_hdr *)adv->transport_hdr;

        /* Set the status of the Address Registration */
        aro->status = status;
        if (PICO_DEV_IS_6LOWPAN(sol->dev)) {
            memcpy(lladdr.pan.addr.data, aro->eui64.addr, len);
            lladdr.pan.mode = (len == SIZE_6LOWPAN_EXT) ? AM_6LOWPAN_EXT : AM_6LOWPAN_SHORT;
            if (pico_6lowpan_lls[sol->dev->mode].addr_iid)
                pico_6lowpan_lls[sol->dev->mode].addr_iid(ll.addr + 8, &lladdr);
        }

        /* Remove the SLLAO from the frame */
        memmove(((uint8_t *)&icmp->msg.info.neigh_sol) + sizeof(struct neigh_sol_s), ((uint8_t *)&icmp->msg.info.neigh_sol) + sizeof(struct neigh_sol_s) + sllao_len, (size_t)(aro->len * 8));
        adv->transport_len = (uint16_t)(adv->transport_len - sllao_len);
        adv->len = (uint16_t)(adv->len - sllao_len);

        /* I'm a router, and it's always solicited */
        icmp->msg.info.neigh_adv.rsor = 0xE0;

        /* Set the ICMPv6 message type to Neighbor Advertisements */
        icmp->type = PICO_ICMP6_NEIGH_ADV;
        icmp->code = 0;
        icmp->crc = pico_icmp6_checksum(adv);

        pico_ipv6_frame_push(adv, NULL, &ll, PICO_PROTO_ICMP6, 0);
        return 0;
    }
}

/* RFC6775 §6.5.1.  Checking for Duplicates */
static int neigh_sol_detect_dad_6lp(struct pico_frame *f)
{
    struct pico_ipv6_neighbor *n = NULL;
    struct pico_icmp6_opt_lladdr *sllao = NULL;
    struct pico_icmp6_hdr *icmp = NULL;
    struct pico_icmp6_opt_aro *aro = NULL;
    size_t len = 0;

    icmp = (struct pico_icmp6_hdr *)f->transport_hdr;
    sllao = (struct pico_icmp6_opt_lladdr *)((uint8_t *)&icmp->msg.info.neigh_sol + sizeof(struct neigh_sol_s));
    aro = (struct pico_icmp6_opt_aro *)(((uint8_t *)&icmp->msg.info.neigh_sol) + sizeof(struct neigh_sol_s) + (sllao->len * 8));

    /* Validate Address Registration Option */
    if (pico_6lp_nd_validate_sol_aro(aro))
        return -1;

    /* See RFC6775 $6.5.1: Checking for duplicates */
    if (!(n = pico_nd_find_neighbor(&icmp->msg.info.neigh_sol.target))) {
        /* No dup, add neighbor to cache */
        if (pico_nd_add_6lp(icmp->msg.info.neigh_sol.target, aro, f->dev))
            neigh_sol_dad_reply(f, sllao, aro, ICMP6_ARO_SUCCES);
        else /* No dup, but neighbor cache is full */
            neigh_sol_dad_reply(f, sllao, aro, ICMP6_ARO_FULL);
        return 0;
    } else {
        if (!aro->lifetime) {
            pico_tree_delete(&NCache, n);
            PICO_FREE(n);
            neigh_sol_dad_reply(f, sllao, aro, ICMP6_ARO_SUCCES);
            return 0;
        }
        /* Check if hwaddr differs */
        len = pico_hw_addr_len(f->dev, sllao);
        if (memcmp(sllao->addr.data, n->hwaddr.data, len) == 0) {
            n->expire = PICO_TIME_MS() + (pico_time)(ONE_MINUTE * aro->lifetime);
            neigh_sol_dad_reply(f, sllao, aro, ICMP6_ARO_DUP);
        }
        return 0;
    }
}

static int router_options(struct pico_frame *f, struct pico_icmp6_opt_lladdr *opt, uint8_t expected_opt)
{
    /* RFC 4861 $6.1
     *  The contents of any defined options that are not specified to be used
     *  with Router Solicitation messages MUST be ignored and the packet
     *  processed as normal.  The only defined option that may appear is the
     *  Source Link-Layer Address option.
     */
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    uint8_t *options = NULL;
    int optlen = 0;
    int len = 0;

    icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
    optlen = f->transport_len - PICO_ICMP6HDR_ROUTER_SOL_SIZE;
    if (optlen)
        options = ((uint8_t *)&icmp6_hdr->msg.info.router_sol) + sizeof(struct router_sol_s);

    return nd_options(options, opt, expected_opt, optlen, len);
}

static int router_sol_validity_checks(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)(f->net_hdr);
    struct pico_icmp6_opt_lladdr opt = { 0 };
    int sllao_present = 0;

    /* Step 2 validation */
    if (f->transport_len < PICO_ICMP6HDR_ROUTER_SOL_SIZE_6LP)
        return -1;

    /* RFC4861, 6.1.1:
     * - If the IP source address is the unspecified address, there is no
     *   source link-layer address option in the message.
     */
    /* Check for SLLAO if the IP source address is UNSPECIFIED */
    sllao_present = router_options(f, &opt, PICO_ND_OPT_LLADDR_SRC);
    if (pico_ipv6_is_unspecified(hdr->src.addr)) {
        /* Frame is not valid when SLLAO is present if IP6-SRC is UNSPEC. */
        if (sllao_present) {
            return -1;
        }
    } else {
        /* Frame is not valid when no SLLAO if present if there's a IP6-SRC */
        if (sllao_present <= 0) {
            return -1;
        }
    }

    return 0;
}

static int router_sol_checks(struct pico_frame *f)
{
    /* Step 1 validation */
    if (icmp6_initial_checks(f) < 0)
        return -1;

    return router_sol_validity_checks(f);
}

static int router_sol_process(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;

    /* Determine if i'm a 6LBR, if i'm not, can't do anything with a router solicitation */
    if (!f->dev->hostvars.routing)
        return -1;

    nd_dbg("[6LBR]: Processing router solicitation...\n");

    /* Router solicitation message validation */
    if (router_sol_checks(f) < 0)
        return -1;

    /* Maybe create a tentative NCE? No, will do it later */

    /* Send a router advertisement via unicast to requesting host */
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    return pico_icmp6_router_advertisement(f->dev, &hdr->src);
}

#endif /* PICO_SUPPORT_6LOWPAN */

static int pico_nd_router_sol_recv(struct pico_frame *f)
{
#ifdef PICO_SUPPORT_6LOWPAN
    /* 6LoWPAN: reply on explicit router solicitations via unicast */
    if (PICO_DEV_IS_6LOWPAN(f->dev))
        return router_sol_process(f);
#endif

    pico_ipv6_neighbor_from_unsolicited(f);
    /* Host only: router solicitation is discarded. */
    return 0;
}
static int radv_process(struct pico_frame *f)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    uint8_t *nxtopt, *opt_start;
    struct pico_ipv6_link *link;
    uint32_t pref_lifetime = 0;
    struct pico_ipv6_hdr *hdr;
    struct pico_ip6 zero = {
        .addr = {0}
    };
    int optlen;
#ifdef PICO_SUPPORT_6LOWPAN
    int sllao = 0;
#endif

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
            pref_lifetime = long_be(prefix->pref_lifetime);
            if (pref_lifetime > long_be(prefix->val_lifetime))
                goto ignore_opt_prefix;

#ifdef PICO_SUPPORT_6LOWPAN
            /* RFC6775 (6LoWPAN): Should the host erroneously receive a PIO with the L (on-link)
             *      flag set, then that PIO MUST be ignored.
             */
            if (PICO_DEV_IS_6LOWPAN(f->dev) && prefix->onlink)
                goto ignore_opt_prefix;
#endif

            if (prefix->val_lifetime == 0)
                goto ignore_opt_prefix;

            if (prefix->prefix_len != 64) {
                return -1;
            }

            /* Refresh lifetime of a prefix */
            link = pico_ipv6_prefix_configured(&prefix->prefix);
            if (link) {
                pico_ipv6_lifetime_set(link, now + (1000 * (pico_time)(long_be(prefix->val_lifetime))));
                goto ignore_opt_prefix;
            }

            /* Configure a an non linklocal IPv6 address */
            link = pico_ipv6_link_add_local(f->dev, &prefix->prefix);
            if (link) {
                pico_ipv6_lifetime_set(link, now + (1000 * (pico_time)(long_be(prefix->val_lifetime))));
                /* Add a default gateway to the default routers list with source of RADV */
                pico_ipv6_route_add(zero, zero, hdr->src, 10, link);
#ifdef PICO_SUPPORT_6LOWPAN
                if (PICO_DEV_IS_6LOWPAN(f->dev)) {
                    pico_6lp_nd_register(link);
                }
#endif
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
#ifdef PICO_SUPPORT_6LOWPAN
            sllao = 1; // RFC6775 (6LoWPAN): An SLLAO MUST be included in the RA.
#endif
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
#ifdef PICO_SUPPORT_6LOWPAN
        case PICO_ND_OPT_6CO:
        {
            struct pico_icmp6_opt_6co *co = (struct pico_icmp6_opt_6co *)nxtopt;
#ifdef PICO_6LOWPAN_IPHC_ENABLED
            if (PICO_DEV_IS_6LOWPAN(f->dev)) {
                struct pico_ip6 prefix;
                memcpy(prefix.addr, (uint8_t *)&co->prefix, (size_t)(co->len - 1) << 3);
                ctx_update(prefix, co->id, co->clen, co->lifetime, co->c, f->dev);
            }
#endif
            optlen -= (co->len << 3);
            nxtopt += (co->len << 3);
        }
        break;
        case PICO_ND_OPT_ABRO:
        {
            struct pico_icmp6_opt_abro *abro = (struct pico_icmp6_opt_abro *)nxtopt;
            /* TODO: Process */
            optlen -= (abro->len << 3);
            nxtopt += (abro->len << 3);
        }
        break;
#endif
        default:
            pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_IPV6OPT,
                                         (uint32_t)sizeof(struct pico_ipv6_hdr) + (uint32_t)PICO_ICMP6HDR_ROUTER_ADV_SIZE + (uint32_t)(nxtopt - opt_start));
            return -1;
        }
    }
#ifdef PICO_SUPPORT_6LOWPAN
    if (PICO_DEV_IS_6LOWPAN(f->dev) && !sllao) {
        return -1;
    }
#endif
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

    /* ETH: Target address belongs to a tentative link on this device, DaD detected a dup */
    link = pico_ipv6_link_istentative(&icmp6_hdr->msg.info.neigh_adv.target);
    if (link && !link->dev->mode)
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
        if ( now > n->expire ) {
            pico_ipv6_nd_timer_elapsed(now, n);
        }
    }
    if (!pico_timer_add(200, pico_ipv6_nd_timer_callback, NULL)) {
        dbg("IPV6 ND: Failed to start callback timer\n");
        /* TODO no idea what consequences this has */
    }
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
                /* Do not send periodic router advertisements when there aren't 2 interfaces from and to the device can route */
                if ((!pico_ipv6_is_linklocal(rt->dest.addr)) && dev->hostvars.routing && (rt->link)
                    && (dev != rt->link->dev) && !PICO_DEV_IS_6LOWPAN(dev)) {
                    pico_icmp6_router_advertisement(dev, &rt->dest);
                }
            }
        }
    }

    next_timer_expire = PICO_IPV6_ND_MIN_RADV_INTERVAL + (pico_rand() % (PICO_IPV6_ND_MAX_RADV_INTERVAL - PICO_IPV6_ND_MIN_RADV_INTERVAL));
    if (!pico_timer_add(next_timer_expire, pico_ipv6_nd_ra_timer_callback, NULL)) {
        dbg("IPv6 ND: Failed to start callback timer\n");
        /* TODO no idea what consequences this has */
    }
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
    if (l && !l->dev->mode)
        return &l->dev->eth->mac;
    else if (l && PICO_DEV_IS_6LOWPAN(l->dev))
        return (struct pico_eth *)l->dev->eth;

    return pico_nd_get(&hdr->dst, f->dev);
}

void pico_ipv6_nd_postpone(struct pico_frame *f)
{
    int i;
    static int last_enq = -1;
    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; i++)
    {
        if (!frames_queued_v6[i]) {
            frames_queued_v6[i] = f;
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

    frames_queued_v6[last_enq] = f;
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
        nd_dbg("ICMP6: received ROUTER ADV\n");
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
    uint32_t timer_cb = 0, ra_timer_cb = 0;

    timer_cb = pico_timer_add(200, pico_ipv6_nd_timer_callback, NULL);
    if (!timer_cb) {
        nd_dbg("IPv6 ND: Failed to start callback timer\n");
        return;
    }

    ra_timer_cb = pico_timer_add(200, pico_ipv6_nd_ra_timer_callback, NULL);
    if (!ra_timer_cb) {
        nd_dbg("IPv6 ND: Failed to start RA callback timer\n");
        pico_timer_cancel(timer_cb);
        return;
    }

    if (!pico_timer_add(1000, pico_ipv6_check_lifetime_expired, NULL)) {
        nd_dbg("IPv6 ND: Failed to start check_lifetime timer\n");
        pico_timer_cancel(timer_cb);
        pico_timer_cancel(ra_timer_cb);
        return;
    }
}

#endif
