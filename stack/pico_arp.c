/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_config.h"
#include "pico_arp.h"
#include "pico_tree.h"
#include "pico_ipv4.h"
#include "pico_device.h"
#include "pico_stack.h"

const uint8_t PICO_ETHADDR_ALL[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
#define PICO_ARP_TIMEOUT 600000
#define PICO_ARP_RETRY 300

#ifdef DEBUG_ARP
    #define arp_dbg dbg
#else
    #define arp_dbg(...) do {} while(0)
#endif

static struct pico_queue pending;
static int pending_timer_on = 0;

void check_pending(pico_time now, void *_unused)
{
    struct pico_frame *f = pico_dequeue(&pending);
    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(_unused);
    if (!f) {
        pending_timer_on = 0;
        return;
    }

    if(pico_ethernet_send(f) > 0)
        pico_frame_discard(f);

    pico_timer_add(PICO_ARP_RETRY, &check_pending, NULL);
}


struct
__attribute__ ((__packed__))
pico_arp_hdr
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t opcode;
    uint8_t s_mac[PICO_SIZE_ETH];
    struct pico_ip4 src;
    uint8_t d_mac[PICO_SIZE_ETH];
    struct pico_ip4 dst;
};

struct arp_service_ipconflict {
    struct pico_eth mac;
    struct pico_ip4 ip;
    void (*conflict)(void);
};

static struct arp_service_ipconflict conflict_ipv4;

#define PICO_SIZE_ARPHDR ((sizeof(struct pico_arp_hdr)))

/* Arp Entries for the tables. */
struct pico_arp {
/* CAREFUL MAN! ARP entry MUST begin with a pico_eth structure,
 * due to in-place casting!!! */
    struct pico_eth eth;
    struct pico_ip4 ipv4;
    int arp_status;
    pico_time timestamp;
    struct pico_device *dev;
    struct pico_timer *timer;
};



/*****************/
/**  ARP TREE **/
/*****************/

/* Routing destination */

static int arp_compare(void *ka, void *kb)
{
    struct pico_arp *a = ka, *b = kb;
    if (a->ipv4.addr < b->ipv4.addr)
        return -1;
    else if (a->ipv4.addr > b->ipv4.addr)
        return 1;

    return 0;
}

PICO_TREE_DECLARE(arp_tree, arp_compare);

/*********************/
/**  END ARP TREE **/
/*********************/

struct pico_eth *pico_arp_lookup(struct pico_ip4 *dst)
{
    struct pico_arp search, *found;
    search.ipv4.addr = dst->addr;
    found = pico_tree_findKey(&arp_tree, &search);
    if (found && (found->arp_status != PICO_ARP_STATUS_STALE))
        return &found->eth;

    return NULL;
}

struct pico_ip4 *pico_arp_reverse_lookup(struct pico_eth *dst)
{
    struct pico_arp*search;
    struct pico_tree_node *index;
    pico_tree_foreach(index, &arp_tree){
        search = index->keyValue;
        if(memcmp(&(search->eth.addr), &dst->addr, 6) == 0)
            return &search->ipv4;
    }
    return NULL;
}

struct pico_eth *pico_arp_get(struct pico_frame *f)
{
    struct pico_eth *a4;
    struct pico_ip4 gateway;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_ipv4_link *l;

    l = pico_ipv4_link_get(&hdr->dst);
    if(l) {
        /* address belongs to ourself */
        return &l->dev->eth->mac;
    }

    gateway = pico_ipv4_route_get_gateway(&hdr->dst);
    /* check if dst is local (gateway = 0), or if to use gateway */
    if (gateway.addr != 0)
        a4 = pico_arp_lookup(&gateway);      /* check if gateway ip mac in cache */
    else
        a4 = pico_arp_lookup(&hdr->dst);     /* check if local ip mac in cache */

    if (!a4) {
        if (++f->failure_count < 4) {
            dbg ("================= ARP REQUIRED: %d =============\n\n", f->failure_count);
            /* check if dst is local (gateway = 0), or if to use gateway */
            if (gateway.addr != 0)
                pico_arp_request(f->dev, &gateway, PICO_ARP_QUERY); /* arp to gateway */
            else
                pico_arp_request(f->dev, &hdr->dst, PICO_ARP_QUERY); /* arp to dst */

            pico_enqueue(&pending, f);
            if (!pending_timer_on) {
                pending_timer_on++;
                pico_timer_add(PICO_ARP_RETRY, &check_pending, NULL);
            }
        } else {
            dbg("ARP: Destination Unreachable\n");
            pico_notify_dest_unreachable(f);
            pico_frame_discard(f);
        }
    }

    return a4;
}

#ifdef DEBUG_ARP
void dbg_arp(void)
{
    struct pico_arp *a;
    struct pico_tree_node *index;

    pico_tree_foreach(index, &arp_tree) {
        a = index->keyValue;
        arp_dbg("ARP to  %08x, mac: %02x:%02x:%02x:%02x:%02x:%02x\n", a->ipv4.addr, a->eth.addr[0], a->eth.addr[1], a->eth.addr[2], a->eth.addr[3], a->eth.addr[4], a->eth.addr[5] );
    }
}
#endif

void arp_expire(pico_time now, void *_stale)
{
    struct pico_arp *stale = (struct pico_arp *) _stale;
    IGNORE_PARAMETER(now);
    stale->arp_status = PICO_ARP_STATUS_STALE;
    arp_dbg("ARP: Setting arp_status to STALE\n");
    pico_arp_request(stale->dev, &stale->ipv4, PICO_ARP_QUERY);

}

void pico_arp_add_entry(struct pico_arp *entry)
{
    entry->arp_status = PICO_ARP_STATUS_REACHABLE;
    entry->timestamp  = PICO_TIME();

    pico_tree_insert(&arp_tree, entry);
    arp_dbg("ARP ## reachable.\n");
    pico_timer_add(PICO_ARP_TIMEOUT, arp_expire, entry);
}

int pico_arp_create_entry(uint8_t*hwaddr, struct pico_ip4 ipv4, struct pico_device*dev)
{
    struct pico_arp*arp = pico_zalloc(sizeof(struct pico_arp));
    if(!arp) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    memcpy(arp->eth.addr, hwaddr, 6);
    arp->ipv4.addr = ipv4.addr;
    arp->dev = dev;

    pico_arp_add_entry(arp);

    return 0;
}

int pico_arp_receive(struct pico_frame *f)
{
    struct pico_arp_hdr *hdr;
    struct pico_arp search, *found, *new = NULL;
    int ret = -1;
    hdr = (struct pico_arp_hdr *) f->net_hdr;

    if (!hdr)
        goto end;

    /* Validate the incoming arp packet */
    if ((hdr->htype != PICO_ARP_HTYPE_ETH) || (hdr->ptype != PICO_IDETH_IPV4))
        goto end;

    if (conflict_ipv4.conflict != NULL)
    {
        if ((conflict_ipv4.ip.addr == hdr->src.addr) && (memcmp(hdr->s_mac, conflict_ipv4.mac.addr, 6) != 0))
            conflict_ipv4.conflict();
    }

    /* Populate a new arp entry */
    search.ipv4.addr = hdr->src.addr;
    memcpy(search.eth.addr, hdr->s_mac, PICO_SIZE_ETH);

    /* Search for already existing entry */

    found = pico_tree_findKey(&arp_tree, &search);
    if (!found) {
        new = pico_zalloc(sizeof(struct pico_arp));
        if (!new)
            goto end;

        new->ipv4.addr = hdr->src.addr;
    }
    else if (found->arp_status == PICO_ARP_STATUS_STALE) {
        /* Replace if stale */
        new = found;

        pico_tree_delete(&arp_tree, new);
    }
    else {
        /* Existing entry found & still valid, update mac address */
        memcpy(found->eth.addr, hdr->s_mac, PICO_SIZE_ETH);

        /* Refresh timeout & update timestamp*/
        pico_timer_cancel(found->timer);
        found->timer = pico_timer_add(PICO_ARP_TIMEOUT, arp_expire, found);
        found->timestamp = PICO_TIME();
    }

    ret = 0;

    if (new) {
        memcpy(new->eth.addr, hdr->s_mac, PICO_SIZE_ETH);
        new->dev = f->dev;
        pico_arp_add_entry(new);
    }

    if (hdr->opcode == PICO_ARP_REQUEST) {
        struct pico_ip4 me;
        struct pico_eth_hdr *eh = (struct pico_eth_hdr *)f->datalink_hdr;
        struct pico_device *link_dev;
        me.addr = hdr->dst.addr;

        link_dev = pico_ipv4_link_find(&me);
        if (link_dev != f->dev)
            goto end;

        hdr->opcode = PICO_ARP_REPLY;
        memcpy(hdr->d_mac, hdr->s_mac, PICO_SIZE_ETH);
        memcpy(hdr->s_mac, f->dev->eth->mac.addr, PICO_SIZE_ETH);
        hdr->dst.addr = hdr->src.addr;
        hdr->src.addr = me.addr;

        /* Prepare eth header for arp reply */
        memcpy(eh->daddr, eh->saddr, PICO_SIZE_ETH);
        memcpy(eh->saddr, f->dev->eth->mac.addr, PICO_SIZE_ETH);
        f->start = f->datalink_hdr;
        f->len = PICO_SIZE_ETHHDR + PICO_SIZE_ARPHDR;
        f->dev->send(f->dev, f->start, (int)f->len);
    }

#ifdef DEBUG_ARG
    dbg_arp();
#endif

end:
    pico_frame_discard(f);
    return ret;
}

int32_t pico_arp_request(struct pico_device *dev, struct pico_ip4 *dst, uint8_t type)
{
    struct pico_frame *q = pico_frame_alloc(PICO_SIZE_ETHHDR + PICO_SIZE_ARPHDR);
    struct pico_eth_hdr *eh;
    struct pico_arp_hdr *ah;
    struct pico_ip4 *src;
    int ret;

    if (type == PICO_ARP_QUERY)
    {
        src = pico_ipv4_source_find(dst);
        if (!src)
            return -1;
    }

    arp_dbg("QUERY: %08x\n", dst->addr);

    if (!q)
        return -1;

    eh = (struct pico_eth_hdr *)q->start;
    ah = (struct pico_arp_hdr *) (q->start + PICO_SIZE_ETHHDR);

    /* Fill eth header */
    memcpy(eh->saddr, dev->eth->mac.addr, PICO_SIZE_ETH);
    memcpy(eh->daddr, PICO_ETHADDR_ALL, PICO_SIZE_ETH);
    eh->proto = PICO_IDETH_ARP;

    /* Fill arp header */
    ah->htype  = PICO_ARP_HTYPE_ETH;
    ah->ptype  = PICO_IDETH_IPV4;
    ah->hsize  = PICO_SIZE_ETH;
    ah->psize  = PICO_SIZE_IP4;
    ah->opcode = PICO_ARP_REQUEST;
    memcpy(ah->s_mac, dev->eth->mac.addr, PICO_SIZE_ETH);

    switch (type) {
    case PICO_ARP_ANNOUNCE:
        ah->src.addr = dst->addr;
        ah->dst.addr = dst->addr;
        break;
    case PICO_ARP_PROBE:
        ah->src.addr = 0;
        ah->dst.addr = dst->addr;
        break;
    default:
        ah->src.addr = src->addr;
        ah->dst.addr = dst->addr;
    }

    arp_dbg("Sending arp request.\n");
    ret = dev->send(dev, q->start, (int) q->len);
    pico_frame_discard(q);
    return ret;
}

int pico_arp_get_neighbors(struct pico_device *dev, struct pico_ip4 *neighbors, int maxlen)
{
    struct pico_arp*search;
    struct pico_tree_node *index;
    int i = 0;
    pico_tree_foreach(index, &arp_tree){
        search = index->keyValue;
        if (search->dev == dev) {
            neighbors[i++].addr = search->ipv4.addr;
            if (i >= maxlen)
                return i;
        }
    }
    return i;
}

void pico_arp_register_ipconflict(struct pico_ip4 *ip, struct pico_eth *mac, void (*cb)(void))
{
    conflict_ipv4.conflict = cb;
    conflict_ipv4.ip.addr = ip->addr;
    if (mac != NULL)
        memcpy(conflict_ipv4.mac.addr, mac, 6);
}
