/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 ********************************************************************/

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv4.h"
#include "pico_arp.h"
#include "pico_socket.h"
#include "pico_olsr.h"
#ifdef PICO_SUPPORT_OLSR
#define DGRAM_MAX_SIZE (100 - 28)
#define MAX_OLSR_MEM (4 * DGRAM_MAX_SIZE)
#define olsr_dbg(...) do {} while(0)

int OOM(void);


#define OLSR_HELLO_INTERVAL   ((uint32_t)5000)
#define OLSR_TC_INTERVAL      ((uint32_t)9000)
#define OLSR_MAXJITTER        ((uint32_t)(OLSR_HELLO_INTERVAL >> 2))
static const struct pico_ip4 HOST_NETMASK = {
    0xffffffff
};
#ifndef MIN
# define MIN(a, b) (a < b ? a : b)
#endif

#define fresher(a, b) ((a > b) || ((b - a) > 32768))


static uint16_t msg_counter; /* Global message sequence number */

/* Objects */
struct olsr_dev_entry
{
    struct olsr_dev_entry *next;
    struct pico_device *dev;
    uint16_t pkt_counter;
};


/* OLSR Protocol */
#define OLSRMSG_HELLO   0xc9
#define OLSRMSG_MID    0x03
#define OLSRMSG_TC    0xca

#define OLSRLINK_SYMMETRIC 0x06
#define OLSRLINK_UNKNOWN 0x08
#define OLSRLINK_MPR  0x0a


#define OLSR_PORT (short_be((uint16_t)698))


/* Headers */

PACKED_STRUCT_DEF olsr_link
{
    uint8_t link_code;
    uint8_t reserved;
    uint16_t link_msg_size;
};

PACKED_STRUCT_DEF olsr_neighbor
{
    uint32_t addr;
    uint8_t lq;
    uint8_t nlq;
    uint16_t reserved;
};

PACKED_STRUCT_DEF olsr_hmsg_hello
{
    uint16_t reserved;
    uint8_t htime;
    uint8_t willingness;
};

PACKED_STRUCT_DEF olsr_hmsg_tc
{
    uint16_t ansn;
    uint16_t reserved;
};


PACKED_STRUCT_DEF olsrmsg
{
    uint8_t type;
    uint8_t vtime;
    uint16_t size;
    struct pico_ip4 orig;
    uint8_t ttl;
    uint8_t hop;
    uint16_t seq;
};

PACKED_STRUCT_DEF olsrhdr
{
    uint16_t len;
    uint16_t seq;
};



/* Globals */
static struct pico_socket *udpsock = NULL;
uint16_t my_ansn = 0;
static struct olsr_route_entry  *Local_interfaces = NULL;
static struct olsr_dev_entry    *Local_devices    = NULL;

static struct olsr_dev_entry *olsr_get_deventry(struct pico_device *dev)
{
    struct olsr_dev_entry *cur = Local_devices;
    while(cur) {
        if (cur->dev == dev)
            return cur;

        cur = cur->next;
    }
    return NULL;
}

struct olsr_route_entry *olsr_get_ethentry(struct pico_device *vif)
{
    struct olsr_route_entry *cur = Local_interfaces;
    while(cur) {
        if (cur->iface == vif)
            return cur;

        cur = cur->next;
    }
    return NULL;
}

static struct olsr_route_entry *get_next_hop(struct olsr_route_entry *dst)
{
    struct olsr_route_entry *hop = dst;
    while(hop) {
        /* olsr_dbg("Finding next hop to %08x m=%d\n", hop->destination.addr, hop->metric); */
        if(hop->metric <= 1)
            return hop;

        hop = hop->gateway;
    }
    return NULL;
}

static inline void olsr_route_add(struct olsr_route_entry *el)
{
    /* char dest[16],nxdest[16]; */
    struct olsr_route_entry *nexthop;

    if(!el)
        return;

    my_ansn++;

    nexthop = get_next_hop(el);
    if (el->gateway && nexthop && (nexthop->destination.addr != el->destination.addr)) {
        /* 2-hops route or more */
        el->next = el->gateway->children;
        el->gateway->children = el;
        el->link_type = OLSRLINK_MPR;
        olsr_dbg("[OLSR]  ----------Adding route to %08x via %08x metric %d\n", el->destination.addr, nexthop->destination.addr, el->metric);
        pico_ipv4_route_add(el->destination, HOST_NETMASK, nexthop->destination, (int) el->metric, NULL);
    } else if (el->iface) {
        /* neighbor */
        struct olsr_route_entry *ei = olsr_get_ethentry(el->iface);
        struct pico_ip4 no_gw = {
            0U
        };
        if (el->link_type == OLSRLINK_UNKNOWN)
            el->link_type = OLSRLINK_SYMMETRIC;

        if (ei) {
            el->next = ei->children;
            ei->children = el;
        }

        olsr_dbg("[OLSR]  ----------Adding neighbor %08x iface %s\n", el->destination.addr, el->iface->name);

        pico_ipv4_route_add(el->destination, HOST_NETMASK, no_gw, 1, pico_ipv4_link_by_dev(el->iface));
    }
}

static inline void olsr_route_del(struct olsr_route_entry *r)
{
    struct olsr_route_entry *cur, *prev = NULL, *lst;
    /* olsr_dbg("[OLSR] DELETING route..................\n"); */
    my_ansn++;
    if (r->gateway) {
        lst = r->gateway->children;
    } else if (r->iface) {
        lst = olsr_get_ethentry(r->iface);
    } else {
        lst = Local_interfaces;
    }

    cur = lst, prev = NULL;
    while(cur) {
        if (cur == r) {
            /* found */
            if (r->gateway) {
                pico_ipv4_route_del(r->destination, HOST_NETMASK, r->metric);
                olsr_dbg("[OLSR] Deleting route to %08x \n", r->destination.addr);
                if (!prev)
                    r->gateway->children = r->next;
                else
                    prev->next = r->next;
            }

            while (r->children) {
                olsr_route_del(r->children);
                /* Orphans must die. */
                /* PICO_FREE(r->children); */
            }
            return;
        }

        prev = cur;
        cur = cur->next;
    }
}

static struct olsr_route_entry *get_route_by_address(struct olsr_route_entry *lst, uint32_t ip)
{
    struct olsr_route_entry *found;
    if(lst) {
        if (lst->destination.addr == ip) {
            return lst;
        }

        /* recursive function, could be dangerous for stack overflow if a lot of routes are available... */
        found = get_route_by_address(lst->children, ip);
        if (found)
            return found;

        found = get_route_by_address(lst->next, ip);
        if (found)
            return found;
    }

    return NULL;
}

#define OLSR_C_SHIFT (uint32_t)4 /* 1/16 */
#define DEFAULT_VTIME 288UL

static uint8_t seconds2olsr(uint32_t seconds)
{
    uint16_t a, b;
    /* olsr_dbg("seconds=%u\n", (uint16_t)seconds); */

    if (seconds > 32767)
        seconds = 32767;

    /* find largest b such as seconds/C >= 2^b */
    for (b = 1; b <= 0x0fu; b++) {
        if ((uint16_t)(seconds * 16u) < (1u << b)) {
            b--;
            break;
        }
    }
    /* olsr_dbg("b=%u", b); */
    /* compute the expression 16*(T/(C*(2^b))-1), which may not be a
       integer, and round it up.  This results in the value for 'a' */
    /* a = (T / ( C * (1u << b) ) ) - 1u; */
    {
        uint16_t den = ((uint16_t)(1u << b) >> 4u);
        /* olsr_dbg(" den=%u ", den); */
        if (den == 0)
        {
            /* olsr_dbg("div by 0!\n"); */
            den = 1u;
        }

        a = (uint16_t)(((uint16_t)seconds / den) - (uint16_t)1);
    }
    /* a = a & 0x0Fu; */

    /* olsr_dbg(" a=%u\n", a); */

    /* if 'a' is equal to 16: increment 'b' by one, and set 'a' to 0 */
    if (16u == a) {
        b++;
        a = 0u;
    }

    return (uint8_t)((a << 4u) + b);
}

static uint32_t olsr2seconds(uint8_t olsr)
{
    uint8_t a, b;
    uint16_t seconds;
    /* olsr_dbg("olsr format: %u -- ", olsr); */
    a = (olsr >> 4) & 0xFu;
    b = olsr & 0x0f;
    /* olsr_dbg("o2s: a=%u, b=%u\n", a,b); */
    if (b < 4)
        seconds = (uint16_t)(((1u << b) + (uint16_t)(((uint16_t)(a << b) >> 4u) & 0xFu)) >> OLSR_C_SHIFT);
    else
        seconds = (uint16_t)(((1u << b) + (uint16_t)(((uint16_t)(a << (b - 4))) & 0xFu)) >> OLSR_C_SHIFT);

    /* olsr_dbg("o2s: seconds: %u\n", seconds); */
    return seconds;
}

static void olsr_garbage_collector(struct olsr_route_entry *sublist)
{
    if(!sublist)
        return;

    if (sublist->time_left <= 0) {
        olsr_route_del(sublist);
        PICO_FREE(sublist);
        return;
    } else {
        /* sublist->time_left -= 2u; */
        sublist->time_left -= 8u;
    }

    olsr_garbage_collector(sublist->children);
    olsr_garbage_collector(sublist->next);
}

struct olsr_fwd_pkt
{
    void *buf;
    uint16_t len;
    struct pico_device *pdev;
};

static uint32_t buffer_mem_used = 0U;

static void olsr_process_out(pico_time now, void *arg)
{
    struct olsr_fwd_pkt *p = (struct olsr_fwd_pkt *)arg;
    struct pico_ip4 bcast;
    struct pico_ipv4_link *addr;
    struct olsr_dev_entry *pdev = Local_devices;
    struct olsrhdr *ohdr;
    (void)now;

    /* Send the thing out */
    ohdr = (struct olsrhdr *)p->buf;
    ohdr->len = short_be((uint16_t)p->len);

    if (p->pdev) {
        struct olsr_dev_entry *odev = olsr_get_deventry(p->pdev);
        if (!odev) {
            goto out_free;
        }

        addr = pico_ipv4_link_by_dev(p->pdev);
        if (!addr)
            goto out_free;

        ohdr->seq = short_be((uint16_t)(odev->pkt_counter)++);
        if (addr->address.addr)
            bcast.addr = (addr->netmask.addr & addr->address.addr) | (~addr->netmask.addr);
        else
            bcast.addr = 0xFFFFFFFFu;

        if ( 0 > pico_socket_sendto(udpsock, p->buf, p->len, &bcast, OLSR_PORT)) {
            olsr_dbg("olsr send\n");
        }
    } else {
        while(pdev) {
            ohdr->seq = short_be((uint16_t)(pdev->pkt_counter++));
            addr = pico_ipv4_link_by_dev(pdev->dev);
            if (!addr)
                continue;

            if (addr->address.addr)
                bcast.addr = (addr->netmask.addr & addr->address.addr) | (~addr->netmask.addr);
            else
                bcast.addr = 0xFFFFFFFFu;

            if ( 0 > pico_socket_sendto(udpsock, p->buf, p->len, &bcast, OLSR_PORT)) {
                olsr_dbg("olsr send\n");
            }

            pdev = pdev->next;
        }
    }

out_free:
    PICO_FREE(p->buf); /* XXX <-- broken? */
    buffer_mem_used -= DGRAM_MAX_SIZE;
    PICO_FREE(p);
}

static void olsr_scheduled_output(uint32_t when, void *buffer, uint16_t size, struct pico_device *pdev)
{
    struct olsr_fwd_pkt *p;
    /* olsr_dbg("Scheduling olsr packet, type:%s, size: %x\n", when == OLSR_HELLO_INTERVAL?"HELLO":"TC", size); */
    if ((buffer_mem_used + DGRAM_MAX_SIZE) > MAX_OLSR_MEM) {
        PICO_FREE(buffer);
        return;
    }

    p = PICO_ZALLOC(sizeof(struct olsr_fwd_pkt));
    if (!p) {
        OOM();
        PICO_FREE(buffer);
        return;
    }

    p->buf = buffer;
    p->len = size;
    p->pdev = pdev;
    buffer_mem_used += DGRAM_MAX_SIZE;
    pico_timer_add(1 + when - ((pico_rand() % OLSR_MAXJITTER)), &olsr_process_out, p);
}


static void refresh_routes(void)
{
    struct olsr_route_entry *local;
    struct olsr_dev_entry *icur = Local_devices;

    /* Refresh local entries */
    /* Step 1: set zero expire time for local addresses and neighbors*/
    local = Local_interfaces;
    while(local) {
        local = local->next;
    }
    /* Step 2: refresh timer for entries that are still valid.
     * Add new entries.
     */
    while(icur) {
        struct pico_ipv4_link *lnk = NULL;
        do {
            lnk = pico_ipv4_link_by_dev_next(icur->dev, lnk);
            if (!lnk) break;

            local = olsr_get_ethentry(icur->dev);
            if (local) {
                local->time_left = (OLSR_HELLO_INTERVAL << 2);
            } else if (lnk) {
                struct olsr_route_entry *e = PICO_ZALLOC(sizeof (struct olsr_route_entry));
                if (!e) {
                    olsr_dbg("olsr: adding local route entry\n");
                    OOM();
                    return;
                }

                e->destination.addr = lnk->address.addr; /* Always pick the first address */
                e->time_left = (OLSR_HELLO_INTERVAL << 2);
                e->iface = icur->dev;
                e->metric = 0;
                e->lq = 0xFF;
                e->nlq = 0xFF;
                e->next = Local_interfaces;
                Local_interfaces = e;
            }
        } while (lnk);

        /* disabled if device type != eth */
        /* refresh_neighbors(icur->dev); */
        icur = icur->next;
    }
}

static uint32_t olsr_build_hello_neighbors(uint8_t *buf, uint32_t size, struct olsr_route_entry **bookmark)
{
    uint32_t ret = 0;
    struct olsr_route_entry *local, *neighbor;
    struct olsr_neighbor *dst = (struct olsr_neighbor *) buf;
    uint32_t total_link_size = sizeof(struct olsr_neighbor) + sizeof(struct olsr_link);
    local = Local_interfaces;
    while (local) {
        neighbor = local->children;
        if (*bookmark) {
            while ((neighbor) && *bookmark != neighbor)
                neighbor = neighbor->next;
        }

        while (neighbor) {
            struct olsr_link *li = (struct olsr_link *) (buf + ret);

            if ((size - ret) < total_link_size) {
                /* Incomplete list, new datagram needed. */
                *bookmark = neighbor;
                return ret;
            }

            li->link_code = neighbor->link_type;
            li->reserved = 0;
            li->link_msg_size = short_be((uint16_t)total_link_size);
            ret += (uint32_t)sizeof(struct olsr_link);
            dst = (struct olsr_neighbor *) (buf + ret);
            dst->addr = neighbor->destination.addr;
            dst->nlq = neighbor->nlq;
            dst->lq = neighbor->lq;
            dst->reserved = 0;
            ret += (uint32_t)sizeof(struct olsr_neighbor);
            neighbor = neighbor->next;
        }
        local = local->next;
    }
    *bookmark = NULL; /* All the list was visited, no more dgrams needed */
    return ret;
}

static uint32_t olsr_build_tc_neighbors(uint8_t *buf, uint32_t size, struct olsr_route_entry **bookmark)
{
    uint32_t ret = 0;
    struct olsr_route_entry *local, *neighbor;
    struct olsr_neighbor *dst = (struct olsr_neighbor *) buf;
    local = Local_interfaces;
    while (local) {
        neighbor = local->children;
        if (*bookmark) {
            while ((neighbor) && *bookmark != neighbor)
                neighbor = neighbor->next;
        }

        while (neighbor) {
            if (size - ret < sizeof(struct olsr_neighbor)) {
                /* Incomplete list, new datagram needed. */
                *bookmark = neighbor;
                return ret;
            }

            dst->addr = neighbor->destination.addr;
            dst->nlq = neighbor->nlq;
            dst->lq = neighbor->lq;
            dst->reserved = 0;
            ret += (uint32_t)sizeof(struct olsr_neighbor);
            dst = (struct olsr_neighbor *) (buf + ret);
            neighbor = neighbor->next;
        }
        local = local->next;
    }
    *bookmark = NULL; /* All the list was visited, no more dgrams needed */
    return ret;
}

static uint32_t olsr_build_mid(uint8_t *buf, uint32_t size, struct pico_device *excluded)
{
    uint32_t ret = 0;
    struct olsr_route_entry *local;
    struct pico_ip4 *dst = (struct pico_ip4 *) buf;
    local = Local_interfaces;
    while (local) {
        if (local->iface != excluded) {
            dst->addr = local->destination.addr;
            ret += (uint32_t)sizeof(uint32_t);
            dst = (struct pico_ip4 *) (buf + ret);
            if (ret >= size)
                return (uint32_t)(ret - sizeof(uint32_t));
        }

        local = local->next;
    }
    return ret;
}


static void olsr_compose_tc_dgram(struct pico_device *pdev, struct pico_ipv4_link *ep)
{
    struct olsrmsg *msg_tc, *msg_mid;
    uint32_t size = 0, r;
    struct olsr_route_entry *last_neighbor = NULL;
    uint8_t *dgram;
    struct olsr_hmsg_tc *tc;
    do {
        dgram = PICO_ZALLOC(DGRAM_MAX_SIZE);
        if (!dgram) {
            OOM();
            return;
        }

        size = (uint32_t)sizeof(struct olsrhdr);
        ep = pico_ipv4_link_by_dev(pdev);
        if (!ep) {
            PICO_FREE(dgram);
            return;
        }


        if (!last_neighbor) {
            /* MID Message */

            msg_mid = (struct olsrmsg *)(dgram + size);
            size += (uint32_t)sizeof(struct olsrmsg);
            msg_mid->type = OLSRMSG_MID;
            msg_mid->vtime = seconds2olsr(60);
            msg_mid->orig.addr = ep->address.addr;
            msg_mid->ttl = 0xFF;
            msg_mid->hop = 0;
            msg_mid->seq = short_be(msg_counter++);
            r = olsr_build_mid(dgram + size, DGRAM_MAX_SIZE - size, pdev);
            if (r == 0) {
                size -= (uint32_t)sizeof(struct olsrmsg);
            } else {
                if ((size + r) > DGRAM_MAX_SIZE)
                    return;

                size += r;
                msg_mid->size = short_be((uint16_t)(sizeof(struct olsrmsg) + r));
            }
        }

        if (size + sizeof(struct olsrmsg) > DGRAM_MAX_SIZE)
            return;

        msg_tc = (struct olsrmsg *) (dgram + size);
        size += (uint32_t)sizeof(struct olsrmsg);
        msg_tc->type = OLSRMSG_TC;
        msg_tc->vtime = seconds2olsr(DEFAULT_VTIME);
        msg_tc->orig.addr = ep->address.addr;
        msg_tc->ttl = 0xFF;
        msg_tc->hop = 0;
        msg_tc->seq = short_be(msg_counter++);
        tc = (struct olsr_hmsg_tc *)(dgram + size);
        size += (uint32_t)sizeof(struct olsr_hmsg_tc);
        if (size > DGRAM_MAX_SIZE)
            return;

        tc->ansn = short_be(my_ansn);
        r = olsr_build_tc_neighbors(dgram + size, DGRAM_MAX_SIZE  - size, &last_neighbor);
        size += r;
        msg_tc->size = short_be((uint16_t)(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_tc) + r));
        olsr_scheduled_output(OLSR_TC_INTERVAL, dgram, (uint16_t)size, pdev );
    } while(last_neighbor);
}

static void olsr_compose_hello_dgram(struct pico_device *pdev, struct pico_ipv4_link *ep)
{
    struct olsrmsg *msg_hello;
    uint32_t size = 0, r;
    struct olsr_route_entry *last_neighbor = NULL;
    uint8_t *dgram;
    struct olsr_hmsg_hello *hello;
    /* HELLO Message */
    do {
        dgram = PICO_ZALLOC(DGRAM_MAX_SIZE);
        if (!dgram) {
            OOM();
            return;
        }

        size = (uint32_t)sizeof(struct olsrhdr);
        msg_hello = (struct olsrmsg *) (dgram + size);
        size += (uint32_t)sizeof(struct olsrmsg);
        msg_hello->type = OLSRMSG_HELLO;
        msg_hello->vtime = seconds2olsr(DEFAULT_VTIME);
        msg_hello->orig.addr = ep->address.addr;
        msg_hello->ttl = 1;
        msg_hello->hop = 0;
        msg_hello->seq = short_be(msg_counter++);
        hello = (struct olsr_hmsg_hello *)(dgram + size);
        size += (uint32_t)sizeof(struct olsr_hmsg_hello);
        hello->reserved = 0;
        hello->htime = seconds2olsr(OLSR_HELLO_INTERVAL);
        hello->htime = 0x05; /* Todo: find and define values */
        hello->willingness = 0x07;
        if (DGRAM_MAX_SIZE > size) {
            r = olsr_build_hello_neighbors(dgram + size, DGRAM_MAX_SIZE - size, &last_neighbor);
            if (r == 0) {
                /* olsr_dbg("Building hello message\n"); */
                PICO_FREE(dgram);
                return;
            }
        }

        size += r;
        msg_hello->size = short_be((uint16_t)(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_hello) + r));
        olsr_scheduled_output(OLSR_HELLO_INTERVAL, dgram, (uint16_t)size, pdev );
    } while(last_neighbor);
}

static void olsr_make_dgram(struct pico_device *pdev, int full)
{
    struct pico_ipv4_link *ep;
    ep = pico_ipv4_link_by_dev(pdev);
    if (!ep) {
        return;
    }

    if (!full) {
        olsr_compose_hello_dgram(pdev, ep);
    } else {
        olsr_compose_tc_dgram(pdev, ep);
    } /*if full */

}

/* Old code was relying on ethernet arp requests */
#define arp_storm(...) do {} while(0)

static void recv_mid(uint8_t *buffer, uint32_t len, struct olsr_route_entry *origin)
{
    uint32_t parsed = 0;
    uint32_t *address;
    struct olsr_route_entry *e;

    if (len % sizeof(uint32_t)) /*drop*/
        return;

    while (len > parsed) {
        address = (uint32_t *)(buffer + parsed);
        e = get_route_by_address(Local_interfaces, *address);
        if (!e) {
            e = PICO_ZALLOC(sizeof(struct olsr_route_entry));
            if (!e) {
                olsr_dbg("olsr allocating route\n");
                OOM();
                return;
            }

            e->time_left = (OLSR_HELLO_INTERVAL << 2);
            e->destination.addr = *address;
            e->gateway = origin;
            /* e->iface = origin->iface; */
            e->iface = NULL;
            e->metric = (uint16_t)(origin->metric + 1u);
            e->lq = origin->lq;
            e->nlq = origin->nlq;
            olsr_route_add(e);
            arp_storm(&e->destination);
        } else if (e->metric > (origin->metric + 1)) {
            olsr_route_del(e);
            e->metric = (uint16_t)(origin->metric + 1u);
            e->gateway = origin;
            e->time_left = (OLSR_HELLO_INTERVAL << 2);
            olsr_route_add(e);
        }

        parsed += (uint32_t)sizeof(uint32_t);
    }
}

/* static void recv_hello(uint8_t *buffer, uint32_t len, struct olsr_route_entry *origin) */
static void recv_hello(uint8_t *buffer, uint32_t len, struct olsr_route_entry *origin, uint16_t hops)
{
    struct olsr_link *li;
    struct olsr_route_entry *e;
    uint32_t parsed = 0;
    struct olsr_neighbor *neigh;

    if (!origin)
        return;

    /* Don't parse hello messages that were forwarded */
    if (hops > 0 || origin->metric > 1)
        return;

    if (pico_ipv4_link_get(&origin->destination))
        return;


    while (len > parsed) {
        li = (struct olsr_link *) buffer;
        neigh = (struct olsr_neighbor *)(buffer + parsed + sizeof(struct olsr_link));
        parsed += short_be(li->link_msg_size);
        e = get_route_by_address(Local_interfaces, neigh->addr);
        if (!e) {
            e = PICO_ZALLOC(sizeof(struct olsr_route_entry));
            if (!e) {
                olsr_dbg("olsr allocating route\n");
                OOM();
                return;
            }

            e->time_left = (OLSR_HELLO_INTERVAL << 2);
            e->destination.addr = neigh->addr;
            e->gateway = origin;
            e->iface = NULL;
            e->metric = (uint16_t)(origin->metric + hops + 1);
            e->link_type = OLSRLINK_UNKNOWN;
            e->lq = MIN(origin->lq, neigh->lq);
            e->nlq = MIN(origin->nlq, neigh->nlq);
            olsr_route_add(e);
            arp_storm(&e->destination);
        } else if ((e->gateway != origin) && (origin->metric > 1) && (e->metric > (origin->metric + hops + 1))) {
            olsr_route_del(e);
            e->metric = (uint16_t)(origin->metric + hops + 1);
            e->gateway = origin;
            e->time_left = (OLSR_HELLO_INTERVAL << 2);
            olsr_route_add(e);
        } else {
            e->time_left = (OLSR_HELLO_INTERVAL << 2);
        }
    }
}

/* static uint32_t reconsider_topology(uint8_t *buf, uint32_t size, struct olsr_route_entry *e) */
static uint32_t reconsider_topology(uint8_t *buf, uint32_t size, struct olsr_route_entry *e)
{
    struct olsr_hmsg_tc *tc = (struct olsr_hmsg_tc *) buf;
    uint16_t new_ansn = short_be(tc->ansn);
    uint32_t parsed = sizeof(struct olsr_hmsg_tc);
    struct olsr_route_entry *rt;
    struct olsr_neighbor *n;
    uint32_t retval = 0;

    if (!e->advertised_tc)
        retval = 1;

    if (e->advertised_tc && fresher(new_ansn, e->ansn))
    {
        PICO_FREE(e->advertised_tc); /* <--- XXX check invalid free? */
        e->advertised_tc = NULL;
        retval = 1;
    }

    /* Ignore self packets */
    if (pico_ipv4_link_get(&e->destination))
        return 0;

    if (!e->advertised_tc) {
        e->advertised_tc = PICO_ZALLOC(size);
        if (!e->advertised_tc) {
            OOM();
            olsr_dbg("Allocating forward packet\n");
            return 0;
        }

        memcpy(e->advertised_tc, buf, size);
        e->ansn = new_ansn;
        while (parsed < size) {
            n = (struct olsr_neighbor *) (buf + parsed);
            parsed += (uint32_t)sizeof(struct olsr_neighbor);
            rt = get_route_by_address(Local_interfaces, n->addr);
            if (rt && (rt->gateway == e)) {
                /* Refresh existing node */
                rt->time_left = e->time_left;
            } else if (!rt || (rt->metric > (e->metric + 1)) || (rt->nlq < n->nlq)) {
                if (!rt) {
                    rt = PICO_ZALLOC(sizeof (struct olsr_route_entry));
                    if (!rt) {
                        OOM();
                        return retval;
                    }

                    rt->destination.addr = n->addr;
                    rt->link_type = OLSRLINK_UNKNOWN;
                } else {
                    olsr_route_del(rt);
                }

                rt->iface = e->iface;
                rt->gateway = e;
                rt->metric = (uint16_t)(e->metric + 1);
                rt->lq = n->lq; /* 0xff */
                rt->nlq = n->nlq; /* 0xff */
                rt->time_left = e->time_left; /* 256 */
                olsr_route_add(rt);
            }
        }
        /* olsr_dbg("Routes changed...\n"); */
    }

    return retval;
}


static void olsr_recv(uint8_t *buffer, uint32_t len)
{
    struct olsrmsg *msg;
    struct olsrhdr *oh = (struct olsrhdr *) buffer;
    struct olsr_route_entry *ancestor;
    uint32_t parsed = 0;
    uint16_t outsize = 0;
    uint8_t *datagram;

    if (len != short_be(oh->len)) {
        return;
    }

    /* RFC 3626, section 3.4, if a packet is too small, it is silently discarded */
    if (len < 16) {
        return;
    }

    parsed += (uint32_t)sizeof(struct olsrhdr);

    datagram = PICO_ZALLOC(DGRAM_MAX_SIZE);
    if (!datagram) {
        OOM();
        return;
    }

    outsize = (uint16_t) (outsize + (sizeof(struct olsrhdr)));
    /* Section 1: parsing received messages. */
    while (len > parsed) {
        struct olsr_route_entry *origin;
        msg = (struct olsrmsg *) (buffer + parsed);
        origin = get_route_by_address(Local_interfaces, msg->orig.addr);

        if(pico_ipv4_link_find(&msg->orig) != NULL) {
            /* olsr_dbg("rebound\n"); */
            parsed += short_be(msg->size);
            continue;
        }

        /* OLSR's TTL expired. */
        if (msg->ttl < 1u) {
            parsed += short_be(msg->size);
            continue;
        }

        if (!origin) {
            if (msg->hop == 0) {
                struct olsr_route_entry *e = PICO_ZALLOC(sizeof (struct olsr_route_entry));
                if (!e) {
                    parsed += short_be(msg->size);
                    OOM();
                    break;
                }

                e->destination.addr = msg->orig.addr;
                e->link_type = OLSRLINK_SYMMETRIC;
                e->time_left = (OLSR_HELLO_INTERVAL << 2);
                e->iface = Local_devices->dev;
                e->gateway = olsr_get_ethentry(e->iface);
                e->metric = 1;
                e->lq = 0xFF;
                e->nlq = 0xFF;
                olsr_route_add(e);
            }

            parsed += short_be(msg->size);
            continue;
        }

        /* We know this is a Master host and a neighbor */
        origin->link_type = OLSRLINK_MPR;
        origin->time_left = olsr2seconds(msg->vtime);
        switch(msg->type) {
        case OLSRMSG_HELLO:
            ancestor = olsr_get_ethentry(origin->iface);
            if ((origin->metric > 1) && ancestor) {
                olsr_route_del(origin);
                origin->gateway = ancestor;
                origin->metric = 1;
                olsr_route_add(origin);
            }

            recv_hello(buffer + (uint32_t)parsed + (uint32_t)sizeof(struct olsrmsg) + (uint32_t)sizeof(struct olsr_hmsg_hello),
                       (uint32_t) ((short_be(msg->size) - (sizeof(struct olsrmsg))) - (uint32_t)sizeof(struct olsr_hmsg_hello)),
                       origin, msg->hop);
            msg->ttl = 0;
            break;
        case OLSRMSG_MID:
            if ((origin->seq != 0) && (!fresher(short_be(msg->seq), origin->seq))) {
                msg->ttl = 0;
            } else {
                recv_mid(buffer + parsed + sizeof(struct olsrmsg), (uint32_t)(short_be(msg->size) - (sizeof(struct olsrmsg))), origin);
                /* olsr_dbg("MID forwarded from origin %08x (seq: %u)\n", long_be(msg->orig.addr), short_be(msg->seq)); */
                origin->seq = short_be(msg->seq);
            }

            break;
        case OLSRMSG_TC:
            if(!pico_ipv4_link_find(&origin->destination)) {
                reconsider_topology(buffer + parsed + sizeof(struct olsrmsg), (uint32_t)(short_be(msg->size) - (sizeof(struct olsrmsg))), origin);
                if ((origin->seq != 0) && (!fresher(short_be(msg->seq), origin->seq))) {
                    msg->ttl = 0;
                } else {
                    /* olsr_dbg("TC forwarded from origin %08x (seq: %u)\n", long_be(msg->orig.addr), short_be(msg->seq)); */
                    origin->seq = short_be(msg->seq);
                }
            }

            break;
        default:
            PICO_FREE(datagram);
            return;
        }

        if (msg->ttl > 1) {
            msg->hop++;
            msg->ttl--;
            memcpy(datagram + outsize, msg, short_be(msg->size));
            outsize = (uint16_t)(outsize + short_be(msg->size));
        }

        parsed += short_be(msg->size);
    }
    /* Section 2: forwarding parsed messages that got past the filter. */
    if ((outsize > sizeof(struct olsrhdr))) {
        /* Finalize FWD packet */
        olsr_scheduled_output(OLSR_MAXJITTER, datagram, outsize, NULL);
    } else {
        /* Nothing to forward. */
        PICO_FREE(datagram);
    }
}

static void wakeup(uint16_t ev, struct pico_socket *s)
{
    unsigned char *recvbuf;
    int r = 0;
    struct pico_ip4 ANY = {
        0
    };
    uint16_t port = OLSR_PORT;
    recvbuf = PICO_ZALLOC(DGRAM_MAX_SIZE);
    if (!recvbuf) {
        OOM();
        return;
    }

    if (ev & PICO_SOCK_EV_RD) {
        r = pico_socket_recv(s, recvbuf, DGRAM_MAX_SIZE);
        if (r > 0)
            olsr_recv(recvbuf, (uint32_t)r);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        pico_socket_close(udpsock);
        udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
        if (udpsock)
            pico_socket_bind(udpsock, &ANY, &port);
    }

    PICO_FREE(recvbuf);
}

static void olsr_hello_tick(pico_time when, void *unused)
{
    struct olsr_dev_entry *d;
    (void)when;
    (void)unused;
    olsr_garbage_collector(Local_interfaces);
    refresh_routes();
    d = Local_devices;
    while(d) {
        olsr_make_dgram(d->dev, 0);
        d = d->next;
    }
    pico_timer_add(OLSR_HELLO_INTERVAL, &olsr_hello_tick, NULL);
}

static void olsr_tc_tick(pico_time when, void *unused)
{
    struct olsr_dev_entry *d;
    (void)when;
    (void)unused;
    d = Local_devices;
    while(d) {
        olsr_make_dgram(d->dev, 1);
        d = d->next;
    }
    pico_timer_add(OLSR_TC_INTERVAL, &olsr_tc_tick, NULL);
}


/* Public interface */

void pico_olsr_init(void)
{
    struct pico_ip4 ANY = {
        0
    };
    uint16_t port = OLSR_PORT;
    olsr_dbg("OLSR initialized.\n");
    if (!udpsock) {
        udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
        if (udpsock)
            pico_socket_bind(udpsock, &ANY, &port);
    }

    pico_timer_add(pico_rand() % 100, &olsr_hello_tick, NULL);
    pico_timer_add(pico_rand() % 900, &olsr_tc_tick, NULL);
}


int OOM(void)
{
    volatile int c = 3600;
    c++;
    c++;
    c++;
    return -1;
}

int pico_olsr_add(struct pico_device *dev)
{
    struct pico_ipv4_link *lnk = NULL;
    struct olsr_dev_entry *od;


    if (!dev) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* olsr_dbg("OLSR: Adding device %s\n", dev->name); */
    od = PICO_ZALLOC(sizeof(struct olsr_dev_entry));
    if (!od) {
        pico_err = PICO_ERR_ENOMEM;
        /* OOM(); */
        return -1;
    }

    od->dev = dev;
    od->next = Local_devices;
    Local_devices = od;

    do {
        char ipaddr[20];
        lnk = pico_ipv4_link_by_dev_next(dev, lnk);
        if (lnk) {
            struct olsr_route_entry *e = PICO_ZALLOC(sizeof(struct olsr_route_entry));
            /* olsr_dbg("OLSR: Found IP address %08x\n", long_be(lnk->address.addr)); */
            pico_ipv4_to_string(ipaddr, (lnk->address.addr));
            /* olsr_dbg("OLSR: Found IP address %s\n", ipaddr); */
            if (!e) {
                olsr_dbg("olsr allocating route\n");
                pico_err = PICO_ERR_ENOMEM;
                return -1;
            }

            e->destination.addr = lnk->address.addr;
            e->link_type = OLSRLINK_SYMMETRIC;
            e->time_left = (OLSR_HELLO_INTERVAL << 2);
            e->gateway = NULL;
            e->children = NULL;
            e->iface = dev;
            e->metric = 0;
            e->lq = 0xFF;
            e->nlq = 0xFF;
            e->next = Local_interfaces;
            Local_interfaces = e;

        }
    } while(lnk);

    return 0;
}

#endif
