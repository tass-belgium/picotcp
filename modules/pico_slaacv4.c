/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Bogdan Lupu
 *********************************************************************/
#include "pico_slaacv4.h"
#include "pico_arp.h"
#include "pico_constants.h"
#include "pico_stack.h"
#include "pico_hotplug_detection.h"

#ifdef PICO_SUPPORT_SLAACV4

#define SLAACV4_NETWORK  ((long_be(0xa9fe0000)))
#define SLAACV4_NETMASK  ((long_be(0xFFFF0000)))
#define SLAACV4_MINRANGE  (0x00000100) /* In host order */
#define SLAACV4_MAXRANGE  (0x0000FDFF) /* In host order */

#define SLAACV4_CREATE_IPV4(seed) ((long_be((seed % SLAACV4_MAXRANGE) + SLAACV4_MINRANGE) & ~SLAACV4_NETMASK) | SLAACV4_NETWORK)

#define PROBE_WAIT           1 /* delay between two tries during claim */
#define PROBE_NB             3 /* number of probe packets during claim */
/* #define PROBE_MIN  1 */
/* #define PROBE_MAX  2 */
#define ANNOUNCE_WAIT        2 /* delay before start announcing */
#define ANNOUNCE_NB          2 /* number of announcement packets */
#define ANNOUNCE_INTERVAL    2 /* time between announcement packets */
#define MAX_CONFLICTS       10 /* max conflicts before rate limiting */
#define MAX_CONFLICTS_FAIL  20 /* max conflicts before declaring failure */
#define RATE_LIMIT_INTERVAL 60 /* time between successive attempts */
#define DEFEND_INTERVAL     10 /* minimum interval between defensive ARP */

enum slaacv4_state {
    SLAACV4_RESET = 0,
    SLAACV4_CLAIMING,
    SLAACV4_CLAIMED,
    SLAACV4_ANNOUNCING,
    SLAACV4_ERROR
};

struct slaacv4_cookie {
    enum slaacv4_state state;
    uint8_t probe_try_nb;
    uint8_t conflict_nb;
    uint8_t announce_nb;
    struct pico_ip4 ip;
    struct pico_device *device;
    uint32_t timer;
    void (*cb)(struct pico_ip4 *ip, uint8_t code);
};

static void pico_slaacv4_hotplug_cb(struct pico_device *dev, int event);

static struct slaacv4_cookie slaacv4_local;

static uint32_t pico_slaacv4_getip(struct pico_device *dev, uint8_t rand)
{
    uint32_t seed = 0;
    if (dev->eth != NULL)
    {
        seed = pico_hash((const uint8_t *)dev->eth->mac.addr, PICO_SIZE_ETH);
    }

    if (rand)
    {
        seed += pico_rand();
    }

    return SLAACV4_CREATE_IPV4(seed);
}

static void pico_slaacv4_init_cookie(struct pico_ip4 *ip, struct pico_device *dev, struct slaacv4_cookie *ck, void (*cb)(struct pico_ip4 *ip,  uint8_t code))
{
    ck->state = SLAACV4_RESET;
    ck->probe_try_nb = 0;
    ck->conflict_nb = 0;
    ck->announce_nb = 0;
    ck->cb = cb;
    ck->device = dev;
    ck->ip.addr = ip->addr;
    ck->timer = 0;
}

static void pico_slaacv4_cancel_timers(struct slaacv4_cookie *tmp)
{
    pico_timer_cancel(tmp->timer);
    tmp->timer = 0;
}

static void pico_slaacv4_send_announce_timer(pico_time now, void *arg)
{
    struct slaacv4_cookie *tmp = (struct slaacv4_cookie *)arg;
    struct pico_ip4 netmask = { 0 };
    netmask.addr = long_be(0xFFFF0000);

    (void)now;

    if (tmp->announce_nb < ANNOUNCE_NB)
    {
        pico_arp_request(tmp->device, &tmp->ip, PICO_ARP_ANNOUNCE);
        tmp->announce_nb++;
        tmp->timer = pico_timer_add(ANNOUNCE_INTERVAL * 1000, pico_slaacv4_send_announce_timer, arg);
    }
    else
    {
        tmp->state = SLAACV4_CLAIMED;
        pico_ipv4_link_add(tmp->device, tmp->ip, netmask);
        if (tmp->cb != NULL)
            tmp->cb(&tmp->ip, PICO_SLAACV4_SUCCESS);
    }
}

static void pico_slaacv4_send_probe_timer(pico_time now, void *arg)
{
    struct slaacv4_cookie *tmp = (struct slaacv4_cookie *)arg;
    (void)now;

    if (tmp->probe_try_nb < PROBE_NB)
    {
        pico_arp_request(tmp->device, &tmp->ip, PICO_ARP_PROBE);
        tmp->probe_try_nb++;
        tmp->timer = pico_timer_add(PROBE_WAIT * 1000, pico_slaacv4_send_probe_timer, tmp);
    }
    else
    {
        tmp->state = SLAACV4_ANNOUNCING;
        tmp->timer = pico_timer_add(ANNOUNCE_WAIT * 1000, pico_slaacv4_send_announce_timer, arg);
    }
}

static void pico_slaacv4_receive_ipconflict(int reason)
{
    struct slaacv4_cookie *tmp = &slaacv4_local;

    tmp->conflict_nb++;
    pico_slaacv4_cancel_timers(tmp);

    if(tmp->state == SLAACV4_CLAIMED)
    {
        if(reason == PICO_ARP_CONFLICT_REASON_CONFLICT)
        {
          pico_ipv4_link_del(tmp->device, tmp->ip);
        }
    }

    if (tmp->conflict_nb < MAX_CONFLICTS)
    {
        tmp->state = SLAACV4_CLAIMING;
        tmp->probe_try_nb = 0;
        tmp->announce_nb = 0;
        tmp->ip.addr = pico_slaacv4_getip(tmp->device, (uint8_t)1);
        pico_arp_register_ipconflict(&tmp->ip, &tmp->device->eth->mac, pico_slaacv4_receive_ipconflict);
        pico_arp_request(tmp->device, &tmp->ip, PICO_ARP_PROBE);
        tmp->probe_try_nb++;
        tmp->timer = pico_timer_add(PROBE_WAIT * 1000, pico_slaacv4_send_probe_timer, tmp);
    }
    else if (tmp->conflict_nb < MAX_CONFLICTS_FAIL)
    {
        tmp->state = SLAACV4_CLAIMING;
        tmp->probe_try_nb = 0;
        tmp->announce_nb = 0;
        tmp->ip.addr = pico_slaacv4_getip(tmp->device, (uint8_t)1);
        pico_arp_register_ipconflict(&tmp->ip, &tmp->device->eth->mac, pico_slaacv4_receive_ipconflict);
        tmp->timer = pico_timer_add(RATE_LIMIT_INTERVAL * 1000, pico_slaacv4_send_probe_timer, tmp);
    }
    else
    {
        if (tmp->cb != NULL)
        {
            pico_hotplug_deregister(tmp->device, &pico_slaacv4_hotplug_cb);
            tmp->cb(&tmp->ip, PICO_SLAACV4_ERROR);
        }

        tmp->state = SLAACV4_ERROR;
    }

}

static void pico_slaacv4_hotplug_cb(__attribute__((unused)) struct pico_device *dev, int event)
{
    struct slaacv4_cookie *tmp = &slaacv4_local;

    if (event == PICO_HOTPLUG_EVENT_UP )
    {
        slaacv4_local.state = SLAACV4_CLAIMING;
        tmp->probe_try_nb = 0;
        tmp->announce_nb = 0;

        pico_arp_register_ipconflict(&tmp->ip, &tmp->device->eth->mac, pico_slaacv4_receive_ipconflict);
        pico_arp_request(tmp->device, &tmp->ip, PICO_ARP_PROBE);
        tmp->probe_try_nb++;
        tmp->timer = pico_timer_add(PROBE_WAIT * 1000, pico_slaacv4_send_probe_timer, tmp);

    }
    else
    {
        if (tmp->state == SLAACV4_CLAIMED )
            pico_ipv4_link_del(tmp->device, tmp->ip);
        pico_slaacv4_cancel_timers(tmp);
    }
}

int pico_slaacv4_claimip(struct pico_device *dev, void (*cb)(struct pico_ip4 *ip,  uint8_t code))
{
    struct pico_ip4 ip;

    if (!dev->eth) {
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;
    }

    if( dev->link_state != NULL )
    {
        //hotplug detect will work

        ip.addr = pico_slaacv4_getip(dev, 0);
        pico_slaacv4_init_cookie(&ip, dev, &slaacv4_local, cb);

        if (pico_hotplug_register(dev, &pico_slaacv4_hotplug_cb))
        {
            return -1;
        }
        if (dev->link_state(dev) == 1)
        {
            pico_arp_register_ipconflict(&ip, &dev->eth->mac, pico_slaacv4_receive_ipconflict);
            pico_arp_request(dev, &ip, PICO_ARP_PROBE);
            slaacv4_local.state = SLAACV4_CLAIMING;
            slaacv4_local.probe_try_nb++;
            slaacv4_local.timer = pico_timer_add(PROBE_WAIT * 1000, pico_slaacv4_send_probe_timer, &slaacv4_local);
        }
    }
    else
    {
        ip.addr = pico_slaacv4_getip(dev, 0);

        pico_slaacv4_init_cookie(&ip, dev, &slaacv4_local, cb);
        pico_arp_register_ipconflict(&ip, &dev->eth->mac, pico_slaacv4_receive_ipconflict);
        pico_arp_request(dev, &ip, PICO_ARP_PROBE);
        slaacv4_local.state = SLAACV4_CLAIMING;
        slaacv4_local.probe_try_nb++;
        slaacv4_local.timer = pico_timer_add(PROBE_WAIT * 1000, pico_slaacv4_send_probe_timer, &slaacv4_local);
    }

    return 0;
}

void pico_slaacv4_unregisterip(void)
{
    struct slaacv4_cookie *tmp = &slaacv4_local;
    struct pico_ip4 empty = {
        .addr = 0x00000000
    };

    if (tmp->state == SLAACV4_CLAIMED)
    {
        pico_ipv4_link_del(tmp->device, tmp->ip);
    }

    pico_slaacv4_cancel_timers(tmp);
    pico_slaacv4_init_cookie(&empty, NULL, tmp, NULL);
    pico_arp_register_ipconflict(&tmp->ip, NULL, NULL);
    pico_hotplug_deregister(tmp->device, &pico_slaacv4_hotplug_cb);
}

#endif
