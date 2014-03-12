/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_config.h"
#include "pico_device.h"
#include "pico_stack.h"
#include "pico_protocol.h"
#include "pico_tree.h"
#include "pico_ipv6.h"
#include "pico_ipv4.h"
#include "pico_icmp6.h"

struct pico_devices_rr_info {
    struct pico_tree_node *node_in, *node_out;
};

static struct pico_devices_rr_info Devices_rr_info = {
    NULL, NULL
};

static int pico_dev_cmp(void *ka, void *kb)
{
    struct pico_device *a = ka, *b = kb;
    if (a->hash < b->hash)
        return -1;

    if (a->hash > b->hash)
        return 1;

    return 0;
}

PICO_TREE_DECLARE(Device_tree, pico_dev_cmp);

int pico_device_init(struct pico_device *dev, const char *name, uint8_t *mac)
{
    #ifdef PICO_SUPPORT_IPV6
    struct pico_ip6 linklocal = {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xff, 0xfe, 0xaa, 0xaa, 0xaa}};
    struct pico_ip6 netmask6 = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    #endif

    uint32_t len = (uint32_t)strlen(name);
    if(len > MAX_DEVICE_NAME)
        len = MAX_DEVICE_NAME;

    memcpy(dev->name, name, len);
    dev->hash = pico_hash(dev->name, len);

    Devices_rr_info.node_in  = NULL;
    Devices_rr_info.node_out = NULL;
    dev->q_in = PICO_ZALLOC(sizeof(struct pico_queue));
    dev->q_out = PICO_ZALLOC(sizeof(struct pico_queue));
    if (!dev->q_in || !dev->q_out)
        return -1;

    pico_tree_insert(&Device_tree, dev);

    if (mac) {
        dev->eth = PICO_ZALLOC(sizeof(struct pico_ethdev));
        if (dev->eth) {
            memcpy(dev->eth->mac.addr, mac, PICO_SIZE_ETH);
            #ifdef PICO_SUPPORT_IPV6
            /* modified EUI-64 + invert universal/local bit */
            linklocal.addr[8] = (mac[0] ^ 0x02);
            linklocal.addr[9] = mac[1];
            linklocal.addr[10] = mac[2];
            linklocal.addr[13] = mac[3];
            linklocal.addr[14] = mac[4];
            linklocal.addr[15] = mac[5];
            if (pico_ipv6_link_add(dev, linklocal, netmask6)) {
                PICO_FREE(dev->q_in);
                PICO_FREE(dev->q_out);
                PICO_FREE(dev->eth);
                return -1;
            }

            #endif
        }


    } else {
        dev->eth = NULL;
        #ifdef PICO_SUPPORT_IPV6
        if (strcmp(dev->name, "loop")) {
            do {
                /* privacy extension + unset universal/local and individual/group bit */
                len = pico_rand();
                linklocal.addr[8]  = (uint8_t)((len & 0xff) & (uint8_t)(~0x03));
                linklocal.addr[9]  = (uint8_t)(len >> 8);
                linklocal.addr[10] = (uint8_t)(len >> 16);
                linklocal.addr[11] = (uint8_t)(len >> 24);
                len = pico_rand();
                linklocal.addr[12] = (uint8_t)len;
                linklocal.addr[13] = (uint8_t)(len >> 8);
                linklocal.addr[14] = (uint8_t)(len >> 16);
                linklocal.addr[15] = (uint8_t)(len >> 24);
                pico_rand_feed(dev->hash);
            } while (pico_ipv6_link_get(&linklocal));

            if (pico_ipv6_link_add(dev, linklocal, netmask6)) {
                PICO_FREE(dev->q_in);
                PICO_FREE(dev->q_out);
                return -1;
            }
        }

        #endif
    }

    #ifdef PICO_SUPPORT_IPV6
    if (dev->eth)
    {
        dev->hostvars.mtu = PICO_ETH_MTU;
        dev->hostvars.basetime = PICO_ND_REACHABLE_TIME;
        /* RFC 4861 $6.3.2 value between 0.5 and 1.5 times basetime */
        dev->hostvars.reachabletime = ((5 + (pico_rand() % 10)) * PICO_ND_REACHABLE_TIME) / 10;
        dev->hostvars.retranstime = PICO_ND_RETRANS_TIMER;
        pico_icmp6_router_solicitation(dev, &linklocal);
    }

    dev->hostvars.hoplimit = PICO_IPV6_DEFAULT_HOP;
    #endif


    return 0;
}

static void pico_queue_destroy(struct pico_queue *q)
{
    if (q) {
        pico_queue_empty(q);
        PICO_FREE(q);
    }
}

void pico_device_destroy(struct pico_device *dev)
{
    if (dev->destroy)
        dev->destroy(dev);

    pico_queue_destroy(dev->q_in);
    pico_queue_destroy(dev->q_out);

    if (dev->eth)
        PICO_FREE(dev->eth);

#ifdef PICO_SUPPORT_IPV4
    pico_ipv4_cleanup_links(dev);
#endif
#ifdef PICO_SUPPORT_IPV6
    pico_ipv6_cleanup_links(dev);
#endif
    pico_tree_delete(&Device_tree, dev);


    pico_tree_delete(&Device_tree, dev);
    Devices_rr_info.node_in  = NULL;
    Devices_rr_info.node_out = NULL;
    PICO_FREE(dev);
}

static int check_dev_serve_interrupt(struct pico_device *dev, int loop_score)
{
    if ((dev->__serving_interrupt) && (dev->dsr)) {
        /* call dsr routine */
        loop_score = dev->dsr(dev, loop_score);
    }

    return loop_score;
}

static int check_dev_serve_polling(struct pico_device *dev, int loop_score)
{
    if (dev->poll) {
        loop_score = dev->poll(dev, loop_score);
    }

    return loop_score;
}

static int devloop_in(struct pico_device *dev, int loop_score)
{
    struct pico_frame *f;
    while(loop_score > 0) {
        if (dev->q_in->frames <= 0)
            break;

        /* Receive */
        f = pico_dequeue(dev->q_in);
        if (f) {
            if (dev->eth) {
                f->datalink_hdr = f->buffer;
                pico_ethernet_receive(f);
            } else {
                f->net_hdr = f->buffer;
                pico_network_receive(f);
            }

            loop_score--;
        }
    }
    return loop_score;
}

static int devloop_sendto_dev(struct pico_device *dev, struct pico_frame *f)
{

    int ret;
    if (dev->eth) {
        ret = pico_ethernet_send(f);
        if (0 <= ret) {
            return -1;
        } else {
            if (!pico_source_is_local(f)) {
                dbg("Destination unreachable -------> SEND ICMP\n");
                pico_notify_dest_unreachable(f);
            } else {
                dbg("Destination unreachable -------> LOCAL\n");
            }

            pico_frame_discard(f);
            return 1;
        }
    } else {
        /* non-ethernet */
        if (dev->send(dev, f->start, (int)f->len) <= 0)
            return -1;

        pico_frame_discard(f);
        return 1;
    }
}

static int devloop_out(struct pico_device *dev, int loop_score)
{
    struct pico_frame *f;
    while(loop_score > 0) {
        if (dev->q_out->frames <= 0)
            break;

        /* Device dequeue + send */
        f = pico_dequeue(dev->q_out);
        if (!f)
            break;

        if (devloop_sendto_dev(dev, f) < 0)
            break;

        loop_score--;
    }
    return loop_score;
}

static int devloop(struct pico_device *dev, int loop_score, int direction)
{
    /* If device supports interrupts, read the value of the condition and trigger the dsr */
    loop_score = check_dev_serve_interrupt(dev, loop_score);

    /* If device supports polling, give control. Loop score is managed internally,
     * remaining loop points are returned. */
    loop_score = check_dev_serve_polling(dev, loop_score);

    if (direction == PICO_LOOP_DIR_OUT)
        loop_score = devloop_out(dev, loop_score);
    else
        loop_score = devloop_in(dev, loop_score);

    return loop_score;
}


static struct pico_tree_node *pico_dev_roundrobin_start(int direction)
{
    if (Devices_rr_info.node_in == NULL)
        Devices_rr_info.node_in = pico_tree_firstNode(Device_tree.root);

    if (Devices_rr_info.node_out == NULL)
        Devices_rr_info.node_out = pico_tree_firstNode(Device_tree.root);

    if (direction == PICO_LOOP_DIR_IN)
        return Devices_rr_info.node_in;
    else
        return Devices_rr_info.node_out;
}

static void pico_dev_roundrobin_end(int direction, struct pico_tree_node *last)
{
    if (direction == PICO_LOOP_DIR_IN)
        Devices_rr_info.node_in = last;
    else
        Devices_rr_info.node_out = last;
}

#define DEV_LOOP_MIN  16

int pico_devices_loop(int loop_score, int direction)
{
    struct pico_device *start, *next;
    struct pico_tree_node *next_node  = pico_dev_roundrobin_start(direction);

    if (!next_node)
        return loop_score;

    next = next_node->keyValue;
    start = next;

    /* round-robin all devices, break if traversed all devices */
    while ((loop_score > DEV_LOOP_MIN) && (next != NULL)) {
        loop_score = devloop(next, loop_score, direction);
        next_node = pico_tree_next(next_node);
        next = next_node->keyValue;
        if (next == NULL)
        {
            next_node = pico_tree_firstNode(Device_tree.root);
            next = next_node->keyValue;
        }

        if (next == start)
            break;
    }
    pico_dev_roundrobin_end(direction, next_node);
    return loop_score;
}

struct pico_device *pico_get_device(const char*name)
{
    struct pico_device *dev;
    struct pico_tree_node *index;
    pico_tree_foreach(index, &Device_tree){
        dev = index->keyValue;
        if(strcmp(name, dev->name) == 0)
            return dev;
    }
    return NULL;
}

int32_t pico_device_broadcast(struct pico_frame *f)
{
    struct pico_tree_node *index;
    int32_t ret = -1;

    pico_tree_foreach(index, &Device_tree)
    {
        struct pico_device *dev = index->keyValue;
        if(dev != f->dev)
        {
            struct pico_frame *copy = pico_frame_copy(f);

            if(!copy)
                return -1;

            copy->dev = dev;
            copy->dev->send(copy->dev, copy->start, (int)copy->len);
            pico_frame_discard(copy);
        }
        else
        {
            ret = f->dev->send(f->dev, f->start, (int)f->len);
        }
    }

    return ret;
}
