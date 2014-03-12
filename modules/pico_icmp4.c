/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_icmp4.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_eth.h"
#include "pico_device.h"
#include "pico_stack.h"
#include "pico_tree.h"

/* Queues */
static struct pico_queue icmp_in = {
    0
};
static struct pico_queue icmp_out = {
    0
};


/* Functions */

static int pico_icmp4_checksum(struct pico_frame *f)
{
    struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
    if (!hdr) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    hdr->crc = 0;
    hdr->crc = short_be(pico_checksum(hdr, f->transport_len));
    return 0;
}

#ifdef PICO_SUPPORT_PING
static void ping_recv_reply(struct pico_frame *f);
#endif

static int pico_icmp4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
    IGNORE_PARAMETER(self);

    if (hdr->type == PICO_ICMP_ECHO) {
        hdr->type = PICO_ICMP_ECHOREPLY;
        /* outgoing frames require a f->len without the ethernet header len */
        if (f->dev && f->dev->eth)
            f->len -= PICO_SIZE_ETHHDR;

        pico_icmp4_checksum(f);
        pico_ipv4_rebound(f);
    } else if (hdr->type == PICO_ICMP_UNREACH) {
        f->net_hdr = f->transport_hdr + PICO_ICMPHDR_UN_SIZE;
        pico_ipv4_unreachable(f, hdr->code);
    } else if (hdr->type == PICO_ICMP_ECHOREPLY) {
#ifdef PICO_SUPPORT_PING
        ping_recv_reply(f);
#endif
        pico_frame_discard(f);
    } else {
        pico_frame_discard(f);
    }

    return 0;
}

static int pico_icmp4_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(f);
    dbg("Called %s\n", __FUNCTION__);
    return 0;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_icmp4 = {
    .name = "icmp4",
    .proto_number = PICO_PROTO_ICMP4,
    .layer = PICO_LAYER_TRANSPORT,
    .process_in = pico_icmp4_process_in,
    .process_out = pico_icmp4_process_out,
    .q_in = &icmp_in,
    .q_out = &icmp_out,
};

static int pico_icmp4_notify(struct pico_frame *f, uint8_t type, uint8_t code)
{
    struct pico_frame *reply;
    struct pico_icmp4_hdr *hdr;
    struct pico_ipv4_hdr *info;
    if (f == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    reply = pico_proto_ipv4.alloc(&pico_proto_ipv4, 8 + sizeof(struct pico_ipv4_hdr) + PICO_ICMPHDR_UN_SIZE);
    info = (struct pico_ipv4_hdr*)(f->net_hdr);
    hdr = (struct pico_icmp4_hdr *) reply->transport_hdr;
    hdr->type = type;
    hdr->code = code;
    hdr->hun.ih_pmtu.ipm_nmtu = short_be(1500);
    hdr->hun.ih_pmtu.ipm_void = 0;
    reply->transport_len = 8 + sizeof(struct pico_ipv4_hdr) +  PICO_ICMPHDR_UN_SIZE;
    reply->payload = reply->transport_hdr + PICO_ICMPHDR_UN_SIZE;
    memcpy(reply->payload, f->net_hdr, 8 + sizeof(struct pico_ipv4_hdr));
    pico_icmp4_checksum(reply);
    pico_ipv4_frame_push(reply, &info->src, PICO_PROTO_ICMP4);
    return 0;
}

int pico_icmp4_port_unreachable(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_PORT);
}

int pico_icmp4_proto_unreachable(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_PROTOCOL);
}

int pico_icmp4_dest_unreachable(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_HOST);
}

int pico_icmp4_ttl_expired(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_TIME_EXCEEDED, PICO_ICMP_TIMXCEED_INTRANS);
}

int pico_icmp4_mtu_exceeded(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_NEEDFRAG);
}

int pico_icmp4_packet_filtered(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    /*Packet Filtered: type 3, code 13 (Communication Administratively Prohibited)*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_FILTER_PROHIB);
}

/***********************/
/* Ping implementation */
/***********************/
/***********************/
/***********************/
/***********************/


#ifdef PICO_SUPPORT_PING


struct pico_icmp4_ping_cookie
{
    struct pico_ip4 dst;
    uint16_t err;
    uint16_t id;
    uint16_t seq;
    uint16_t size;
    int count;
    pico_time timestamp;
    int interval;
    int timeout;
    void (*cb)(struct pico_icmp4_stats*);

};

static int cookie_compare(void *ka, void *kb)
{
    struct pico_icmp4_ping_cookie *a = ka, *b = kb;
    if (a->id < b->id)
        return -1;

    if (a->id > b->id)
        return 1;

    return (a->seq - b->seq);
}

PICO_TREE_DECLARE(Pings, cookie_compare);

static int8_t pico_icmp4_send_echo(struct pico_icmp4_ping_cookie *cookie)
{
    struct pico_frame *echo = pico_proto_ipv4.alloc(&pico_proto_ipv4, (uint16_t)(PICO_ICMPHDR_UN_SIZE + cookie->size));
    struct pico_icmp4_hdr *hdr;
    if (!echo) {
        return -1;
    }

    hdr = (struct pico_icmp4_hdr *) echo->transport_hdr;

    hdr->type = PICO_ICMP_ECHO;
    hdr->code = 0;
    hdr->hun.ih_idseq.idseq_id = short_be(cookie->id);
    hdr->hun.ih_idseq.idseq_seq = short_be(cookie->seq);
    echo->transport_len = (uint16_t)(PICO_ICMPHDR_UN_SIZE + cookie->size);
    echo->payload = echo->transport_hdr + PICO_ICMPHDR_UN_SIZE;
    echo->payload_len = cookie->size;
    /* XXX: Fill payload */
    pico_icmp4_checksum(echo);
    pico_ipv4_frame_push(echo, &cookie->dst, PICO_PROTO_ICMP4);
    return 0;
}


static void ping_timeout(pico_time now, void *arg)
{
    struct pico_icmp4_ping_cookie *cookie = (struct pico_icmp4_ping_cookie *)arg;
    IGNORE_PARAMETER(now);

    if(pico_tree_findKey(&Pings, cookie)) {
        if (cookie->err == PICO_PING_ERR_PENDING) {
            struct pico_icmp4_stats stats;
            stats.dst = cookie->dst;
            stats.seq = cookie->seq;
            stats.time = 0;
            stats.size = cookie->size;
            stats.err = PICO_PING_ERR_TIMEOUT;
            dbg(" ---- Ping timeout!!!\n");
            cookie->cb(&stats);
        }

        pico_tree_delete(&Pings, cookie);
        PICO_FREE(cookie);
    }
}

static void next_ping(pico_time now, void *arg);
static inline void send_ping(struct pico_icmp4_ping_cookie *cookie)
{
    (void)(pico_icmp4_send_echo(cookie));
    cookie->timestamp = pico_tick;
    pico_timer_add((uint32_t)cookie->timeout, ping_timeout, cookie);
    if (cookie->seq < (uint16_t)cookie->count)
        pico_timer_add((uint32_t)cookie->interval, next_ping, cookie);
}

static void next_ping(pico_time now, void *arg)
{
    struct pico_icmp4_ping_cookie *newcookie, *cookie = (struct pico_icmp4_ping_cookie *)arg;
    IGNORE_PARAMETER(now);

    if(pico_tree_findKey(&Pings, cookie)) {
        if (cookie->seq < (uint16_t)cookie->count) {
            newcookie = PICO_ZALLOC(sizeof(struct pico_icmp4_ping_cookie));
            if (!newcookie)
                return;

            memcpy(newcookie, cookie, sizeof(struct pico_icmp4_ping_cookie));
            newcookie->seq++;

            pico_tree_insert(&Pings, newcookie);
            send_ping(newcookie);
        }
    }
}


static void ping_recv_reply(struct pico_frame *f)
{
    struct pico_icmp4_ping_cookie test, *cookie;
    struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
    test.id  = short_be(hdr->hun.ih_idseq.idseq_id );
    test.seq = short_be(hdr->hun.ih_idseq.idseq_seq);

    cookie = pico_tree_findKey(&Pings, &test);
    if (cookie) {
        struct pico_icmp4_stats stats;
        cookie->err = PICO_PING_ERR_REPLIED;
        stats.dst = cookie->dst;
        stats.seq = cookie->seq;
        stats.size = cookie->size;
        stats.time = pico_tick - cookie->timestamp;
        stats.err = cookie->err;
        stats.ttl = ((struct pico_ipv4_hdr *)f->net_hdr)->ttl;
        if(cookie->cb != NULL)
            cookie->cb(&stats);
    } else {
        dbg("Reply for seq=%d, not found.\n", test.seq);
    }
}

int pico_icmp4_ping(char *dst, int count, int interval, int timeout, int size, void (*cb)(struct pico_icmp4_stats *))
{
    static uint16_t next_id = 0x91c0;
    struct pico_icmp4_ping_cookie *cookie;

    if((dst == NULL) || (interval == 0) || (timeout == 0) || (count == 0)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    cookie = PICO_ZALLOC(sizeof(struct pico_icmp4_ping_cookie));
    if (!cookie) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    if (pico_string_to_ipv4(dst, &cookie->dst.addr) < 0) {
        pico_err = PICO_ERR_EINVAL;
        PICO_FREE(cookie);
        return -1;
    }

    cookie->seq = 1;
    cookie->id = next_id++;
    cookie->err = PICO_PING_ERR_PENDING;
    cookie->size = (uint16_t)size;
    cookie->interval = interval;
    cookie->timeout = timeout;
    cookie->cb = cb;
    cookie->count = count;

    pico_tree_insert(&Pings, cookie);
    send_ping(cookie);

    return 0;

}

#endif
