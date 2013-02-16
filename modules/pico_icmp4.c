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


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


/* Functions */

static int pico_icmp4_checksum(struct pico_frame *f)
{
  struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
  if (!hdr)
    return -1;
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
  if (hdr->type == PICO_ICMP_ECHO) {
    hdr->type = PICO_ICMP_ECHOREPLY;
    /* Ugly, but the best way to get ICMP data size here. */
    f->transport_len = f->buffer_len - PICO_SIZE_IP4HDR;
    if (f->dev->eth)
      f->transport_len -= PICO_SIZE_ETHHDR;
    pico_icmp4_checksum(f);
    f->net_hdr = f->transport_hdr - PICO_SIZE_IP4HDR;
    f->start = f->net_hdr;
    f->len = f->buffer_len;
    if (f->dev->eth)
      f->len -= PICO_SIZE_ETHHDR;
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
  .q_in = &in,
  .q_out = &out,
};

static int pico_icmp4_notify(struct pico_frame *f, uint8_t type, uint8_t code)
{

  struct pico_frame *reply = pico_proto_ipv4.alloc(&pico_proto_ipv4, 8 + sizeof(struct pico_ipv4_hdr) + PICO_ICMPHDR_UN_SIZE);
  struct pico_icmp4_hdr *hdr;
  struct pico_ipv4_hdr *info = (struct pico_ipv4_hdr*)(f->net_hdr);

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
  return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_PORT);
}

int pico_icmp4_proto_unreachable(struct pico_frame *f)
{
  return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_PROTOCOL);
}

int pico_icmp4_dest_unreachable(struct pico_frame *f)
{
  return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_HOST);
}

int pico_icmp4_ttl_expired(struct pico_frame *f)
{
  return pico_icmp4_notify(f, PICO_ICMP_TIME_EXCEEDED, PICO_ICMP_TIMXCEED_INTRANS);
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
  unsigned long timestamp;
  int interval;
  int timeout;
  void (*cb)(struct pico_icmp4_stats*);
  RB_ENTRY(pico_icmp4_ping_cookie) node;
};

RB_HEAD(ping_tree, pico_icmp4_ping_cookie);
RB_PROTOTYPE_STATIC(ping_tree, pico_icmp4_ping_cookie, node, cookie_compare);

static int cookie_compare(struct pico_icmp4_ping_cookie *a, struct pico_icmp4_ping_cookie *b)
{
  if (a->id < b->id)
    return -1;
  if (a->id > b->id)
    return 1;
  return (a->seq - b->seq);
}

RB_GENERATE_STATIC(ping_tree, pico_icmp4_ping_cookie, node, cookie_compare);

static struct ping_tree Pings;

static int pico_icmp4_send_echo(struct pico_icmp4_ping_cookie *cookie)
{
  struct pico_frame *echo = pico_proto_ipv4.alloc(&pico_proto_ipv4, PICO_ICMPHDR_UN_SIZE + cookie->size);
  struct pico_icmp4_hdr *hdr;

  hdr = (struct pico_icmp4_hdr *) echo->transport_hdr;

  hdr->type = PICO_ICMP_ECHO;
  hdr->code = 0;
  hdr->hun.ih_idseq.idseq_id = short_be(cookie->id);
  hdr->hun.ih_idseq.idseq_seq = short_be(cookie->seq);
  echo->transport_len = PICO_ICMPHDR_UN_SIZE + cookie->size;
  echo->payload = echo->transport_hdr + PICO_ICMPHDR_UN_SIZE;
  echo->payload_len = cookie->size;
  /* XXX: Fill payload */
  pico_icmp4_checksum(echo);
  pico_ipv4_frame_push(echo, &cookie->dst, PICO_PROTO_ICMP4);
  return 0;
}


static void ping_timeout(unsigned long now, void *arg)
{
  struct pico_icmp4_ping_cookie *cookie = (struct pico_icmp4_ping_cookie *)arg;
  if (RB_FIND(ping_tree, &Pings, cookie)) {
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
    RB_REMOVE(ping_tree, &Pings, cookie);
    pico_free(cookie);
  }
}

static void next_ping(unsigned long now, void *arg);
static inline void send_ping(struct pico_icmp4_ping_cookie *cookie)
{
  pico_icmp4_send_echo(cookie);
  cookie->timestamp = pico_tick;
  pico_timer_add(cookie->timeout, ping_timeout, cookie);
  pico_timer_add(cookie->interval, next_ping, cookie);
}

static void next_ping(unsigned long now, void *arg)
{
  struct pico_icmp4_ping_cookie *newcookie, *cookie = (struct pico_icmp4_ping_cookie *)arg;
  if (RB_FIND(ping_tree, &Pings, cookie)) {
    if (cookie->seq < cookie->count) {
      newcookie = pico_zalloc(sizeof(struct pico_icmp4_ping_cookie));
      if (!newcookie)
        return;
      memcpy(newcookie, cookie, sizeof(struct pico_icmp4_ping_cookie));
      newcookie->seq++;
      RB_INSERT(ping_tree, &Pings, newcookie);
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

  cookie = RB_FIND(ping_tree, &Pings, &test);
  if (cookie) {
    struct pico_icmp4_stats stats;
    cookie->err = PICO_PING_ERR_REPLIED;
    stats.dst = cookie->dst;
    stats.seq = cookie->seq;
    stats.size = cookie->size;
    stats.time = pico_tick - cookie->timestamp;
    stats.err = cookie->err;
		if(cookie->cb != NULL)
    	cookie->cb(&stats);
    /* XXX cb */
  } else {
    dbg("Reply for seq=%d, not found.\n", test.seq);
  }
}

int pico_icmp4_ping(char *dst, int count, int interval, int timeout, int size, void (*cb)(struct pico_icmp4_stats *))
{
  static uint16_t next_id = 0x91c0;
  struct pico_icmp4_ping_cookie *cookie;

  cookie = pico_zalloc(sizeof(struct pico_icmp4_ping_cookie));
  if (!cookie)
    return -1;

  if (pico_string_to_ipv4(dst, &cookie->dst.addr) < 0) {
    pico_free(cookie);
    return -1;
  }
  cookie->seq = 1;
  cookie->id = next_id++;
  cookie->err = PICO_PING_ERR_PENDING;
  cookie->size = size;
  cookie->interval = interval;
  cookie->timeout = timeout;
  cookie->cb = cb;
  cookie->count = count;

  RB_INSERT(ping_tree, &Pings, cookie);
  send_ping(cookie);

  return 0;
}

#endif
