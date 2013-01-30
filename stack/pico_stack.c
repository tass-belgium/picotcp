/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Daniele Lacamera
*********************************************************************/


#include "pico_config.h"
#include "pico_frame.h"
#include "pico_device.h"
#include "pico_protocol.h"
#include "pico_addressing.h"

#include "pico_eth.h"
#include "pico_arp.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_icmp4.h"
#include "pico_igmp2.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "heap.h"

#ifdef PICO_SUPPORT_MCAST
# define PICO_SIZE_MCAST 3
  const uint8_t PICO_ETHADDR_MCAST[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x00};
#endif

volatile unsigned long pico_tick;
volatile pico_err_t pico_err;

static uint32_t _rand_seed;


static void pico_rand_feed(uint32_t feed)
{
  if (!feed)
    return;
  _rand_seed *= 1664525;
  _rand_seed += 1013904223;
  _rand_seed ^= ~(feed);
}

uint32_t pico_rand(void)
{
  pico_rand_feed(pico_tick);
  return _rand_seed;
}

/* NOTIFICATIONS: distributed notifications for stack internal errors.
 */

int pico_notify_socket_unreachable(struct pico_frame *f)
{
  if (0) {}
#ifdef PICO_SUPPORT_ICMP4 
  else if (IS_IPV4(f)) {
    pico_icmp4_port_unreachable(f);
  }
#endif
#ifdef PICO_SUPPORT_ICMP6 
  else if (IS_IPV6(f)) {
    pico_icmp6_port_unreachable(f);
  }
#endif

  return 0;
}

int pico_notify_proto_unreachable(struct pico_frame *f)
{
  if (0) {}
#ifdef PICO_SUPPORT_ICMP4 
  else if (IS_IPV4(f)) {
    pico_icmp4_proto_unreachable(f);
  }
#endif
#ifdef PICO_SUPPORT_ICMP6 
  else if (IS_IPV6(f)) {
    pico_icmp6_proto_unreachable(f);
  }
#endif
  return 0;
}

int pico_notify_dest_unreachable(struct pico_frame *f)
{
  if (0) {}
#ifdef PICO_SUPPORT_ICMP4 
  else if (IS_IPV4(f)) {
    pico_icmp4_dest_unreachable(f);
  }
#endif
#ifdef PICO_SUPPORT_ICMP6 
  else if (IS_IPV6(f)) {
    pico_icmp6_dest_unreachable(f);
  }
#endif
  return 0;
}

int pico_notify_ttl_expired(struct pico_frame *f)
{
  if (0) {}
#ifdef PICO_SUPPORT_ICMP4 
  else if (IS_IPV4(f)) {
    pico_icmp4_ttl_expired(f);
  }
#endif
#ifdef PICO_SUPPORT_ICMP6 
  else if (IS_IPV6(f)) {
    pico_icmp6_ttl_expired(f);
  }
#endif
  return 0;
}


/* Transport layer */
int pico_transport_receive(struct pico_frame *f, uint8_t proto)
{
  int ret = -1;
  switch (proto) {

#ifdef PICO_SUPPORT_ICMP4
  case PICO_PROTO_ICMP4:
    ret = pico_enqueue(pico_proto_icmp4.q_in, f);
    break;
#endif

#ifdef PICO_SUPPORT_IGMP2
  case PICO_PROTO_IGMP2:
    ret = pico_enqueue(pico_proto_igmp2.q_in, f);
    break;
#endif

#ifdef PICO_SUPPORT_UDP
  case PICO_PROTO_UDP:
    ret = pico_enqueue(pico_proto_udp.q_in, f);
    break;
#endif

#ifdef PICO_SUPPORT_TCP
  case PICO_PROTO_TCP:
    ret = pico_enqueue(pico_proto_tcp.q_in, f);
    break;
#endif

  default:
    /* Protocol not available */
    dbg("pkt: no such protocol (%d)\n", proto);
    pico_notify_proto_unreachable(f);
    pico_frame_discard(f);
    ret = -1;
 }
 return ret;
}

int pico_transport_send(struct pico_frame *f)
{
  if (!f || !f->sock || !f->sock->proto) {
    pico_frame_discard(f);
    return -1;
  }
  return f->sock->proto->push(f->sock->net, f);
}

int pico_network_receive(struct pico_frame *f)
{
  if (0) {}
#ifdef PICO_SUPPORT_IPV4
  else if (IS_IPV4(f)) {
    pico_enqueue(pico_proto_ipv4.q_in, f);
  }
#endif
#ifdef PICO_SUPPORT_IPV6
  else if (IS_IPV6(f)) {
    pico_enqueue(pico_proto_ipv6.q_in, f);
  }
#endif
  else {
    dbg("Network not found.\n");
    pico_frame_discard(f);
    return -1;
  }
  return f->buffer_len;
}


/* Network layer: interface towards socket for frame sending */
int pico_network_send(struct pico_frame *f)
{
  if (!f || !f->sock || !f->sock->net) {
    pico_frame_discard(f);
    return -1;
  }
  return f->sock->net->push(f->sock->net, f);
}

int pico_destination_is_local(struct pico_frame *f)
{
  if (0) { }
#ifdef PICO_SUPPORT_IPV4
  else if (IS_IPV4(f)) {
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
    if (pico_ipv4_link_find(&hdr->dst))
      return 1;
  }
#endif
#ifdef PICO_SUPPORT_IPV6
  else if (IS_IPV6(f)) {
  }
#endif
  return 0;
}

int pico_source_is_local(struct pico_frame *f)
{
  if (0) { }
#ifdef PICO_SUPPORT_IPV4
  else if (IS_IPV4(f)) {
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
    if (pico_ipv4_link_find(&hdr->src))
      return 1;
  }
#endif
#ifdef PICO_SUPPORT_IPV6
  else if (IS_IPV6(f)) {
  /* XXX */
  }
#endif
  return 0;


}


/* DATALINK LEVEL: interface from network to the device
 * and vice versa.
 */

/* The pico_ethernet_receive() function is used by 
 * those devices supporting ETH in order to push packets up 
 * into the stack. 
 */
int pico_ethernet_receive(struct pico_frame *f)
{
  struct pico_eth_hdr *hdr;
  if (!f || !f->dev || !f->datalink_hdr)
    goto discard;
  hdr = (struct pico_eth_hdr *) f->datalink_hdr;
  f->datalink_len = sizeof(struct pico_eth_hdr);
  if ( (memcmp(hdr->daddr, f->dev->eth->mac.addr, PICO_SIZE_ETH) != 0) && 
#ifdef PICO_SUPPORT_MCAST
    (memcmp(hdr->daddr, PICO_ETHADDR_MCAST, PICO_SIZE_MCAST) != 0) &&
#endif
    (memcmp(hdr->daddr, PICO_ETHADDR_ALL, PICO_SIZE_ETH) != 0) ) 
    goto discard;

  f->net_hdr = f->datalink_hdr + f->datalink_len;
  if (hdr->proto == PICO_IDETH_ARP)
    return pico_arp_receive(f);
  if ((hdr->proto == PICO_IDETH_IPV4) || (hdr->proto == PICO_IDETH_IPV6))
    return pico_network_receive(f);
discard:
  pico_frame_discard(f);
  return -1;
}

static int destination_is_bcast(struct pico_frame *f)
{
  if (!f)
    return 0;

  if (IS_IPV6(f))
    return 0;
#ifdef PICO_SUPPORT_IPV4
  else {
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    return pico_ipv4_is_broadcast(hdr->dst.addr);
  }
#endif
  return 0;
}

#ifdef PICO_SUPPORT_MCAST
static int destination_is_mcast(struct pico_frame *f)
{
  if (!f)
    return 0;

  if (IS_IPV6(f))
    return 0;
#ifdef PICO_SUPPORT_IPV4
  else {
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    return !pico_ipv4_is_unicast(hdr->dst.addr);
  }
#endif
  return 0;
}

static struct pico_eth *pico_ethernet_mcast_translate(struct pico_frame *f, uint8_t *pico_mcast_mac)
{
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

  /* place 23 lower bits of IP in lower 23 bits of MAC */
  /* Remark: IP is little endian, MAC is big endian */
  pico_mcast_mac[5] = ((hdr->dst.addr) & 0xFF000000) >> 24;
  pico_mcast_mac[4] = ((hdr->dst.addr) & 0x00FF0000) >> 16; 
  pico_mcast_mac[3] = ((hdr->dst.addr) & 0x00007F00) >> 8;

  return (struct pico_eth *)pico_mcast_mac;
}
#endif /* PICO_SUPPORT_MCAST */

/* This is called by dev loop in order to ensure correct ethernet addressing.
 * Returns 0 if the destination is unknown, and -1 if the packet is not deliverable
 * due to ethernet addressing (i.e., no arp association was possible. 
 *
 * Only IP packets must pass by this. ARP will always use direct dev->send() function, so
 * we assume IP is used.
 */
int pico_ethernet_send(struct pico_frame *f, void *nexthop)
{
  struct pico_arp *a4 = NULL;
  struct pico_eth *dstmac = NULL;

  if (IS_IPV6(f)) {
    /*TODO: Neighbor solicitation */
    dstmac = NULL;
  }

  else if (IS_IPV4(f)) {
    if (IS_BCAST(f) || destination_is_bcast(f)) {
     dbg("IPV4: Destination is BROADCAST!\n");
     dstmac = (struct pico_eth *) PICO_ETHADDR_ALL;
    } 
#ifdef PICO_SUPPORT_MCAST
    else if (destination_is_mcast(f)) {
      uint8_t pico_mcast_mac[6] = {0x01, 0x00, 0x05, 0x00, 0x00, 0x00};
      dstmac = pico_ethernet_mcast_translate(f, pico_mcast_mac);
    } 
#endif
    else {
      a4 = pico_arp_get(f);
      if (!a4)
        return 0;
      dstmac = (struct pico_eth *) a4;
    }
    /* This sets destination and source address, then pushes the packet to the device. */
    if (dstmac && (f->start > f->buffer) && ((f->start - f->buffer) >= PICO_SIZE_ETHHDR)) {
      struct pico_eth_hdr *hdr;
      f->start -= PICO_SIZE_ETHHDR;
      f->len += PICO_SIZE_ETHHDR;
      f->datalink_hdr = f->start;
      f->datalink_len = PICO_SIZE_ETHHDR;
      hdr = (struct pico_eth_hdr *) f->datalink_hdr;
      memcpy(hdr->saddr, f->dev->eth->mac.addr, PICO_SIZE_ETH);
      memcpy(hdr->daddr, dstmac, PICO_SIZE_ETH);
      hdr->proto = PICO_IDETH_IPV4;
      return f->dev->send(f->dev, f->start, f->len);
    } else {
      return -1;
    }
  } /* End IPV4 ethernet addressing */
  return -1;
}

void pico_store_network_origin(void *src, struct pico_frame *f)
{
  #ifdef PICO_SUPPORT_IPV4
  struct pico_ip4 *ip4;
  #endif

  #ifdef PICO_SUPPORT_IPV6
  struct pico_ip6 *ip6;
  #endif

  #ifdef PICO_SUPPORT_IPV4
  if (IS_IPV4(f)) {
    struct pico_ipv4_hdr *hdr;
    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    ip4 = (struct pico_ip4 *) src;
    ip4->addr = hdr->src.addr;
  }
  #endif
  #ifdef PICO_SUPPORT_IPV6
  if (IS_IPV6(f)) {
    struct pico_ipv6_hdr *hdr;
    hdr = (struct pico_ipv6_hdr *) f->net_hdr;
    ip6 = (struct pico_ip6 *) src;
    memcpy(ip6->addr, hdr->src.addr, PICO_SIZE_IP6);
  }
  #endif
}


/* LOWEST LEVEL: interface towards devices. */
/* Device driver will call this function which returns immediately.
 * Incoming packet will be processed later on in the dev loop.
 */
int pico_stack_recv(struct pico_device *dev, uint8_t *buffer, int len)
{
  struct pico_frame *f;
  int ret;
  if (len <= 0)
    return -1;
  f = pico_frame_alloc(len);
  if (!f)
    return -1;

  /* Association to the device that just received the frame. */
  f->dev = dev;

  /* Setup the start pointer, lenght. */
  f->start = f->buffer;
  f->len = f->buffer_len;
  if (f->len > 8) {
    int mid_frame = f->buffer_len >> 1;
    pico_rand_feed(*(uint32_t*)(f->buffer + mid_frame));
  }
  memcpy(f->buffer, buffer, len);
  ret = pico_enqueue(dev->q_in, f);
  if (ret <= 0) {
    pico_frame_discard(f);
  }
  return ret;
}

int pico_sendto_dev(struct pico_frame *f)
{
  if (!f->dev) {
    pico_frame_discard(f);
    return -1;
  } else {
    if (f->len > 8) {
      int mid_frame = f->buffer_len >> 1;
      pico_rand_feed(*(uint32_t*)(f->buffer + mid_frame));
    }
    return pico_enqueue(f->dev->q_out, f);
  }
}

struct pico_timer
{
  unsigned long expire;
  void *arg;
  void (*timer)(unsigned long timestamp, void *arg);
};

typedef struct pico_timer pico_timer;

DECLARE_HEAP(pico_timer, expire);

static heap_pico_timer *Timers;

void pico_check_timers(void)
{
  struct pico_timer *t = heap_first(Timers);
  pico_tick = PICO_TIME_MS();
  while((t) && (t->expire < pico_tick)) {
    t->timer(pico_tick, t->arg);
    heap_peek(Timers, t);
    t = heap_first(Timers);
  }
}

void pico_stack_tick(void)
{
    int score;
    pico_check_timers();
    score = pico_devices_loop(100);
    pico_rand_feed(score);
    score = pico_protocols_loop(100);
    pico_rand_feed(score);
    score = pico_sockets_loop(100);
    pico_rand_feed(score);
}

void pico_stack_loop(void)
{
  while(1) {
    pico_stack_tick();
    PICO_IDLE();
  }
}

void pico_timer_add(unsigned long expire, void (*timer)(unsigned long, void *), void *arg)
{
  pico_timer t;
  t.expire = PICO_TIME_MS() + expire;
  t.arg = arg;
  t.timer = timer;
  heap_insert(Timers, &t);
  if (Timers->n > 10) {
    dbg("Warning: I have %d timers\n", Timers->n);
  }
}

void pico_stack_init(void)
{

#ifdef PICO_SUPPORT_IPV4
  pico_protocol_init(&pico_proto_ipv4);
#endif

#ifdef PICO_SUPPORT_IPV6
  pico_protocol_init(&pico_proto_ipv6);
#endif

#ifdef PICO_SUPPORT_ICMP4
  pico_protocol_init(&pico_proto_icmp4);
#endif

#ifdef PICO_SUPPORT_IGMP2
  pico_protocol_init(&pico_proto_igmp2);
#endif

#ifdef PICO_SUPPORT_UDP
  pico_protocol_init(&pico_proto_udp);
#endif

#ifdef PICO_SUPPORT_TCP
  pico_protocol_init(&pico_proto_tcp);
#endif

  pico_rand_feed(123456);

  /* Initialize timer heap */
  Timers = heap_init();
  pico_stack_tick();
  pico_stack_tick();
  pico_stack_tick();
}

