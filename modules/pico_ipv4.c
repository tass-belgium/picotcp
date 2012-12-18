/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Daniele Lacamera, Markian Yskout
*********************************************************************/


#include "pico_ipv4.h"
#include "pico_config.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


/* Functions */

static inline int pico_is_digit(char c)
{
  if(c < '0' || c > '9')
    return 0;
  return 1;
} 
 
int pico_ipv4_to_string(char *ipbuf, const uint32_t ip)
{
  const unsigned char *addr = (unsigned char *) &ip;
  int i;
  
  for(i = 0; i < 4; i++)
  {
    if(addr[i] > 99){
      *ipbuf++ = '0' + (addr[i] / 100);
      *ipbuf++ = '0' + ((addr[i] % 100) / 10);
      *ipbuf++ = '0' + ((addr[i] % 100) % 10);
    }else if(addr[i] > 9){
      *ipbuf++ = '0' + (addr[i] / 10);
      *ipbuf++ = '0' + (addr[i] % 10);
    }else{
      *ipbuf++ = '0' + addr[i];
    }
    if(i < 3)
      *ipbuf++ = '.';
  }
  *ipbuf = '\0';
  
  return 0;
}
    
int pico_string_to_ipv4(const char *ipstr, uint32_t *ip)
{
  unsigned char buf[4] = {0};
  int cnt = 0;
  int p;

  if(!ipstr || !ip)
    return -1;

  while((p = *ipstr++) != 0)
  {
    if(pico_is_digit(p)){
      buf[cnt] = (10 * buf[cnt]) + (p - '0');
    }else if(p == '.'){
        cnt++;
    }else{
      return -1;
    }
  }   
  
  /* Handle short notation */
  if(cnt == 1){
    buf[3] = buf[1];
    buf[1] = 0;
    buf[2] = 0;
  }else if (cnt == 2){
    buf[3] = buf[2];
    buf[2] = 0;
  }else if(cnt != 3){
    /* String could not be parsed, return error */
    return -1;
  }   

  *ip = *((uint32_t *) &buf[0]);

  return 0;

}  

int pico_ipv4_valid_netmask(uint32_t mask)
{
  int cnt = 0;
  int end = 0;
  int i;
  uint32_t mask_swap = long_be(mask);

  /* 
   * Swap bytes for convenient parsing 
   * e.g. 0x..f8ff will become 0xfff8..
   * Then, we count the consecutive bits
   *
   * */

  for(i = 0; i < 32; i++){
    if((mask_swap << i) & (1 << 31)){
      if(end)
        return -1;
      cnt++;
    }else{
      end = 1;
    }        
  }
  return cnt;
}

int pico_ipv4_is_unicast(uint32_t address) 
{
  const unsigned char *addr = (unsigned char *) &address;
  
  if((addr[0] & 0xe0) == 0xe0)
    return 0;
    
  return 1;
}

static int pico_ipv4_checksum(struct pico_frame *f)
{
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  if (!hdr)
    return -1;
  hdr->crc = 0;
  hdr->crc = short_be(pico_checksum(hdr, PICO_SIZE_IP4HDR));
  return 0;
}

static int pico_ipv4_forward(struct pico_frame *f);

static int pico_ipv4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  if (pico_ipv4_link_find(&hdr->dst)) {
    f->transport_hdr = ((uint8_t *)f->net_hdr) + PICO_SIZE_IP4HDR;
    f->transport_len = short_be(hdr->len) - PICO_SIZE_IP4HDR;
    pico_transport_receive(f, hdr->proto);
  } else {
    /* Packet is not local. Try to forward. */
    if (pico_ipv4_forward(f) != 0) {
      pico_frame_discard(f);
    }
  }
  return 0;
}

static int pico_ipv4_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  f->start = (uint8_t*) f->net_hdr;
  return pico_sendto_dev(f);
}


static struct pico_frame *pico_ipv4_alloc(struct pico_protocol *self, int size)
{
  struct pico_frame *f =  pico_frame_alloc(size + PICO_SIZE_IP4HDR + PICO_SIZE_ETHHDR);
  if (!f)
    return NULL;
  f->datalink_hdr = f->buffer;
  f->datalink_len = PICO_SIZE_ETHHDR;
  f->net_hdr = f->buffer + PICO_SIZE_ETHHDR;
  f->net_len = PICO_SIZE_IP4HDR;
  f->transport_hdr = f->net_hdr + PICO_SIZE_IP4HDR;
  f->transport_len = size;
  f->len =  size + PICO_SIZE_IP4HDR;
  return f;
}

static int pico_ipv4_frame_sock_push(struct pico_protocol *self, struct pico_frame *f);

/* Interface: protocol definition */
struct pico_protocol pico_proto_ipv4 = {
  .name = "ipv4",
  .proto_number = PICO_PROTO_IPV4,
  .layer = PICO_LAYER_NETWORK,
  .alloc = pico_ipv4_alloc,
  .process_in = pico_ipv4_process_in,
  .process_out = pico_ipv4_process_out,
  .push = pico_ipv4_frame_sock_push,
  .q_in = &in,
  .q_out = &out,
};

/* Interface: link to device */

struct pico_ipv4_link
{
  struct pico_device *dev;
  struct pico_ip4 address;
  struct pico_ip4 netmask;
  RB_ENTRY(pico_ipv4_link) node;
};

RB_HEAD(link_tree, pico_ipv4_link);
RB_PROTOTYPE_STATIC(link_tree, pico_ipv4_link, node, ipv4_link_compare);

static int ipv4_link_compare(struct pico_ipv4_link *a, struct pico_ipv4_link *b)
{
  if (a->address.addr < b->address.addr)
    return -1;
  if (a->address.addr > b->address.addr)
    return 1;
  return 0;
}

RB_GENERATE_STATIC(link_tree, pico_ipv4_link, node, ipv4_link_compare);



struct pico_ipv4_route
{
  struct pico_ip4 dest;
  struct pico_ip4 netmask;
  struct pico_ip4 gateway;
  struct pico_ipv4_link *link;
  uint32_t metric;
  RB_ENTRY(pico_ipv4_route) node;
};

RB_HEAD(routing_table, pico_ipv4_route);
RB_PROTOTYPE_STATIC(routing_table, pico_ipv4_route, node, ipv4_route_compare);

/* use RB_FIND for perfect match only (e.g. to avoid double route to same dst) */
static int ipv4_route_compare(struct pico_ipv4_route *a, struct pico_ipv4_route *b)
{

  /* Routes are sorted by (host side) netmask len, then by addr, then by metric. */
  if (long_be(a->netmask.addr) < long_be(b->netmask.addr))
    return -1;

  if (long_be(a->netmask.addr) > long_be(b->netmask.addr))
    return 1;

  if (a->dest.addr < b->dest.addr)
    return -1;

  if (a->dest.addr > b->dest.addr)
    return 1;

  if (a->metric < b->metric)
    return -1;

  if (a->metric > b->metric)
    return 1;

  return 0;
}

RB_GENERATE_STATIC(routing_table, pico_ipv4_route, node, ipv4_route_compare);

static struct link_tree Tree_dev_link;
static struct routing_table Routes;

static struct pico_ipv4_route *route_find(struct pico_ip4 *addr)
{
  struct pico_ipv4_route *r;
  RB_FOREACH(r, routing_table, &Routes) {
    if ((addr->addr & (r->netmask.addr)) == (r->dest.addr)) {
      return r;
    }
  }
  return NULL;
}

struct pico_ip4 pico_ipv4_route_get_gateway(struct pico_ip4 *addr)
{
  struct pico_ip4 nullip;
  struct pico_ipv4_route *route = route_find(addr);
  nullip.addr = 0U;
  if (!route)
    return nullip;
  else
    return route->gateway;
}

struct pico_ip4 *pico_ipv4_source_find(struct pico_ip4 *dst)
{
  struct pico_ipv4_route *rt = route_find(dst);
  struct pico_ip4 *myself = NULL;
  if (rt) {
    myself = &rt->link->address;
  }
  return myself;
}

int pico_ipv4_frame_push(struct pico_frame *f, struct pico_ip4 *dst, uint8_t proto)
{
  struct pico_ipv4_route *route;
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  static uint16_t ipv4_progressive_id = 0x91c0;
  
  if (!hdr) {
    dbg("IP header error\n");
    goto drop;
  }

  if (dst->addr == 0) {
    dbg("IP src addr error\n");
    goto drop;
  }

  route = route_find(dst);
  if (!route) {
    dbg("Route to %08x not found.\n", long_be(dst->addr));
    goto drop;
  }

  if (f->sock)
    f->sock->local_addr.ip4.addr = route->link->address.addr;

  hdr->vhl = 0x45;
  hdr->len = short_be(f->transport_len + PICO_SIZE_IP4HDR);
  hdr->id = short_be(ipv4_progressive_id++);
  hdr->src.addr = route->link->address.addr;
  hdr->dst.addr = dst->addr;
  hdr->frag = short_be(PICO_IPV4_DONTFRAG);
  hdr->ttl = PICO_IPV4_DEFAULT_TTL;
  hdr->proto = proto;
  pico_ipv4_checksum(f);

  f->dev = route->link->dev;
  return pico_enqueue(&out, f);
drop:
  pico_frame_discard(f);
  return -1;
}


static int pico_ipv4_frame_sock_push(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_ip4 *dst;
  if (!f->sock) {
    pico_frame_discard(f);
    return -1;
  }
  dst = &f->sock->remote_addr.ip4;
  return pico_ipv4_frame_push(f, dst, f->sock->proto->proto_number);
}

void dbg_route(void)
{
  struct pico_ipv4_route *r;
  RB_FOREACH(r, routing_table, &Routes) {
    dbg("Route to %08x/%08x, gw %08x, dev: %s, metric: %d\n", r->dest.addr, r->netmask.addr, r->gateway.addr, r->link->dev->name, r->metric);
  }
}

int pico_ipv4_route_add(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link)
{
  struct pico_ipv4_route test, *new;
  test.dest.addr = address.addr;
  test.netmask.addr = netmask.addr;
  test.metric = metric;
  if (RB_FIND(routing_table, &Routes, &test))
    return -1;
  new = pico_zalloc(sizeof(struct pico_ipv4_route));
  if (!new)
    return -1;

  new->dest.addr = address.addr;
  new->netmask.addr = netmask.addr;
  new->gateway.addr = gateway.addr;
  new->metric = metric;
  new->link = link;
  RB_INSERT(routing_table, &Routes, new);
  dbg_route();
  return 0;
}

int pico_ipv4_route_del(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link)
{
  struct pico_ipv4_route test, *found;
  test.dest.addr = address.addr;
  test.netmask.addr = netmask.addr;
  test.metric = metric;
  found = RB_FIND(routing_table, &Routes, &test);
  if (found) {
    pico_free(found);
    RB_REMOVE(routing_table, &Routes, found);
    dbg_route();
    return 0;
  }
  return -1;
}


int pico_ipv4_link_add(struct pico_device *dev, struct pico_ip4 address, struct pico_ip4 netmask)
{
  struct pico_ipv4_link test, *new;
  struct pico_ip4 network, gateway;
  char ipstr[30];
  test.address.addr = address.addr;
  test.netmask.addr = netmask.addr;
  /** XXX: Valid netmask / unicast address test **/

  if (RB_FIND(link_tree, &Tree_dev_link, &test)) {
    dbg("IPv4: Trying to assign an invalid address (in use)\n");
    return -1;
  }

  /** XXX: Check for network already in use (e.g. trying to assign 10.0.0.1/24 where 10.1.0.1/8 is in use) **/
  new = pico_zalloc(sizeof(struct pico_ipv4_link));
  if (!new) {
    dbg("IPv4: Out of memory!\n");
    return -1;
  }
  new->address.addr = address.addr;
  new->netmask.addr = netmask.addr;
  new->dev = dev;
  RB_INSERT(link_tree, &Tree_dev_link, new);

  network.addr = address.addr & netmask.addr;
  gateway.addr = 0U;
  pico_ipv4_route_add(network, netmask, gateway, 1, new);
  pico_ipv4_to_string(ipstr, new->address.addr);
  dbg("Assigned ipv4 %s to device %s\n", ipstr, new->dev->name);
  return 0;
}



int pico_ipv4_link_del(struct pico_device *dev, struct pico_ip4 address)
{
  struct pico_ipv4_link test, *found;
  test.address.addr = address.addr;
  found = RB_FIND(link_tree, &Tree_dev_link, &test);
  if (!found)
    return -1;
  RB_REMOVE(link_tree, &Tree_dev_link, found);
  return 0;
}


struct pico_ipv4_link *pico_ipv4_link_get(struct pico_ip4 *address)
{
  struct pico_ipv4_link test, *found = NULL;
  test.address.addr = address->addr;
  found = RB_FIND(link_tree, &Tree_dev_link, &test);
  if (!found)
    return NULL;
  else
    return found;
}


struct pico_device *pico_ipv4_link_find(struct pico_ip4 *address)
{
  struct pico_ipv4_link test, *found;
  test.address.addr = address->addr;
  found = RB_FIND(link_tree, &Tree_dev_link, &test);
  if (!found)
    return NULL;
  return found->dev;
}

int pico_ipv4_rebound(struct pico_frame *f)
{
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  struct pico_ip4 dst;
  if (!hdr)
    return -1;
  dst.addr = hdr->src.addr;
  return pico_ipv4_frame_push(f, &dst, hdr->proto);
}

static int pico_ipv4_forward(struct pico_frame *f)
{

  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  struct pico_ipv4_route *rt;
  if (!hdr) {
    return -1;
  }

  dbg("FORWARDING.\n");
  rt = route_find(&hdr->dst);
  if (!rt) {
    pico_notify_dest_unreachable(f);
    return -1;
  }
  dbg("ROUTE: valid..\n");
  f->dev = rt->link->dev;
  hdr->ttl-=1;
  if (hdr->ttl < 1) {
    pico_notify_ttl_expired(f);
    return -1;
  }
  hdr->crc++;
  dbg("Routing towards %s\n", f->dev->name);
  f->start = f->net_hdr;
  pico_sendto_dev(f);
  return 0;

}

