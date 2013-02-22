/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

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
#include "pico_nat.h"
#include "pico_igmp2.h"

#ifdef PICO_SUPPORT_IPV4

#ifdef PICO_SUPPORT_MCAST
# define mcast_dbg(...) do{}while(0)
# define PICO_MCAST_ALL_HOSTS 0x010000E0 /* 224.0.0.1 */
  /* Default network interface for multicast transmission */
  static struct pico_ipv4_link *mcast_default_link = NULL;
#endif

/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};

/* Functions */
 
int pico_ipv4_to_string(char *ipbuf, const uint32_t ip)
{
  const unsigned char *addr = (unsigned char *) &ip;
  int i;

  if (!ipbuf) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

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

  if(!ipstr || !ip) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

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
      if(end) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
      }
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
    return 0; /* multicast */
    
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
#ifdef PICO_SUPPORT_MCAST
static int pico_ipv4_mcast_is_group_member(struct pico_frame *f);
#endif
static int pico_ipv4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  uint8_t option_len = 0;
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  struct pico_ip4 address0;
  address0.addr = long_be(0x00000000);
  /* NAT needs transport header information */
  if(((hdr->vhl) & 0x0F )> 5){
     option_len =  4*(((hdr->vhl) & 0x0F)-5);
  }
  f->transport_hdr = ((uint8_t *)f->net_hdr) + PICO_SIZE_IP4HDR + option_len;
  f->transport_len = short_be(hdr->len) - PICO_SIZE_IP4HDR - option_len;
#ifdef PICO_SUPPORT_MCAST
  /* Multicast address in source, discard quietly */
  if (!pico_ipv4_is_unicast(hdr->src.addr)) {
    mcast_dbg("MCAST: ERROR multicast address %08X in source address\n", hdr->src.addr);
    pico_frame_discard(f);
    return 0;
  }
#endif
  if (pico_ipv4_is_broadcast(hdr->dst.addr) && (hdr->proto == PICO_PROTO_UDP)) {
      /* Receiving UDP broadcast datagram */
      f->flags |= PICO_FRAME_FLAG_BCAST;
      pico_enqueue(pico_proto_udp.q_in, f);
  } else if (!pico_ipv4_is_unicast(hdr->dst.addr)  ) {
#ifdef PICO_SUPPORT_MCAST
    /* Receiving UDP multicast datagram TODO set f->flags? */
    if (hdr->proto == PICO_PROTO_IGMP2) {
      mcast_dbg("MCAST: received IGMP message\n");
      pico_transport_receive(f, PICO_PROTO_IGMP2);
    } else if (pico_ipv4_mcast_is_group_member(f) && (hdr->proto == PICO_PROTO_UDP)) {
      pico_enqueue(pico_proto_udp.q_in, f);
    } else {
      pico_frame_discard(f);
    }
#endif
  } else if (pico_ipv4_link_find(&hdr->dst)) {
   if (pico_ipv4_nat_isenabled_in(f) == 0) {  /* if NAT enabled (dst port registerd), do NAT */
      if(pico_ipv4_nat(f, hdr->dst) != 0) {
        return -1;
      }
      pico_ipv4_forward(f); /* Local packet became forward packet after NAT */
    } else {                              /* no NAT so enqueue to next layer */
      pico_transport_receive(f, hdr->proto);
    }
  } else if (pico_ipv4_link_find(&address0) == f->dev) {
    //address of this device is apparently 0.0.0.0; might be a DHCP packet
    pico_enqueue(pico_proto_udp.q_in, f);
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
  f->net_hdr = f->buffer + PICO_SIZE_ETHHDR;
  f->net_len = PICO_SIZE_IP4HDR + size;
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
  RB_FOREACH_REVERSE(r, routing_table, &Routes) { /* Biggest netmask is checked first... */
    if ((addr->addr & (r->netmask.addr)) == (r->dest.addr)) {
      return r;
    }
  }
  return NULL;
}

struct pico_ip4 pico_ipv4_route_get_gateway(struct pico_ip4 *addr)
{
  struct pico_ip4 nullip;
  nullip.addr = 0U;

  if(!addr) {
    pico_err = PICO_ERR_EINVAL;
    return nullip;
  }

  struct pico_ipv4_route *route = route_find(addr);
  if (!route) {
    pico_err = PICO_ERR_EHOSTUNREACH;
    return nullip;
  }
  else
    return route->gateway;
}

struct pico_ip4 *pico_ipv4_source_find(struct pico_ip4 *dst)
{
  if(!dst) {
    pico_err = PICO_ERR_EINVAL;
    return NULL;
  }

  struct pico_ipv4_route *rt = route_find(dst);
  struct pico_ip4 *myself = NULL;
  if (rt) {
    myself = &rt->link->address;
  } else
    pico_err = PICO_ERR_EHOSTUNREACH;
  return myself;
}

#ifdef PICO_SUPPORT_MCAST
struct pico_mcast_group {
  struct pico_ipv4_link *mcast_link;
  struct pico_ip4 mcast_addr;
  uint16_t reference_count;
  RB_ENTRY(pico_mcast_group) node;
};

static int mcast_cmp(struct pico_mcast_group *a, struct pico_mcast_group *b)
{
  if (a->mcast_addr.addr < b->mcast_addr.addr) {
    return -1;
  } else if (a->mcast_addr.addr > b->mcast_addr.addr) {
    return 1;
  } else {
    return 0;
  }
}

RB_HEAD(pico_mcast_list, pico_mcast_group);
RB_PROTOTYPE_STATIC(pico_mcast_list, pico_mcast_group, node, mcast_cmp);
RB_GENERATE_STATIC(pico_mcast_list, pico_mcast_group, node, mcast_cmp);

static void pico_ipv4_mcast_print_groups(struct pico_ipv4_link *mcast_link)
{
  struct pico_mcast_group *g = NULL;
  uint16_t i = 0;

  mcast_dbg("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  mcast_dbg("+              MULTICAST list interface %-16s +\n", mcast_link->dev->name);
  mcast_dbg("+--------------------------------------------------------+\n");
  mcast_dbg("+  nr  |    interface     | host group | reference count +\n");
  mcast_dbg("+--------------------------------------------------------+\n");

  RB_FOREACH(g, pico_mcast_list, mcast_link->mcast_head) {
    mcast_dbg("+ %04d | %16s |  %08X  |      %05u      +\n", i, g->mcast_link->dev->name, g->mcast_addr.addr, g->reference_count);
    i++;
  }
  mcast_dbg("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

int pico_ipv4_mcast_join_group(struct pico_ip4 *mcast_addr, struct pico_ipv4_link *mcast_link)
{
  struct pico_mcast_group *g, test = {0};
  struct pico_ipv4_link *link;

  if (pico_ipv4_is_unicast(mcast_addr->addr)) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  /* RFC 1112, section 7.1 suggests to also check on validity of mcast_link */

  if (mcast_link)
    link = mcast_link;
  else
    link = mcast_default_link;

  test.mcast_addr = *mcast_addr;
  g = RB_FIND(pico_mcast_list, link->mcast_head, &test);
  if (g) {
    g->reference_count++;
  } else {
    g = pico_zalloc(sizeof(struct pico_mcast_group));
    if (!g) {
      pico_err = PICO_ERR_ENOMEM;
      return -1;
    }
    g->mcast_link = link;
    g->mcast_addr = *mcast_addr;
    g->reference_count = 1;
    RB_INSERT(pico_mcast_list, link->mcast_head, g);

    if (mcast_addr->addr != PICO_MCAST_ALL_HOSTS) {
      dbg("MCAST: sent IGMP host membership report\n");
      pico_igmp2_join_group(mcast_addr, link);
    }
  }

  pico_ipv4_mcast_print_groups(link);
  return 0;
}

int pico_ipv4_mcast_leave_group(struct pico_ip4 *mcast_addr, struct pico_ipv4_link *mcast_link)
{

  struct pico_mcast_group *g, test = {0};
  struct pico_ipv4_link *link;

  if (pico_ipv4_is_unicast(mcast_addr->addr)) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  /* RFC 1112, section 7.1 suggests to also check on validity of mcast_link */

  if (mcast_link)
    link = mcast_link;
  else
    link = mcast_default_link;

  test.mcast_addr = *mcast_addr;
  g = RB_FIND(pico_mcast_list, link->mcast_head, &test);
  if (g) {
    g->reference_count--;
    if (g->reference_count < 1) {
      if (mcast_addr->addr != PICO_MCAST_ALL_HOSTS) {
        dbg("MCAST: sent IGMP leave group\n");
        pico_igmp2_leave_group(mcast_addr, link);
      }
      RB_REMOVE(pico_mcast_list, link->mcast_head, g);
    }
  } else {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  pico_ipv4_mcast_print_groups(link);
  return 0;
}

static int pico_ipv4_mcast_is_group_member(struct pico_frame *f)
{
  struct pico_ipv4_link *link;
  struct pico_mcast_group *g, test = {0};
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

  test.mcast_addr = hdr->dst; 
  RB_FOREACH(link, link_tree, &Tree_dev_link) {
    g = RB_FIND(pico_mcast_list, link->mcast_head, &test);
    if (g) {
      if (f->dev == link->dev) {
        mcast_dbg("MCAST: IP %08X is group member of current link %s\n", hdr->dst.addr, f->dev->name);
        return 1;
      } else {
        mcast_dbg("MCAST: IP %08X is group member of different link %s\n", hdr->dst.addr, link->dev->name);
      }
    }
  }
  mcast_dbg("MCAST: IP %08X is not a group member of current link %s\n", hdr->dst.addr, f->dev->name);
  return 0;
}
#endif /* PICO_SUPPORT_MCAST */

int pico_ipv4_frame_push(struct pico_frame *f, struct pico_ip4 *dst, uint8_t proto)
{
  if(!f || !dst) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  struct pico_ipv4_route *route;
  struct pico_ipv4_link *link;
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  uint8_t ttl = PICO_IPV4_DEFAULT_TTL;
  static uint16_t ipv4_progressive_id = 0x91c0;
  
  if (!hdr) {
    dbg("IP header error\n");
    pico_err = PICO_ERR_EINVAL;
    goto drop;
  }

  if (dst->addr == 0) {
    dbg("IP src addr error\n");
    pico_err = PICO_ERR_EINVAL;
    goto drop;
  }

  route = route_find(dst);
  if (!route) {
    pico_err = PICO_ERR_EHOSTUNREACH;
    if (pico_ipv4_is_unicast(dst->addr)) {
      dbg("Route to %08x not found.\n", long_be(dst->addr));
      goto drop;
    }
#ifdef PICO_SUPPORT_MCAST
    link = mcast_default_link;
    if(pico_udp_get_mc_ttl(f->sock, &ttl) < 0)
      ttl = PICO_IP_DEFAULT_MULTICAST_TTL;
#else
    goto drop;
#endif
  } else {
    link = route->link;
  }

  if (f->sock)
    f->sock->local_addr.ip4.addr = link->address.addr;

  hdr->vhl = 0x45;
  hdr->len = short_be(f->transport_len + PICO_SIZE_IP4HDR);
  hdr->id = short_be(ipv4_progressive_id++);
  hdr->src.addr = link->address.addr;
  hdr->dst.addr = dst->addr;
  hdr->frag = short_be(PICO_IPV4_DONTFRAG);
  hdr->ttl = ttl;
  hdr->proto = proto;
  pico_ipv4_checksum(f);

  f->dev = link->dev;
#ifdef PICO_SUPPORT_MCAST
  if (!pico_ipv4_is_unicast(hdr->dst.addr)) {
  /* Sending UDP multicast datagram, am I member? If so, loopback copy */
    if (pico_ipv4_mcast_is_group_member(f)) {
      mcast_dbg("MCAST: sender is member of group, loopback copy\n");
      struct pico_frame *cpy = pico_frame_copy(f);
      pico_enqueue(&in, cpy);
    }
  }
#endif

  if(pico_ipv4_link_get(&hdr->dst)){
    //it's our own IP
    return pico_enqueue(&in, f);
  }else{
    /* TODO: Check if there are members subscribed here */
    return pico_enqueue(&out, f);
  }

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


#ifdef DEBUG_ROUTE
static void dbg_route(void)
{
  struct pico_ipv4_route *r;
  RB_FOREACH(r, routing_table, &Routes) {
    dbg("Route to %08x/%08x, gw %08x, dev: %s, metric: %d\n", r->dest.addr, r->netmask.addr, r->gateway.addr, r->link->dev->name, r->metric);
  }
}
#else
#define dbg_route() do{ }while(0)
#endif

int pico_ipv4_route_add(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link)
{
  struct pico_ipv4_route test, *new;
  test.dest.addr = address.addr;
  test.netmask.addr = netmask.addr;
  test.metric = metric;
  if (RB_FIND(routing_table, &Routes, &test)) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  
  new = pico_zalloc(sizeof(struct pico_ipv4_route));
  if (!new) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  new->dest.addr = address.addr;
  new->netmask.addr = netmask.addr;
  new->gateway.addr = gateway.addr;
  new->metric = metric;
  if (gateway.addr == 0) {
    /* No gateway provided, use the link */
    new->link = link;
  } else {
    struct pico_ipv4_route *r = route_find(&gateway);
    if (!r ) { /* Specified Gateway is unreachable */
      pico_err = PICO_ERR_EHOSTUNREACH;
      pico_free(new);
      return -1;
    }
    if (r->gateway.addr) { /* Specified Gateway is not a neighbor */
      pico_err = PICO_ERR_ENETUNREACH;
      pico_free(new);
      return -1;
    }
    new->link = r->link;
  }
  if (!new->link) {
      pico_err = PICO_ERR_EINVAL;
      pico_free(new);
      return -1;
  }
  RB_INSERT(routing_table, &Routes, new);
  dbg_route();
  return 0;
}

int pico_ipv4_route_del(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link)
{
  if (!link) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

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
  pico_err = PICO_ERR_EINVAL;
  return -1;
}


int pico_ipv4_link_add(struct pico_device *dev, struct pico_ip4 address, struct pico_ip4 netmask)
{
  if(!dev) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  struct pico_ipv4_link test, *new;
  struct pico_ip4 network, gateway;
  char ipstr[30];
  test.address.addr = address.addr;
  test.netmask.addr = netmask.addr;
  /** XXX: Valid netmask / unicast address test **/

  if (RB_FIND(link_tree, &Tree_dev_link, &test)) {
    dbg("IPv4: Trying to assign an invalid address (in use)\n");
    pico_err = PICO_ERR_EADDRINUSE;
    return -1;
  }

  /** XXX: Check for network already in use (e.g. trying to assign 10.0.0.1/24 where 10.1.0.1/8 is in use) **/
  new = pico_zalloc(sizeof(struct pico_ipv4_link));
  if (!new) {
    dbg("IPv4: Out of memory!\n");
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  new->address.addr = address.addr;
  new->netmask.addr = netmask.addr;
  new->dev = dev;
#ifdef PICO_SUPPORT_MCAST
  new->mcast_head = pico_zalloc(sizeof(struct pico_mcast_list));
  if (!new->mcast_head) {
    pico_free(new);
    dbg("IPv4: Out of memory!\n");
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
#endif

  RB_INSERT(link_tree, &Tree_dev_link, new);
#ifdef PICO_SUPPORT_MCAST
  if (!mcast_default_link)
    mcast_default_link = new;

  struct pico_ip4 mcast_all_hosts;
  mcast_all_hosts.addr = PICO_MCAST_ALL_HOSTS;
  pico_ipv4_mcast_join_group(&mcast_all_hosts, new);
#endif

  network.addr = address.addr & netmask.addr;
  gateway.addr = 0U;
  pico_ipv4_route_add(network, netmask, gateway, 1, new);
  pico_ipv4_to_string(ipstr, new->address.addr);
  dbg("Assigned ipv4 %s to device %s\n", ipstr, new->dev->name);
  return 0;
}


int pico_ipv4_link_del(struct pico_device *dev, struct pico_ip4 address)
{
  if(!dev) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  struct pico_ipv4_link test, *found;
  struct pico_ip4 network;

  test.address.addr = address.addr;
  found = RB_FIND(link_tree, &Tree_dev_link, &test);
  if (!found) {
    pico_err = PICO_ERR_ENXIO;
    return -1;
  }

  network.addr = found->address.addr & found->netmask.addr;
  pico_ipv4_route_del(network, found->netmask,pico_ipv4_route_get_gateway(&found->address), 1, found);
#ifdef PICO_SUPPORT_MCAST
  struct pico_mcast_group *g = NULL, *tmp = NULL;
  RB_FOREACH_SAFE(g, pico_mcast_list, found->mcast_head, tmp) {  
    RB_REMOVE(pico_mcast_list, found->mcast_head, g);
    pico_free(g);
  }
#endif
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
  if(!address) {
    pico_err = PICO_ERR_EINVAL;
    return NULL;
  }

  struct pico_ipv4_link test, *found;
  test.address.addr = address->addr;
  found = RB_FIND(link_tree, &Tree_dev_link, &test);
  if (!found) {
    pico_err = PICO_ERR_ENXIO;
    return NULL;
  }
  return found->dev;
}

int pico_ipv4_rebound(struct pico_frame *f)
{
  if(!f) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  struct pico_ip4 dst;
  if (!hdr) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
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

  //dbg("IP> FORWARDING.\n");
  rt = route_find(&hdr->dst);
  if (!rt) {
    pico_notify_dest_unreachable(f);
    return -1;
  }
  //dbg("ROUTE: valid..\n");
  f->dev = rt->link->dev;
  hdr->ttl-=1;
  if (hdr->ttl < 1) {
    pico_notify_ttl_expired(f);
    return -1;
  }
  hdr->crc++;

  /* check if NAT enbled on link and do NAT if so */
  if (pico_ipv4_nat_isenabled_out(rt->link) == 0)
    pico_ipv4_nat(f, rt->link->address);

  //dbg("Routing towards %s\n", f->dev->name);
  f->start = f->net_hdr;
  if(f->dev->eth != NULL)
    f->len -= PICO_SIZE_ETHHDR;
  pico_sendto_dev(f);
  return 0;

}

int pico_ipv4_is_broadcast(uint32_t addr)
{
  struct pico_ipv4_link *link;
  if (addr == PICO_IP4_ANY)
    return 1;
  if (addr == PICO_IP4_BCAST)
    return 1;
  RB_FOREACH(link, link_tree, &Tree_dev_link) {
    if ((link->address.addr | (~link->netmask.addr)) == addr)
      return 1;
  }
  return 0;
}


void pico_ipv4_unreachable(struct pico_frame *f, int err)
{
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  f->transport_hdr = ((uint8_t *)f->net_hdr) + PICO_SIZE_IP4HDR;
  pico_transport_error(f, hdr->proto, err);
}

#endif
