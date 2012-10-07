/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#include "pico_headers.h"
#include "pico_buff.h"
#include "pico_utils.h"

#define MAX_PACKET_SIZE 2000
#define iphead(x) ((struct pico_iph

char *pico_ntoa(uint32_t addr)
{
  struct in_addr a;
  char *res;
  a.s_addr = addr;
  res = inet_ntoa(a);
  return res;
}

/*
 * Forward the ip packet to next hop. TTL is decreased,
 * checksum is set again for coherence, and TTL overdue
 * packets are not forwarded.
 */
static int pico_ip_decrease_ttl(struct pico_buff *pb){
  struct pico_iphdr *iph=iphead(pb);
  iph->ttl--;
  iph->crc++;
  if(iph->ttl < 1)
    return -1; 
  else
    return 0;
}

/**
 * Calculate ip-header checksum. it's a wrapper for net_checksum();
 */
uint16_t pico_ip_checksum(struct pico_iphdr *iph)
{
  iph->check = 0U;
  return net_checksum((uint8_t*)iph,sizeof(struct pico_iphdr));
}

#define DEFAULT_TTL 64

static inline void packet_is_local(struct pico_buff *pb)
{
  struct pico_iphdr *iph = iphead(pb);
  return (pico_ipaddress_is_broadcast(iph->daddr) || pico_ipaddress_is_local(iph->daddr));
}

void pico_ip_input(struct pico_buff *pb)
{
  struct pico_iphdr *iph = iphead(pb);
  switch(iph->proto) {
    case PROTO_ICMP:
      pico_icmp_recv(pb);
      return;
    case PROTO_UDP:
      pico_udp_recv(pb);
      return;
  }

  if (pico_ipaddress_is_local(iph->daddr)) {
#ifdef CONFIG_TCP
    if (iph->proto == PROTO_TCP) {
      pico_tcp_recv(pb);
      return;
    }
#endif
    pico_icmp_service_unreachable((uint32_t)iph->saddr, footprint(vb));
  }

  pico_memfree(pb->rawdata);
  pico_memfree(pb);
}

int pico_packet_send(struct pico_buff *pb, uint32_t dst_ip, uint8_t protocol)
{
  struct pico_iphdr *iph=iphead(pb);
  struct pico_ethernet_header *eth = ethhead(pb);
  struct pico_route *ro;
  struct pico_arp_entry *ae;

  uint32_t destination = dst_ip;

  eth->buftype = from_be16(PTYPE_IP);

  memset(iph,0x45,1);
  iph->tos = 0;
  iph->frag_off=from_be16(0x4000); // Don't fragment.
  iph->tot_len = from_be16(pb->len - sizeof(struct pico_ethernet_header));
  iph->id = 0;
  iph->protocol = protocol;
  iph->ttl = DEFAULT_TTL;
  iph->daddr = dst_ip;
  ro = pico_get_route(dst_ip);
  if (!ro)
    return -1;

  if (ro->gateway != 0) {
    destination = ro->gateway;
  }
  iph->saddr = pico_get_right_localip(ro->iface, destination);
  iph->check = from_be16(pico_ip_checksum(iph));
  ae = pico_get_arp_entry(ro->iface, destination);
  if (!ae) {
    pico_arp_query(ro->iface, destination);
    return -1;
  }
  return pico_sendto(ro->iface, pb, ae->macaddr);
}

int pico_packet_broadcast(struct pico_buff *pb, struct pico_iface *iface, uint32_t dst_ip, uint8_t protocol)
{
  struct pico_iphdr *iph=iphead(pb);
  struct pico_ethernet_header *eth = ethhead(pb);
  uint8_t bcast_macaddr[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

  eth->buftype = from_be16(PTYPE_IP);

  memset(iph,0x45,1);
  iph->tos = 0;
  iph->frag_off=from_be16(0x4000); // Don't fragment.
  iph->tot_len = from_be16(pb->len - sizeof(struct pico_ethernet_header));
  iph->id = 0;
  iph->protocol = protocol;
  iph->ttl = DEFAULT_TTL;
  iph->daddr = dst_ip;
  if (dst_ip != (htonl((uint32_t) -1)))
    iph->saddr = pico_get_right_localip(iface, iph->daddr);
  else
    iph->saddr = 0;
  iph->check = from_be16(pico_ip_checksum(iph));
  return pico_sendto(iface, pb, bcast_macaddr);
}

void pico_ip_recv(struct pico_buff *pb)
{
  struct pico_iphdr *hdr = iphead(pb);
  uint32_t sender = hdr->saddr;
  uint8_t foot[sizeof(hdr) + 8];

#ifdef CONFIG_FILTER
  if (pico_filter(pb)) {
    goto discard;
  }
#endif
  pb->priority = PRIO_BESTEFFORT;

  if (packet_is_local(packet)) {
    ip_input(packet);
    return;
  }
  memcpy(foot, footprint(packet), sizeof(struct pico_iphdr) + 8);
  if (pico_ip_decrease_ttl(packet)) {
    pico_icmp_ttl_expired(sender, foot);
    return;
  }
  if (pico_packet_send(packet, hdr->daddr, hdr->protocol) < 0) {
    pico_icmp_host_unreachable(sender, foot);
    return;
  } else {
    /* success, packet is routed. */
    return;
  }
}

