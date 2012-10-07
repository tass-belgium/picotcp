#include "pico_headers.h"
#include "pico_object.h"
#include "pico_hwdev.h"
#include "pico_buff.h"
#include "pico_ip.h"
#include "pico_arp.h"

void pico_hwdev_recv(struct pico_hwdev *orig, void *data, uint32_t len)
{
  struct pico_buff *pb = pico_alloc(sizeof(struct pico_buff));
  if (!pb)
    return NULL;
  memset(pb, 0, sizeof(struct pico_buff));
  pb->rawdata = (uint8_t *)data;
  pb->size = len;
  pb->start = pb->rawdata + orig->hw_hdr_size;
  pb->hw_priv = orig;
  pb->eth = (struct pico_ethhdr *) pb->start;

  /* Filter out packets that are not for us */
  if (memcmp(pb->eth.dst, orig->HWADDR, 6) &&
    memcmp(pb->eth.dst, ETH_BCAST, 6) )
    goto discard;

  if (pb->eth.proto == to_be16(PTYPE_IP)) {
    pb->ip = (struct pico_iphdr *) (pb->start + sizeof(struct pico_ethhdr));
    pico_ip_recv(pb);
    return;
  } else if (pb->eth.proto == to_be16(PTYPE_ARP)) {
    pb->arp = (struct pico_arphdr *) (pb->start + sizeof(struct pico_ethhdr));
    pico_arp_recv(pb);
    return;
  } else {
    /**  buffer type not supported. **/
    /** place your IPV6 code here :) **/
  }

discard:
  /* Silently discarded. */
  pico_memfree(pb->rawdata);
  pico_memfree(pb);
}


