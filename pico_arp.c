#include "pico_config.h"
#include "pico_arp.h"
#include "rb.h"

/*****************/
/**  ARP TREE **/
/*****************/

/* Routing destination */

RB_HEAD(arp_tree, pico_arp);
RB_PROTOTYPE_STATIC(arp_tree, pico_arp, node, arp_compare);


static int arp_compare(struct pico_arp *a, struct pico_arp *b)
{

  if (a->ipv4.addr < b->ipv4.addr)
    return -1;
  else if (a->ipv4.addr > b->ipv4.addr)
    return 1;
  return 0;
}

RB_GENERATE_STATIC(arp_tree, pico_arp, node, arp_compare);

/*********************/
/**  END ARP TREE **/
/*********************/


struct pico_arp *pico_arp_get(struct pico_frame *f)
{
  return NULL;
}

