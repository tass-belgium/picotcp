#include "pico_config.h"
#include "pico_arp.h"
#include "rb.h"

/*****************/
/**  ARP TREE **/
/*****************/

/* Routing destination */

RB_HEAD(arp4_tree, pico_arp4);
RB_PROTOTYPE_STATIC(arp4_tree, pico_arp4, node, arp4_compare);

RB_HEAD(arp6_tree, pico_arp6);
RB_PROTOTYPE_STATIC(arp6_tree, pico_arp6, node, arp6_compare);

static int arp4_compare(struct pico_arp4 *a, struct pico_arp4 *b)
{

  if (a->ipv4.addr < b->ipv4.addr)
    return -1;
  else if (a->ipv4.addr > b->ipv4.addr)
    return 1;
  return 0;
}

static int arp6_compare(struct pico_arp6 *a, struct pico_arp6 *b)
{
  return memcmp(a->ipv6.addr, b->ipv6.addr, PICO_SIZE_IP6);
}

RB_GENERATE_STATIC(arp4_tree, pico_arp4, node, arp4_compare);
RB_GENERATE_STATIC(arp6_tree, pico_arp6, node, arp6_compare);

/*********************/
/**  END ROUTE TREE **/
/*********************/


