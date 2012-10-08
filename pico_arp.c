
/*****************/
/**  ARP TREE **/
/*****************/

/* Routing destination */

RB_HEAD(eth_arp_tree, pico_arp_entry);
RB_HEAD(eth_link_tree, pico_eth_link);
RB_PROTOTYPE_STATIC(eth_arp_tree, pico_arp_entry, node, arp_compare);
RB_PROTOTYPE_STATIC(eth_link_tree, pico_eth_link, node, link_compare);

#define ETH_MASKED_NET(x) (x->dst.s_addr | x->dst.s_netmask)

static int arp_compare(struct pico_arp_entry *a, struct pico_arp_entry *b)
{

#ifdef PICO_CONFIG_IPV4
  if (a->addr_ipv4.s_addr < b->addr_ipv4.s_addr)
    return -1;
  else if (a->addr_ipv4.s_addr > b->addr_ipv4.s_addr)
    return 1;
  return 0;
#else
  return 0;
#endif
}

static int link_compare(struct pico_eth_link *a, struct pico_eth_link *b)
{
  if (a->address.s_addr < b->address.s_addr) {
    return -1;
  } else if (a->address.s_addr > b->address.s_addr) {
    return 1;
  }
  return 0;
}

RB_GENERATE_STATIC(eth_arp_tree, pico_arp_entry, node, routing_compare);
RB_GENERATE_STATIC(eth_link_tree, pico_eth_link, node, link_compare);

/*********************/
/**  END ROUTE TREE **/
/*********************/


