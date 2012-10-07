#include "pico_setup.h"
#include "pico_common.h"
#include "rb.h"
#include "pico_queue.h"


#define IS_MODULE_ETH
#include "pico_module_eth.h"
#undef IS_MODULE_ETH


struct eth {
  uint8_t s_addr[6];
  uint16_t padding;
};

struct pico_eth_device {
  struct eth address;
  struct pico_device *dev;
};

/* Eth internal private structure has two members:
 * - Links tree, containing the eth devices
 * - ARP tree, containing the eth destinations
 */

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


/* Main private structure */
static struct s_proto_eth {
  struct eth_link_tree  ltree;
  struct eth_arp_tree rtree;

} proto_eth;

/* Module interface declarations */
int mod_eth_send(struct pico_frame *pkt);
int mod_eth_recv(struct pico_frame *pkt);
void mod_eth_run(void);
struct pico_module *mod_eth_init(void *arg);
void mod_eth_shutdown(struct pico_module *ip);

/* Globally accessible module definition */
struct pico_module  pico_module_eth = {
  .init = mod_eth_init,
  .shutdown = mod_eth_shutdown,
  .priv = &proto_eth,
  .name = "eth"
};


/*** MODULE IMPLEMENTATION ***/

int mod_eth_send(struct pico_frame *pkt)
{
  if (pkt->stage == PICO_ROUTING_INCOMING) {
    /* Wrong direction */
    pico_frame_discard(pkt);
    return -1;
  }

  /* TODO: look for arp destination in the tree. */
  /* TODO: If destination is not found, send a bcast arp request directly + manage refusal in network */
  /* TODO: if destination is found, fill eth header + call pico_dev_send() to enqueue packet */

  return 0;
}

int mod_eth_recv(struct pico_frame *pkt)
{

  /* TODO: compare eth destination */
  /* TODO: fill id_net */
  /* TODO: delivery() */
  return 0;
}

void mod_eth_run(void)
{
  /* This should do nothing. */
}


struct pico_module *mod_eth_init(void *arg)
{
  struct pico_module *ip = &pico_module_eth;
  ip->to_lower.recv = mod_eth_recv;
  ip->to_upper.send = mod_eth_send;
  ip->run = mod_eth_run;
  return ip;
}

void mod_eth_shutdown(struct pico_module *ip)
{
  /* TODO */
}
/*** END MODULE IMPLEMENTATION ***/

/* TODO: 
 * - device configuration interface (set eth_link)
 * - arp management
 */

/* Unit test */
#ifdef UNIT_ETH_MAIN
int main(void) {
  struct pico_module ip;
  mod_eth_init(&ip);
  return 0;
}

#endif
