#include "pico_setup.h"
#include "pico_common.h"
#include "rb.h"
#include "pico_queue.h"


#define IS_MODULE_IPV4
#include "pico_module_ipv4.h"
#undef IS_MODULE_IPV4


/* IPv4 internal private structure has two members:
 * - Route tree, containing all the static routes
 * - Links tree, containing the association with L2 devices
 */

/*****************/
/**  ROUTE TREE **/
/*****************/

/* Routing destination */
struct ipv4_route {
  struct ipv4 dst;
  struct ipv4 gateway;
  unsigned int metric;
  struct pico_device *net;
  struct pico_queue ingres;
  struct pico_queue egres;
  RB_ENTRY(ipv4_route) node;
};


/* Configured device */
struct ipv4_link {
  struct pico_device *dev;
  struct ipv4 address;
  struct ipv4 netmask;
  RB_ENTRY(ipv4_link) node;
};

RB_HEAD(ipv4_route_tree, ipv4_route);
RB_HEAD(ipv4_link_tree, ipv4_link);
RB_PROTOTYPE_STATIC(ipv4_route_tree, ipv4_route, node, routing_compare);
RB_PROTOTYPE_STATIC(ipv4_link_tree, ipv4_link, node, link_compare);

#define IPV4_MASKED_NET(x) (x->dst.s_addr | x->dst.s_netmask)

/* RB_FIND can only be used for perfectly matching destinations. */
/* For other uses, a foreach loop must be used. See the ipv4_route function */
int routing_compare(struct ipv4_route *a, struct ipv4_route *b)
{
  if (a->dst.s_netmask < b->dst.s_netmask)
    return -1;
  else if (a->dst.s_netmask > b->dst.s_netmask)
    return 1;

  if (a->dst.s_addr < b->dst.s_addr)
    return -1;
  else if (a->dst.s_addr > b->dst.s_addr)
    return 1;
  return 0;
}

int link_compare(struct ipv4_link *a, struct ipv4_link *b)
{
  if (a->address.s_addr < b->address.s_addr) {
    return -1;
  } else if (a->address.s_addr > b->address.s_addr) {
    return 1;
  }
  return 0;
}

RB_GENERATE_STATIC(ipv4_route_tree, ipv4_route, node, routing_compare);
RB_GENERATE_STATIC(ipv4_link_tree, ipv4_link, node, link_compare);

/*********************/
/**  END ROUTE TREE **/
/*********************/


/* Main private structure */
static struct s_proto_ipv4 {
  struct ipv4_link_tree  ltree;
  struct ipv4_route_tree rtree;
} proto_ipv4;

/* Module interface declarations */
int mod_ipv4_send(struct pico_frame *pkt);
int mod_ipv4_recv(struct pico_frame *pkt);
void mod_ipv4_run(void);
struct pico_frame* mod_ipv4_alloc(int payload_size);
struct pico_module *mod_ipv4_init(void *arg);
void mod_ipv4_shutdown(struct pico_module *ip);

/* Globally accessible module definition */
struct pico_module  pico_module_ipv4 = {
  .init = mod_ipv4_init,
  .shutdown = mod_ipv4_shutdown,
  .priv = &proto_ipv4,
  .name = "ipv4"
};


/*** MODULE IMPLEMENTATION ***/

int mod_ipv4_send(struct pico_frame *pkt)
{
  if (pkt->dest) {
    pkt->dest->to_upper.send(pkt);
  }
  if (pkt->stage == PICO_ROUTING_INCOMING) {
    /* Wrong direction */
    pico_frame_discard(pkt);
    return -1;
  }
  return 0;
}

int mod_ipv4_recv(struct pico_frame *pkt)
{
  return 0;
}

void mod_ipv4_run(void)
{

}

struct pico_frame* mod_ipv4_alloc(int payload_size)
{
  return pico_frame_alloc(&pico_module_ipv4, payload_size + 50);
}

struct pico_module *mod_ipv4_init(void *arg)
{
  struct pico_module *ip = &pico_module_ipv4;
  ip->to_lower.recv = mod_ipv4_recv;
  ip->to_upper.send = mod_ipv4_send;
  ip->run = mod_ipv4_run;
  return ip;
}

void mod_ipv4_shutdown(struct pico_module *ip)
{
  /* TODO */
}
/*** END MODULE IMPLEMENTATION ***/

/** Exported additional functionalities **/
int ipv4_route(struct pico_frame *pkt)
{
  struct ipv4_route *a;
  RB_FOREACH(a, ipv4_route_tree, &proto_ipv4.rtree) {
    if (IPV4_MASKED_NET(a) == 0) {
      return -1;
    } else if (IPV4_MASKED_NET(a) > IPV4_MASKED_NET(a)) {
      return 1;
    }
  }
  return 0;
}

/* TODO: 
 * - device configuration interface
 * - route add/remove
 */


/* Unit test */
#ifdef UNIT_IPV4_MAIN
int main(void) {
  struct pico_module ip;
  mod_ipv4_init(&ip);
  return 0;
}

#endif
