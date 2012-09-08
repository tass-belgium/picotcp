#include "pico_setup.h"
#include "pico_common.h"
#include "rb.h"


#define IS_MODULE_IPV4
#include "pico_module_ipv4.h"
#undef IS_MODULE_IPV4

/* Route (internal) structure */
struct ipv4_route {
  struct ipv4 *dst;
  struct ipv4 *gateway;
  unsigned int metric;
  struct pico_device *net;
  RB_ENTRY(ipv4_route) link;
};


int routing_compare(struct ipv4_route *a, struct ipv4_route *b)
{
  /* TODO */
  return 0;
}

RB_HEAD(ipv4_route_tree, ipv4_route);
RB_PROTOTYPE(ipv4_route_tree, ipv4_route, link, routing_compare);


/* Macro to convert priv field */
#define PROTO_IPV4(x) ((struct proto_ipv4 *)((x)->priv))

struct proto_ipv4 {
  struct sock_ipv4 *socks;
  struct ipv4_route *routes;
  struct ipv4 *default_gateway;
  struct ipv4_route_tree rtree;
};

int mod_ipv4_send(struct pico_frame *pkt)
{
  if (pkt->dest) {
    pkt->dest->to_upper.send(pkt);
  }
  if (pkt->stage == PICO_ROUTING_INCOMING) {
    /* Wrong direction */
    //pico_frame_discard(pkt);
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

}

struct pico_module *mod_ipv4_init(void *arg)
{
  struct pico_module *ip = pico_zalloc(sizeof(struct pico_module));
  if (!ip)
    return NULL;
  ip->priv = pico_zalloc(sizeof(struct proto_ipv4));
  ip->to_lower.recv = mod_ipv4_recv;
  ip->to_upper.send = mod_ipv4_send;
  ip->run = mod_ipv4_run;
  return ip;
}

void mod_ipv4_shutdown(struct pico_module *ip)
{
  /* TODO */
}

struct pico_module  pico_module_ipv4 = {
  .init = mod_ipv4_init,
  .shutdown = mod_ipv4_shutdown,
  .name = "ipv4"
};



#ifdef UNIT_IPV4_MAIN
int main(void) {
  struct pico_module ip;
  mod_ipv4_init(&ip);
}

#endif
