#include "pico_ipv4.h"
#include "pico_config.h"
#include "pico_icmp4.h"


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


/* Functions */

static int pico_ipv4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  dbg("Called %s\n", __FUNCTION__);
  switch (hdr->proto) {

#ifdef PICO_SUPPORT_ICMP4
    case PICO_PROTO_ICMP4:
      pico_enqueue(pico_proto_icmp4.q_in, f);
      break;
#endif

    default:
      pico_frame_discard(f);
  }
  return 0;
}

static int pico_ipv4_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  dbg("Called %s\n", __FUNCTION__);
  return 0;
}

static struct pico_frame *pico_ipv4_alloc(struct pico_protocol *self, int size)
{
  return pico_frame_alloc(size + PICO_SIZE_IP4HDR);
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_ipv4 = {
  .name = "ipv4",
  .layer = PICO_LAYER_NETWORK,
  .alloc = pico_ipv4_alloc,
  .process_in = pico_ipv4_process_in,
  .process_out = pico_ipv4_process_out,
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

static struct link_tree Tree_dev_link;

int pico_ipv4_link_add(struct pico_device *dev, struct pico_ip4 address, struct pico_ip4 netmask)
{
  struct pico_ipv4_link test, *new;
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

struct pico_device *pico_ipv4_link_find(struct pico_ip4 *address)
{
  struct pico_ipv4_link test, *found;
  test.address.addr = address->addr;
  found = RB_FIND(link_tree, &Tree_dev_link, &test);
  if (!found)
    return NULL;
  return found->dev;
}

