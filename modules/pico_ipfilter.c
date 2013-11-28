/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Andrei Carp
		 Simon  Maes
*********************************************************************/

#include "pico_ipv4.h"
#include "pico_config.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_ipfilter.h"
#include "pico_tcp.h"
#include "pico_udp.h"
#include "pico_tree.h"

/**************** LOCAL MACROS ****************/
#define MAX_PRIORITY	(10)
#define MIN_PRIORITY	(-10)

#define ipf_dbg(...) do{}while(0)

/**************** LOCAL DECLARATIONS ****************/
struct filter_node;
typedef int (*func_pntr)(struct filter_node *filter, struct pico_frame *f);
static int filter_compare(void *filterA, void *filterB);

/**************** FILTER TREE ****************/

struct filter_node {
  struct pico_device *fdev;
  // output address
  uint32_t out_addr;
  uint32_t out_addr_netmask;
  // input address
  uint32_t in_addr;
  uint32_t in_addr_netmask;
  // transport
  uint16_t out_port;
  uint16_t in_port;
  // filter details
  uint8_t proto;
  int8_t priority;
  uint8_t tos;
  uint8_t filter_id;
  func_pntr function_ptr;
};

PICO_TREE_DECLARE(filter_tree,&filter_compare);

#define CHECK_AND_RETURN(a,b) do{ \
									if((a) && ((a)!=(b)))\
									{ \
									  if((a)>(b)) return 1; \
									  else return -1;\
									}\
								}while(0) \


int filter_compare(void *filterA, void *filterB)
{
	struct filter_node * filter = (struct filter_node *)filterA,
			* temp = (struct filter_node *)filterB;

	// improve the search
	if(temp->filter_id && filter->filter_id == temp->filter_id)
		return 0;

	ipf_dbg("filter ->> %x %x %x %x %d %d\n",filter->in_addr,filter->in_addr_netmask,filter->out_addr,filter->out_addr_netmask,filter->in_port,filter->out_port);

	CHECK_AND_RETURN(filter->fdev,temp->fdev);
	CHECK_AND_RETURN((filter->in_addr & filter->in_addr_netmask),(temp->in_addr & filter->in_addr_netmask));
	CHECK_AND_RETURN((filter->out_addr & filter->out_addr_netmask),(temp->out_addr & filter->in_addr_netmask));
	CHECK_AND_RETURN(filter->in_port,temp->in_port);
	CHECK_AND_RETURN(filter->out_port,temp->out_port);
	CHECK_AND_RETURN(filter->priority,temp->priority);
	CHECK_AND_RETURN(filter->proto,temp->proto);

	return 0;
}

/**************** FILTER CALLBACKS ****************/

static int fp_priority(struct filter_node *filter, struct pico_frame *f) {
  //TODO do priority-stuff
  IGNORE_PARAMETER(filter);
  IGNORE_PARAMETER(f);
  return 0;
}

static int fp_reject(struct filter_node *filter, struct pico_frame *f) {
// TODO check first if sender is pico itself or not
  IGNORE_PARAMETER(filter);
  ipf_dbg("ipfilter> reject\n");
  pico_icmp4_packet_filtered(f);
  pico_frame_discard(f);
  return 1;
}

static int fp_drop(struct filter_node *filter, struct pico_frame *f) {
  IGNORE_PARAMETER(filter);
  ipf_dbg("ipfilter> drop\n");
  pico_frame_discard(f);
  return 1;
}

/**************** FILTER API's ****************/
int pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto, struct pico_ip4 *out_addr, struct pico_ip4 *out_addr_netmask, struct pico_ip4 *in_addr, struct pico_ip4 *in_addr_netmask, uint16_t out_port, uint16_t in_port, int8_t priority, uint8_t tos, enum filter_action action)
{
  static uint8_t filter_id = 0;
  struct filter_node *new_filter;

  if (proto != PICO_PROTO_IPV4 || tos != 0 )
  {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  if ( priority > MAX_PRIORITY || priority < MIN_PRIORITY) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  if (action > FILTER_COUNT) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  ipf_dbg("ipfilter> adding filter\n");

  new_filter = pico_zalloc(sizeof(struct filter_node));

  new_filter->fdev = dev;
  new_filter->proto = proto;

  new_filter->out_addr = (!out_addr)? 0U : out_addr->addr;
  new_filter->out_addr_netmask = (!out_addr_netmask) ? 0U : out_addr_netmask->addr;
  new_filter->in_addr = (!in_addr) ? 0U : in_addr->addr;
  new_filter->in_addr_netmask = (!in_addr_netmask) ? 0U : in_addr_netmask->addr;

  new_filter->out_port = out_port;
  new_filter->in_port = in_port;
  new_filter->priority = priority;
  new_filter->tos = tos;

  if(filter_id == 0)
	  filter_id = 1;

  new_filter->filter_id = filter_id;

  /*Define filterType_functionPointer here instead of in ipfilter-function, to prevent running multiple times through switch*/
  switch (action) {
    case FILTER_PRIORITY:
      new_filter->function_ptr = fp_priority;
      break;
    case FILTER_REJECT:
      new_filter->function_ptr = fp_reject;
      break;
    case FILTER_DROP:
      new_filter->function_ptr = fp_drop;
      break;
    default:
      ipf_dbg("ipfilter> unknown filter action\n");
      break;
  }
  if(pico_tree_insert(&filter_tree,new_filter))
  {
	  pico_free(new_filter);
	  ipf_dbg("ipfilter> failed adding filter to tree.\n");
	  return -1;
  }

  return new_filter->filter_id;
}

int pico_ipv4_filter_del(uint8_t filter_id)
{
	struct filter_node *node = NULL;
	struct filter_node dummy={.filter_id=filter_id};
	if((node = pico_tree_delete(&filter_tree,&dummy))== NULL)
	{
		ipf_dbg("ipfilter> failed to delete filter :%d\n",filter_id);
		return -1;
	}

	pico_free(node);
	return 0;
}

int ipfilter(struct pico_frame *f)
{
  struct filter_node temp;
  struct filter_node * filter_frame = NULL;
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  struct pico_tcp_hdr *tcp_hdr;
  struct pico_udp_hdr *udp_hdr;
  struct pico_icmp4_hdr *icmp_hdr;

  memset(&temp,0u,sizeof(struct filter_node));

  temp.fdev = f->dev;
  temp.out_addr = ipv4_hdr->dst.addr;
  temp.in_addr = ipv4_hdr->src.addr;
  if (ipv4_hdr->proto == PICO_PROTO_TCP ) {
      tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
      temp.out_port = short_be(tcp_hdr->trans.dport);
      temp.in_port = short_be(tcp_hdr->trans.sport);
  }else if (ipv4_hdr->proto == PICO_PROTO_UDP ) {
      udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      temp.out_port = short_be(udp_hdr->trans.dport);
      temp.in_port = short_be(udp_hdr->trans.sport);
  }
  else
  {
	  if(ipv4_hdr->proto == PICO_PROTO_ICMP4)
	  {
		  icmp_hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
		  if(icmp_hdr->type == PICO_ICMP_UNREACH && icmp_hdr->type == PICO_ICMP_UNREACH_FILTER_PROHIB)
			  return 0;
	  }
	  temp.out_port = temp.in_port = 0;
  }

  temp.proto = ipv4_hdr->proto;
  temp.priority = f->priority;
  temp.tos = ipv4_hdr->tos;

  filter_frame = pico_tree_findKey(&filter_tree,&temp);
  if(filter_frame)
  {
	  ipf_dbg("Filtering frame %p with filter %p\n",f,filter_frame);
	  filter_frame->function_ptr(filter_frame,f);
	  return 1;
  }

  return 0;
}

