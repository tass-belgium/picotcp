/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Simon Maes
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


//#define ipf_dbg dbg
#define ipf_dbg(...) do{}while(0)

struct filter_node;
typedef int (*func_pntr)(struct filter_node *filter, struct pico_frame *f);

struct filter_node {
  struct pico_device *fdev;
  struct filter_node *next_filter;
  uint32_t out_addr;
  uint32_t out_addr_netmask;
  uint32_t in_addr;
  uint32_t in_addr_netmask;
  uint16_t out_port;
  uint16_t in_port;
  uint8_t proto;
  int8_t priority;
  uint8_t tos;
  uint8_t filter_id;
  func_pntr function_ptr;
};

static struct filter_node *head = NULL;
static struct filter_node *tail = NULL;

/*======================== FUNCTION PNTRS ==========================*/

static int fp_accept(struct filter_node *filter, struct pico_frame *f) {return 0;}

static int fp_priority(struct filter_node *filter, struct pico_frame *f) {

  //TODO do priority-stuff
  return 0;
}

static int fp_reject(struct filter_node *filter, struct pico_frame *f) {
// TODO check first if sender is pico itself or not
  ipf_dbg("ipfilter> #reject\n");
  pico_icmp4_packet_filtered(f);
  pico_frame_discard(f);
  return 1;
}

static int fp_drop(struct filter_node *filter, struct pico_frame *f) {

  ipf_dbg("ipfilter> # drop\n");
  pico_frame_discard(f);
  return 1;
}

/*============================ API CALLS ============================*/
int pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto, struct pico_ip4 *out_addr, struct pico_ip4 *out_addr_netmask, struct pico_ip4 *in_addr, struct pico_ip4 *in_addr_netmask, uint16_t out_port, uint16_t in_port, int8_t priority, uint8_t tos, enum filter_action action)
{
  static uint8_t filter_id = 0;
  struct filter_node *new_filter;

  if ( !(dev != NULL || proto != 0 || (out_addr != NULL && out_addr->addr != 0U) || (out_addr_netmask != NULL && out_addr_netmask->addr != 0U)|| (in_addr != NULL && in_addr->addr != 0U) || (in_addr_netmask != NULL && in_addr_netmask->addr != 0U)|| out_port != 0 || in_port !=0 || tos != 0 )) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  if ( priority > 10 || priority < -10) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  if (action > 3 || action < 0) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  ipf_dbg("ipfilter> # adding filter\n");

  new_filter = pico_zalloc(sizeof(struct filter_node));
  if (!head) {
    head = tail = new_filter;
  } else {
    tail->next_filter = new_filter;
    tail = new_filter;
  }

  new_filter->fdev = dev;
  new_filter->proto = proto;
  if (out_addr != NULL)
    new_filter->out_addr = out_addr->addr;
  else
    new_filter->out_addr = 0U;

  if (out_addr_netmask != NULL)
    new_filter->out_addr_netmask = out_addr_netmask->addr;
  else
    new_filter->out_addr_netmask = 0U;

  if (in_addr != NULL)
    new_filter->in_addr = in_addr->addr;
  else
    new_filter->in_addr = 0U;
 
  if (in_addr_netmask != NULL)
    new_filter->in_addr_netmask = in_addr_netmask->addr;
  else
    new_filter->in_addr_netmask = 0U;

  new_filter->out_port = out_port;
  new_filter->in_port = in_port;
  new_filter->priority = priority;
  new_filter->tos = tos;
  new_filter->filter_id = filter_id++;

  /*Define filterType_functionPointer here instead of in ipfilter-function, to prevent running multiple times through switch*/
  switch (action) {
    case FILTER_ACCEPT:
      new_filter->function_ptr = fp_accept;
      break;
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
      ipf_dbg("ipfilter> #unknown filter action\n");
      break;
  }
  return new_filter->filter_id;
}

int pico_ipv4_filter_del(uint8_t filter_id)
{
  struct filter_node *work;
  struct filter_node *prev;

  if (!tail || !head) {
    pico_err = PICO_ERR_EPERM;
    return -1;
  }

  work = head;
  if (work->filter_id == filter_id) {
      /*delete filter_node from linked list*/
      head = work->next_filter;
      pico_free(work);
      return 0;
  }
  prev = work;
  work = work->next_filter;

  while (1) {
    if (work->filter_id == filter_id) {
        if (work != tail) {
        /*delete filter_node from linked list*/
        prev->next_filter = work->next_filter;
        pico_free(work);
        return 0;
        } else {
          prev->next_filter = NULL;
          pico_free(work);
          return 0;
        }
    } else {
      /*check next filter_node*/
      prev = work;
      work = work->next_filter;
      if (work == tail) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
      }
    }
  }
}

/*================================== CORE FILTER FUNCTIONS ==================================*/
int match_filter(struct filter_node *filter, struct pico_frame *f)
{
  struct filter_node temp;
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  struct pico_tcp_hdr *tcp_hdr;
  struct pico_udp_hdr *udp_hdr;

  if (!filter|| !f) {
    ipf_dbg("ipfilter> ## nullpointer in match filter \n");
    return -1;
  }

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
  } else {
    temp.out_port = temp.in_port = 0;
  }
  temp.proto = ipv4_hdr->proto;
  temp.priority = f->priority;
  temp.tos = ipv4_hdr->tos;



  if ( ((filter->fdev == NULL || filter->fdev == temp.fdev) && \
        (filter->in_addr == 0 || ((filter->in_addr_netmask == 0) ? (filter->in_addr == temp.in_addr) : 1)) &&\
        (filter->in_port == 0 || filter->in_port == temp.in_port) &&\
        (filter->out_addr == 0 || ((filter->out_addr_netmask == 0) ? (filter->out_addr == temp.out_addr) : 1)) && \
        (filter->out_port == 0 || filter->out_port == temp.out_port)  && \
        (filter->proto == 0 || filter->proto == temp.proto ) &&\
        (filter->priority == 0 || filter->priority == temp.priority ) &&\
        (filter->tos == 0 || filter->tos == temp.tos ) &&\
        (filter->out_addr_netmask == 0 || ((filter->out_addr & filter->out_addr_netmask) == (temp.out_addr & filter->out_addr_netmask)) ) &&\
        (filter->in_addr_netmask == 0 || ((filter->in_addr & filter->in_addr_netmask) == (temp.in_addr & filter->in_addr_netmask)) )\
       ) ) 
    return 0;

  //No filter match!
  ipf_dbg("ipfilter> #no match\n");
  return 1;
}

int ipfilter(struct pico_frame *f)
{
  struct filter_node *work = head;

  /*return 1 if pico_frame is discarded as result of the filtering, 0 for an incomming packet, -1 for faults*/
  if (!tail || !head)  {
    return 0;
  }

  if ( match_filter(work, f) == 0 ) { 
    ipf_dbg("ipfilter> # ipfilter match\n");
    /*filter match, execute filter!*/
    return work->function_ptr(work, f);
  } 
  while (tail != work) {
    ipf_dbg("ipfilter> next filter..\n");
    work = work->next_filter;
    if ( match_filter(work, f) == 0 ) {
      ipf_dbg("ipfilter> # ipfilter match\n");
      /*filter match, execute filter!*/
      return work->function_ptr(work, f);
    }
  }
  return 0;
}

