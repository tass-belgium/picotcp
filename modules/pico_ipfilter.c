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

  printf("# prio\n");
  f->priority = filter->priority;
  return 0;
}

static int fp_reject(struct filter_node *filter, struct pico_frame *f) {
// TODO check first if sender is pico itself or not
  printf("#reject\n");
  pico_icmp4_packet_filtered(f);
  pico_frame_discard(f);
  return 1;
}

static int fp_drop(struct filter_node *filter, struct pico_frame *f) {

  printf("# drop\n");
  pico_frame_discard(f);
  printf("# exit drop\n");
  return 1;
}

/*============================ API CALLS ============================*/
uint8_t pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto, uint32_t out_addr, uint32_t out_addr_netmask, uint32_t in_addr, uint32_t in_addr_netmask, uint16_t out_port, uint16_t in_port, int8_t priority, uint8_t tos, enum filter_action action) {
// s -> out
// d -> in
  printf("# adding filter\n");
  static uint8_t filter_id = 0;

  struct filter_node *new_filter;
  new_filter = pico_zalloc(sizeof(struct filter_node));
  if (!head) {
    head = tail = new_filter;
    printf(">>> 0X%08x\n", head);
  } else {
    tail->next_filter = new_filter;
    tail = new_filter;
  }

  new_filter->fdev = dev;
  new_filter->proto = proto;
  new_filter->out_addr = out_addr;
  new_filter->out_addr_netmask = out_addr_netmask;
  new_filter->in_addr = in_addr;
  new_filter->in_addr_netmask = in_addr_netmask;
  new_filter->out_port = out_port;
  new_filter->in_port = in_port;
  new_filter->priority = priority;
  new_filter->tos = tos;
  new_filter->filter_id = filter_id++;

  /*Define filterType_functionPointer here instead of in ipfilter-function, to prevent running multiple times through switch*/
  switch (action) {
    case filter_accept:
      new_filter->function_ptr = fp_accept;
      break;
    case filter_priority:
      new_filter->function_ptr = fp_priority;
      break;
    case filter_reject:
      new_filter->function_ptr = fp_reject;
      break;
    case filter_drop:
      new_filter->function_ptr = fp_drop;
  printf("# select drop: %d\n", action);
  printf("fp_drop: 0x%08x\n",fp_drop);
  printf("newfilter: 0x%08x\n",new_filter);
      break;
    default:
      printf("#unknown filter action\n");
      break;
  }
  printf("# filter added\n");
  return 0;
}

int pico_ipv4_filter_del(uint8_t filter_id) {

  if (!tail || !head) {
    return -1;
  }

  struct filter_node *work;
  struct filter_node *prev;
  work = head;
  if (work->filter_id == filter_id) {
      /*delete filter_node from linked list*/
      head = work->next_filter;
      free(work);
      return 0;
  }
  prev = work;
  work = work->next_filter;

  while (1) {
    if (work->filter_id == filter_id) {
        if (work != tail) {
        /*delete filter_node from linked list*/
        prev->next_filter = work->next_filter;
        free(work);
        return 0;
        } else {
          prev->next_filter = NULL;
          free(work);
          return 0;
        }
    } else {
      /*check next filter_node*/
      prev = work;
      work = work->next_filter;
    }
  }
  return -1;
}

/*================================== CORE FILTER FUNCTIONS ==================================*/
int match_filter(struct filter_node *filter, struct pico_frame *f) {

  if (!filter|| !f) {
    printf("## nullpointer in match filter \n");
    return -1;
  }

  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  if (filter->fdev != NULL) {
    if (filter->fdev == f->dev)
      return 0; /*filter match!*/
  }
      printf("filter proto:%d\n",filter->proto);
      printf("packet proto:%d\n",ipv4_hdr->proto);
  if (filter->proto != 0) {
    if (filter->proto == ipv4_hdr->proto) {
     
      printf("protocol match \n");
      return 0;
    }
  }
  if (filter->out_addr != 0) {
    if (filter->out_addr == ipv4_hdr->src.addr)
      return 0;
  }
  if (filter->out_addr_netmask != 0) {
    if ((filter->out_addr & filter->out_addr_netmask) == (ipv4_hdr->src.addr & filter->out_addr_netmask))
      return 0;
   }
  if (filter->in_addr != 0) {
    if (filter->in_addr == ipv4_hdr->dst.addr)
      return 0;
  }
  if (filter->in_addr_netmask != 0) {
    if ((filter->in_addr & filter->in_addr_netmask) == (ipv4_hdr->dst.addr & filter->in_addr_netmask))
      return 0;
   }/*OUT*/
  if (filter->out_port != 0) {
    if (ipv4_hdr->proto == PICO_PROTO_TCP ) {
      struct pico_tcp_hdr *tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
      if (short_be(filter->out_port) == tcp_hdr->trans.sport)
        return 0;
    } else if (ipv4_hdr->proto == PICO_PROTO_UDP) {
      struct pico_udp_hdr *udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      printf("sport/out_port: %u %u\n", short_be(udp_hdr->trans.sport), filter->out_port);
      if ((short_be(filter->out_port) == udp_hdr->trans.sport) && (filter->proto != PICO_PROTO_UDP))
        return 0;
    }
  }

  /*IN*/
  if (filter->in_port != 0) {
      printf("proto: %d\n",ipv4_hdr->proto);
    if (ipv4_hdr->proto == PICO_PROTO_TCP ) {
      struct pico_tcp_hdr *tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
      printf("got tcp_hdr\n");
      if (short_be(filter->in_port) == tcp_hdr->trans.dport)
        return 0;
    } else if (ipv4_hdr->proto == PICO_PROTO_UDP) {
      struct pico_udp_hdr *udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      printf("dport/in_port: %u %u\n", short_be(udp_hdr->trans.dport), filter->in_port);
      if ((short_be(filter->in_port) == udp_hdr->trans.dport) && (filter->proto != PICO_PROTO_UDP)) {
      printf("dport/in_port: %d\n", short_be(udp_hdr->trans.dport));
        return 0;
      }
    }
  }

  if ((filter->priority > 10) || (filter->priority < -10))
    return -1;
  if (filter->tos != 0) {
    if (filter->tos == ipv4_hdr->tos);
      return 0;
  }
  /*No filter match!*/
  printf("#no match\n");
  return 1;
}

int ipfilter(struct pico_frame *f) {
  /*return 1 if pico_frame is discarded as result of the filtering, 0 for an incomming packet, -1 for faults*/
  if (!tail || !head)  {
    return 0;
  }

  struct filter_node *work = head;
  printf("%s>>> 0X%08x\n",__FUNCTION__ ,work);
  printf("# ipfilter\n");
  if ( match_filter(work, f) == 0 ) { 
    printf("# ipfilter match\n");
      /*filter match, execute filter!*/
      printf("work_functionpnt: 0x%08x\n",work->function_ptr);
      printf("work: 0x%08x\n",work);
      printf("sizeof: %d\n", sizeof(*work));
      return work->function_ptr(work, f);
    } 

  while (tail != work) {
    printf("next filter..\n");
    work = work->next_filter;
      printf("work: 0x%08x\n",work);
    if ( match_filter(work, f) == 0 ) {
  printf("# ipfilter match\n");
      /*filter match, execute filter!*/
      printf("work_functionpnt: 0x%08x\n",work->function_ptr);
      printf("sizeof: %d\n", sizeof(*work));
      return work->function_ptr(work, f);
    }
  }
  return 0;
}

