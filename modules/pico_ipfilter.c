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
  uint32_t src_addr;
  uint32_t saddr_netmask;
  uint32_t dst_addr;
  uint32_t daddr_netmask;
  uint8_t proto;
  uint8_t sport;
  uint8_t dport;
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

  f->priority = filter->priority;
  return 0;
}

static int fp_reject(struct filter_node *filter, struct pico_frame *f) {
// TODO check first if sender is pico itself or not
  pico_icmp4_packet_filtered(f);
  pico_frame_discard(f);
  return 1;
}

static int fp_drop(struct filter_node *filter, struct pico_frame *f) {

  pico_frame_discard(f);
  return 1;
}

/*============================ API CALLS ============================*/
uint8_t pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto, uint32_t src_addr, uint32_t saddr_netmask, uint32_t dst_addr, uint32_t daddr_netmask, uint8_t sport, uint8_t dport, uint8_t priority, uint8_t tos, enum filter_action action) {

  static uint8_t filter_id = 0;

  struct filter_node *new_filter;
  new_filter = pico_zalloc(sizeof(struct filter_node));
  if (!head) {
    head = tail = new_filter;
  } else {
    tail->next_filter = new_filter;
    tail = new_filter;
  }

  new_filter->fdev = dev;
  new_filter->proto = proto;
  new_filter->src_addr = src_addr;
  new_filter->saddr_netmask = saddr_netmask;
  new_filter->dst_addr = dst_addr;
  new_filter->daddr_netmask = daddr_netmask;
  new_filter->sport = sport;
  new_filter->dport = dport;
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
      break;
  }
  return 0;
}

int pico_ipv4_filter_del(uint8_t filter_id) {

  uint8_t cnt = 0;
  while (tail != head) {
    if (tail->filter_id == filter_id) {
      /*delete filter_node from linked list*/
      free(tail --);
      return 0;
    } else {
      /*check previous filter_node*/
      tail --;
      cnt ++;
    }
  }
  /*replace tail pointer to the end of the train*/
  tail = tail + cnt;
  return -1;
}

/*================================== CORE FILTER FUNCTIONS ==================================*/
int match_filter(struct filter_node *filter, struct pico_frame *f) {
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  if (filter->fdev != NULL) {
    if (filter->fdev != f->dev)
      return 1; /*No filter match!*/
  }
  if (filter->proto != 0) {
    if (filter->proto != f->proto)
      return 1;
  }
  if (filter->src_addr != 0) {
    if (filter->src_addr != ipv4_hdr->src.addr)
      return 1;
  }
  if (filter->saddr_netmask != 0) {
    if ((filter->src_addr & filter->saddr_netmask) != (ipv4_hdr->src.addr & filter->saddr_netmask))
      return 1;
   }
  if (filter->dst_addr != 0) {
    if (filter->dst_addr != ipv4_hdr->dst.addr)
      return 1;
  }
  if (filter->daddr_netmask != 0) {
    if ((filter->dst_addr & filter->daddr_netmask) != (ipv4_hdr->dst.addr & filter->daddr_netmask))
      return 1;
   }
  if (filter->sport != 0) {
    if (f->proto == PICO_PROTO_TCP ) {
      struct pico_tcp_hdr *tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
      if (filter->sport != tcp_hdr->trans.sport)
        return 1;
    } else if (f->proto == PICO_PROTO_UDP) {
      struct pico_udp_hdr *udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      if (filter->dport != udp_hdr->trans.dport)
        return 1;
    }
  }
  if ((filter->priority > 10) || (filter->priority < -10))
    return -1;
  if (filter->tos != 0) {
    if (filter->tos != ipv4_hdr->tos);
      return 1;
  }
  /*filter match!*/
  return 0;
}

int ipfilter(struct pico_frame *f) {
  /*return 1 if pico_frame is discarded as result of the filtering, 0 for an incomming packet, -1 for faults*/
  uint8_t cnt = 0;
  while (tail != head) {
    if ( match_filter(head, f) == 0 ) {
      /*filter match, execute filter!*/
      return head->function_ptr(head, f);
    }
    head++;
    cnt++;
  }
  /*replace head pointer to the head of the train*/
  head = head - cnt;
  return 0;
}

