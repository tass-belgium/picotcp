/*
 *  PicoTCP lightweight TCP/IP stack.
 *  Copyright 2012 Daniele Lacamera <root@danielinux.net>
 *
 *  See LICENSE.
 */
#include "pico_common.h"
#include "pico_setup.h"

static int frame_deliver_up(struct pico_frame *pkt)
{

  if (!pkt || !pkt->dest) {
    return -1;
  }

  pkt->origin = pkt->owner;
  pkt->owner = pkt->dest;
  pkt->dest = NULL;
  return  pkt->owner->to_lower.recv(pkt);
}

static int frame_deliver_down(struct pico_frame *pkt)
{

  if (!pkt || !pkt->dest) {
    return -1;
  }

  pkt->origin = pkt->owner;
  pkt->owner = pkt->dest;
  pkt->dest = NULL;
  return  pkt->owner->to_upper.send(pkt);
}

static int _do_pico_frame_deliver(struct pico_frame *pkt, int cpy)
{
  char target[MAX_MODULE_NAME];
  /* Shortcut for packets that already know their way */
  if (pkt->dest)
    goto deliver;

  if (pkt->stage == PICO_ROUTING_INCOMING) {
    /* Packet being received, climbing up the stack. */
    switch(pkt->owner->layer) {
      case PICO_LAYER_DATALINK:

        if (pkt->id_eth == PICO_IDETH_IP) {
          /* must be processed by the network */
          snprintf(target, MAX_MODULE_NAME, "ipv%hd", pkt->id_net);
        } else{
          snprintf(target, MAX_MODULE_NAME, "app:2:%hd", pkt->id_net);
        }
        pkt->dest = pico_mod_get(target);
      break;

      case PICO_LAYER_NETWORK:
        snprintf(target, MAX_MODULE_NAME, "trans%hd:%hd", pkt->id_trans, pkt->id_sock);
        pkt->dest = pico_mod_get(target);
        if (!pkt->dest) {
          snprintf(target, MAX_MODULE_NAME, "app:3:%hd", pkt->id_trans);
          pkt->dest = pico_mod_get(target);
        }
        if (!pkt->dest) {
            snprintf(target, MAX_MODULE_NAME, "app:3:1"); /* ICMP */
            pkt->dest = pico_mod_get(target);
          }
      case PICO_LAYER_TRANSPORT:
        /* Bounced back from transport layer to some stack application
           relying on TCP/UDP (e.g. internal DNS).
         */
         snprintf(target, MAX_MODULE_NAME, "app:5:%hd:%hd", pkt->id_trans, pkt->id_sock);
         pkt->dest = pico_mod_get(target);
      break;
    }
  } else {
    /* Outgoing packet, sliding down the stack */
    switch (pkt->owner->layer) {
      case PICO_LAYER_APP:
        {
          snprintf(target, MAX_MODULE_NAME, "trans:%hd:%hd", (uint16_t)pkt->id_trans, pkt->id_sock);
          pkt->dest = pico_mod_get(target);
        }
      break;

      case PICO_LAYER_TRANSPORT:
          snprintf(target, MAX_MODULE_NAME, "ipv%hd", pkt->id_net);
          pkt->dest = pico_mod_get(target);
      break;
      /* NETWORK and DATALINK packets MUST already have the dest module set at this point. */
    }
  }

deliver:
  if (!pkt->dest) {
    return -1;
  } else {
    if (cpy)
      pkt->usage_count++;
    if (pkt->stage == PICO_ROUTING_INCOMING)
      return frame_deliver_up(pkt);
    else
      return frame_deliver_down(pkt);
  }
}

int pico_frame_deliver(struct pico_frame *pkt)
{
  return _do_pico_frame_deliver(pkt, 0);
}

int pico_frame_deliver_cpy(struct pico_frame *pkt)
{
  return _do_pico_frame_deliver(pkt, 1);
}

struct pico_frame *pico_frame_alloc(struct pico_module *owner, int size)
{
  struct pico_frame *p = pico_zalloc(sizeof(struct pico_frame));
  if (!p)
    return NULL;
  p->buffer = pico_zalloc(size);
  if (!p->buffer) {
    pico_free(p);
    return NULL;
  }
  p->buffer_len = size;
  p->owner = owner;
  p->usage_count = 1;
  p->stage = PICO_ROUTING_OUTGOING;
  return p;
}

void pico_frame_discard(struct pico_frame *p)
{
  p->usage_count--;
  if (p->usage_count <= 0) {
    pico_free(p->buffer);
    pico_free(p);
  }
}

/* Called by device itself to receive a new packet */
void pico_dev_recv(struct pico_device *dev, struct pico_frame *p)
{
  if (pico_enqueue(dev->qin, p) != 0)
    pico_frame_discard(p);
  else {
    p->stage = PICO_ROUTING_INCOMING;
    p->dev = dev;
    p->owner = dev;
  }
}

/* Called by network layer to enqueue new packet for transmission */
void pico_dev_send(struct pico_device *dev, struct pico_frame *p)
{
  if ((p->stage != PICO_ROUTING_OUTGOING) || (pico_enqueue(dev->qout, p) != 0))
    pico_frame_discard(p);
  else {
    p->dev = dev;
    p->owner = dev;
  }
}


/* Called by upper layers to allocate a new outgoing frame */
void pico_dev_alloc(struct pico_device *dev, uint16_t size)
{
  pico_frame_alloc(size + dev->overhead + (pico->eth_dev?14:0));
}

/* process_in */
void pico_dev_process_input(struct pico_device *dev, int score)
{
  struct pico_frame *p = pico_dequeue(dev->qin);
  while(p) {
    if (p->dev_eth) {
      p->dest = p->dev_eth;
    } else {
      /* TODO: set id_net */
    }
    pico_frame_deliver(p);
    if (--score <= 0)
      return;
    p = pico_dequeue(dev->qin);
  }
}

/* process_out */
void pico_dev_process_output(struct pico_device *dev, int score)
{
  struct pico_frame *p = pico_dequeue(dev->qout);
  while(p) {
    if (dev->send(p) > 0)
      pico_frame_discard(p);
    else
      return;
    if (--score <= 0)
      return;
    p = pico_dequeue(dev->qout);
  }
}


/* Ethernet layer */

