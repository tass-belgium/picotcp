#include "pico_common.h"
#include "pico_setup.h"



/* Routing thing */

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

