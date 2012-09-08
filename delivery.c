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
          snprintf(target, MAX_MODULE_NAME, "app:2:%hd");
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
            pkt->flags |= PICO_UNREACHABLE;
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

#if 0

/**** PSEUDOCODE ***/

// module interface
pico_module_load(char *name, void *arg) {
  struct module *mod;
  mod = hash_get(name);
  if (mod)
    return 0;
  mod = module_open(name, arg);
  if (mod) {
    if (mod->init(mod) == 0) {
      hash_insert(mod);
      return 0;
    }
  }
  return -1;
}

pico_loop() {
  for(;;) {
    run_sockets();
    run_devices();
    run_networks();
    run_apps();
  }
};


// network
void net_ipv4_run(void) {
  while (packets in the queue) {
    pick_first();
    route() || trans_recv();
  }
}



// transport
void trans_run(void) {
  while(packets in the queue) {
    pick_first();
    network_send();
  }
}

int trans_recv(pkt) {
  if (space in the queue) {
    enqueue(pkt);
    return len;
  }
  return 0; // no space in socket buffer to recv
}

int trans_recv_ready(pkt) {
  if (space in the queue >= pkt.len) {
    return 1;
  }
  return 0;
}



/********* NOTES *************/

Arp must export an interface to query for destination while packets are waiting in the IP output queue.
ICMP must export an interface to deny 




#endif


