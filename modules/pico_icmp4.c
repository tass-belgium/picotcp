#include "pico_icmp4.h"
#include "pico_config.h"


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


/* Functions */

static int pico_icmp4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  dbg("Called %s\n", __FUNCTION__);
  return 0;
}

static int pico_icmp4_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  dbg("Called %s\n", __FUNCTION__);
  return 0;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_icmp4 = {
  .name = "icmp4",
  .layer = PICO_LAYER_TRANSPORT,
  .process_in = pico_icmp4_process_in,
  .process_out = pico_icmp4_process_out,
  .q_in = &in,
  .q_out = &out,
};
