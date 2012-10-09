#include "pico_ipv4.h"


/* Queues */
static struct pico_queue in;
static struct pico_queue out;


/* Functions */

static int pico_ipv4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  return 0;
}

static int pico_ipv4_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  return 0;
}

static struct pico_frame *pico_ipv4_alloc(struct pico_protocol *self, int size)
{
  return pico_frame_alloc(size + PICO_SIZE_IP4HDR);
}

struct pico_protocol pico_proto_ipv4 = {
  .layer = PICO_LAYER_NETWORK,
  .alloc = pico_ipv4_alloc,
  .process_in = pico_ipv4_process_in,
  .process_out = pico_ipv4_process_out,
  .q_in = &in,
  .q_out = &out,
};
