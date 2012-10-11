#include "pico_udp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


/* Functions */

static __attribute__((unused)) int pico_udp_checksum(struct pico_frame *f)
{
  struct pico_udp_hdr *hdr = (struct pico_udp_hdr *) f->transport_hdr;
  if (!hdr)
    return -1;
  hdr->crc = 0;
  hdr->crc = short_be(pico_checksum(hdr, f->transport_len));
  return 0;
}

static int pico_udp_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_udp_hdr *hdr = (struct pico_udp_hdr *) f->transport_hdr;
  if (hdr) {

  } else {
    pico_frame_discard(f);
  }
  return 0;
}

static int pico_udp_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  dbg("Called %s\n", __FUNCTION__);
  
  return 0;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_udp = {
  .name = "udp",
  .layer = PICO_LAYER_TRANSPORT,
  .process_in = pico_udp_process_in,
  .process_out = pico_udp_process_out,
  .q_in = &in,
  .q_out = &out,
};
