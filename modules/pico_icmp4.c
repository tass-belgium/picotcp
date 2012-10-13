#include "pico_icmp4.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_eth.h"


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


/* Functions */

static int pico_icmp4_checksum(struct pico_frame *f)
{
  struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
  if (!hdr)
    return -1;
  hdr->crc = 0;
  hdr->crc = short_be(pico_checksum(hdr, f->transport_len));
  return 0;
}

static int pico_icmp4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
  if (hdr->type == PICO_ICMP_ECHO) {
    hdr->type = PICO_ICMP_ECHOREPLY;
    /* Ugly, but the best way to get ICMP data size here. */
    f->transport_len = f->buffer_len - PICO_SIZE_IP4HDR - PICO_SIZE_ETHHDR;
    pico_icmp4_checksum(f);
    f->net_hdr = f->transport_hdr - PICO_SIZE_IP4HDR;
    f->start = f->net_hdr;
    f->len = f->buffer_len - PICO_SIZE_ETHHDR;
    pico_ipv4_rebound(f);
  } else {
    pico_frame_discard(f);
  }
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
  .proto_number = PICO_PROTO_ICMP4,
  .layer = PICO_LAYER_TRANSPORT,
  .process_in = pico_icmp4_process_in,
  .process_out = pico_icmp4_process_out,
  .q_in = &in,
  .q_out = &out,
};
