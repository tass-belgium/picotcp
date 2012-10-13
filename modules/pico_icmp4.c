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

static int pico_icmp4_unreachable(struct pico_frame *f, uint8_t code)
{

  struct pico_frame *reply = pico_proto_ipv4.alloc(&pico_proto_ipv4, 8 + sizeof(struct pico_ipv4_hdr) + PICO_ICMPHDR_UN_SIZE);
  struct pico_icmp4_hdr *hdr;
  struct pico_ipv4_hdr *info = (struct pico_ipv4_hdr*)(f->net_hdr);

  hdr = (struct pico_icmp4_hdr *) reply->transport_hdr;

  hdr->type = PICO_ICMP_UNREACH;
  hdr->code = code;
  hdr->hun.ih_pmtu.ipm_nmtu = short_be(1500);
  hdr->hun.ih_pmtu.ipm_void = 0;
  reply->transport_len = 8 + sizeof(struct pico_ipv4_hdr) +  PICO_ICMPHDR_UN_SIZE;
  reply->payload = reply->transport_hdr + PICO_ICMPHDR_UN_SIZE;
  memcpy(reply->payload, f->net_hdr, 8 + sizeof(struct pico_ipv4_hdr));
  pico_icmp4_checksum(reply);
  pico_ipv4_frame_push(reply, &info->src, PICO_PROTO_ICMP4);
  return 0;
}

int pico_icmp4_port_unreachable(struct pico_frame *f)
{
  return pico_icmp4_unreachable(f, PICO_ICMP_UNREACH_PORT);
}

int pico_icmp4_proto_unreachable(struct pico_frame *f)
{
  return pico_icmp4_unreachable(f, PICO_ICMP_UNREACH_PROTOCOL);
}

int pico_icmp4_dest_unreachable(struct pico_frame *f)
{
  return pico_icmp4_unreachable(f, PICO_ICMP_UNREACH_HOST);
}

