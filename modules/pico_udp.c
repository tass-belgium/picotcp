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


static int pico_udp_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  dbg("Called %s\n", __FUNCTION__);
  
  return 0;
}

static int pico_udp_push(struct pico_protocol *self, struct pico_frame *f)
{

  struct pico_udp_hdr *hdr;
  f->transport_hdr = f->payload - PICO_UDPHDR_SIZE;
  f->transport_len = f->payload_len + PICO_UDPHDR_SIZE;
  hdr = (struct pico_udp_hdr *) f->transport_hdr;
  hdr->trans.sport = f->sock->local_port;
  hdr->trans.dport = f->sock->remote_port;
  hdr->len = f->payload_len;
  hdr->crc = pico_udp_checksum(f);
  if (pico_enqueue(self->q_out, f) < 0) {
    return -1;
  }
  return 0;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_udp = {
  .name = "udp",
  .proto_number = PICO_PROTO_UDP,
  .layer = PICO_LAYER_TRANSPORT,
  .process_in = pico_transport_process_in,
  .process_out = pico_udp_process_out,
  .push = pico_udp_push,
  .q_in = &in,
  .q_out = &out,
};


#define PICO_UDP_MODE_UNICAST 0x01
#define PICO_UDP_MODE_MULTICAST 0x02
#define PICO_UDP_MODE_BROADCAST 0xFF

struct pico_socket_udp
{
  struct pico_socket sock;
  int mode;

};

struct pico_socket *pico_udp_open(void)
{
  struct pico_socket_udp *u = pico_zalloc(sizeof(struct pico_socket_udp));
  if (!u)
    return NULL;
  u->mode = PICO_UDP_MODE_UNICAST;
  return &u->sock;
}


