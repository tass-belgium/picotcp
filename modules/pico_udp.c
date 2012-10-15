#include "pico_udp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_stack.h"


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
  return pico_network_send(f); 
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

int pico_udp_recv(struct pico_socket *s, void *buf, int len, void *src, uint16_t *port)
{
  struct pico_frame *f = pico_dequeue(&s->q_in);
  if (f) {
    f->payload = f->transport_hdr + sizeof(struct pico_udp_hdr);
    f->payload_len = f->transport_len - sizeof(struct pico_udp_hdr);
    dbg("expected: %d, got: %d\n", len, f->payload_len);
    if (src)
      pico_store_network_origin(src, f);
    if (port) {
      struct pico_trans *hdr = (struct pico_trans *)f->transport_hdr;
      *port = hdr->sport;
    }
    if (f->payload_len > len) {
      memcpy(buf, f->payload, len);
      f->payload += len;
      f->payload_len -= len;
      pico_frame_discard(f); /** XXX: re-queue on head, instead! **/
      return len;
    } else {
      memcpy(buf, f->payload, f->payload_len);
      pico_frame_discard(f);
      return f->payload_len;
    }
  } else return -1;
}

