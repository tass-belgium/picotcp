#include "pico_tcp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


/* Functions */

static __attribute__((unused)) int pico_tcp_checksum(struct pico_frame *f)
{
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
  if (!hdr)
    return -1;
  hdr->crc = 0;
  hdr->crc = short_be(pico_checksum(hdr, f->transport_len));
  return 0;
}

static int pico_tcp_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  dbg("Called %s\n", __FUNCTION__);
  
  return 0;
}


/* Interface: protocol definition */
struct pico_protocol pico_proto_tcp = {
  .name = "tcp",
  .proto_number = PICO_PROTO_TCP,
  .layer = PICO_LAYER_TRANSPORT,
  .process_in = pico_transport_process_in,
  .process_out = pico_tcp_process_out,
  .q_in = &in,
  .q_out = &out,
};

struct pico_socket_tcp {
  struct pico_socket sock;
  uint32_t snd_nxt;
  uint32_t snd_una;
  uint16_t cwnd;
  uint16_t ssthresh;
  uint32_t rcv_nxt;
  uint16_t rwnd;
  uint16_t avg_rtt;
};

#define TCP_SOCK(s) ((struct pico_socket_tcp *)s)

static uint32_t pico_paws(void)
{
  return 0U; /*XXX: implement paws */
}

static int tcp_send(struct pico_socket_tcp *ts, struct pico_frame *f)
{


  return 0;
}

struct pico_socket *pico_tcp_open(void)
{
  struct pico_socket_tcp *t = pico_zalloc(sizeof(struct pico_socket_tcp));
  if (!t)
    return NULL;
  return &t->sock;
}

int pico_tcp_initconn(struct pico_socket *s)
{
  struct pico_socket_tcp *ts = TCP_SOCK(s);
  struct pico_frame *syn = s->net->alloc(s->net, PICO_TCPHDR_SIZE +
      PICO_TCPOPTLEN_MSS + PICO_TCPOPTLEN_NOOP + PICO_TCPOPTLEN_SACK +
      PICO_TCP_OPTION_MSS + PICO_TCPOPTLEN_END);

  if (!syn)
    return -1;
  ts->snd_nxt = pico_paws();
  syn->sock = s;
  //syn->seq = ts->snd_nxt;
  /* XXX ... */
  tcp_send(ts, syn);
  return 0;
}

int pico_tcp_input(struct pico_socket *s, struct pico_frame *f)
{
  struct pico_socket_tcp *ts = TCP_SOCK(s);
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) (f->transport_hdr);
  int ret = -1;

  if (!hdr)
    goto discard;

  dbg("[tcp input] socket: %p state: %d <-- local port:%d remote port: %d seq: %lu flags: %d\n",
      s, s->state, short_be(hdr->trans.dport), short_be(hdr->trans.sport), long_be(hdr->seq), hdr->flags);


discard:
  pico_frame_discard(f);
  return ret;
}




