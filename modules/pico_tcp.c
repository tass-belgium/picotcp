#include "pico_tcp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_stack.h"
#include "pico_socket.h"
#include "pico_queue.h"
#define TCP_SOCK(s) ((struct pico_socket_tcp *)s)
#define SEQN(f) long_be(((struct pico_tcp_hdr *)(f->transport_hdr))->seq)
#define ACKN(f) long_be(((struct pico_tcp_hdr *)(f->transport_hdr))->ack)

#define PICO_TCP_LOOKAHEAD      0x00
#define PICO_TCP_RETRANSMIT     0x01
#define PICO_TCP_RECOVER        0x02
#define PICO_TCP_BLACKOUT       0x03
#define PICO_TCP_UNREACHABLE    0x04

/* Structure for TCP socket */
struct pico_socket_tcp {
  struct pico_socket sock;

  /* tcp_output */
  uint32_t snd_nxt;
  uint32_t snd_una;
  uint32_t snd_last;

  /* congestion control */
  uint16_t cwnd;
  uint16_t ssthresh;
  uint16_t in_flight;
  uint16_t avg_rtt;
  uint16_t rwnd;
  uint16_t rwnd_scale;

  /* tcp_input */
  uint32_t rcv_nxt;
  uint32_t rcv_ackd;
  uint32_t rcv_processed;
  uint16_t wnd;
  uint16_t wnd_scale;

  /* options */
  uint32_t ts_nxt;
  uint16_t mss;
  uint8_t sack_ok;
  uint8_t ts_ok;
  uint8_t mss_ok;
  uint8_t scale_ok;

  /* Transmission */
  uint8_t  x_mode;
  uint8_t  dupacks;
  uint8_t  backoff;

};


/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};

static inline int seq_compare(uint32_t a, uint32_t b)
{
  uint32_t thresh = ((uint32_t)(-1))>>1;
  if (((a > thresh) && (b > thresh)) || ((a <= thresh) && (b <= thresh))) {
    if (a > b)
      return 1;
    if (b > a)
      return -1;
  } else {
    if (a > b)
      return -2;
    if (b > a)
      return 2;
  }
  return 0;
}

/* Enhanced interface for tcp queues. */

/* Insert the packet in the queue, using the sequence number as order */
static int pico_enqueue_segment(struct pico_queue *q, struct pico_frame *f)
{
  struct pico_frame *test = q->head;
  int ret = -1;
  if ((q->max_frames) && (q->max_frames <= q->frames))
    return ret;

  if ((q->max_size) && (q->max_size < (f->buffer_len + q->size)))
    return ret;

  if (!q->head) {
    q->head = f;
    q->tail = f;
    q->size = 0;
    q->frames = 0;
    ret = 0;
  } else if (seq_compare(SEQN(f),  SEQN(q->head)) < 0) {
    f->next = q->head;
    q->head = f;
    ret = 0;
  } else if (seq_compare(SEQN(f), SEQN(q->tail)) > 0) {  /* Most Likely (enqueue) case */
    q->tail->next = f;
    f->next = NULL;
    ret = 0;
  } else {
    while((test) && (seq_compare(SEQN(f), SEQN(test)) > 0)) {
      if ((!test->next) || (seq_compare(SEQN(f), SEQN(test->next)) < 0)) {
        f->next = test->next;
        test->next = f;
        ret = 0;
        break;
      }
      test = test->next;
    }
  }
  if (ret == 0) {
    q->size += f->buffer_len;
    q->frames++;
#ifdef PICO_SUPPORT_DEBUG_TOOLS
    debug_q(q);
#endif
    return q->size;
  }
  return -1;
}

static struct pico_frame *pico_queue_peek(struct pico_queue *q, uint32_t seq)
{
  struct pico_frame *test = q->head;
#ifdef PICO_SUPPORT_DEBUG_TOOLS
  if (q->head)
    debug_q(q);
#endif
  while(test) {
    //dbg("Looking for %08x, found: %08x\n", seq, SEQN(test));
    if (SEQN(test) == seq)
      return test;
    test = test->next;
  }
  return NULL;
}

static struct pico_frame *pico_queue_peek_first(struct pico_queue *q)
{
  return q->head;
}

/* Useful for getting rid of the beginning of the buffer (e.g. for a fresh ack or a read() op */
static int pico_queue_release_until(struct pico_queue *q, uint32_t seq)
{
  struct pico_frame *prev = NULL, *test = q->head;
  int ret = 0;
  while(test) {
    struct pico_frame *del;
    if (seq_compare(SEQN(test) + test->payload_len, seq) <= 0) {
      if (!prev) 
        q->head = test->next;
        q->frames--;
        q->size -= test->buffer_len;
        dbg("TCP> Burning (release until)...\n");
        del = test;
        test = test->next;
        pico_frame_discard(del);
        ret++;
    } else {
      break;
    }
  }
  return ret;
}


/* API calls */

struct __attribute__((packed)) tcp_pseudo_hdr_ipv4
{
  struct pico_ip4 src;
  struct pico_ip4 dst;
  uint16_t tcp_len;
  uint8_t res;
  uint8_t proto;
};

int pico_tcp_checksum_ipv4(struct pico_frame *f)
{
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
  struct pico_socket *s = f->sock;
  struct tcp_pseudo_hdr_ipv4 pseudo;
  if (!hdr || !s)
    return -1;

  pseudo.src.addr = s->local_addr.ip4.addr;
  pseudo.dst.addr = s->remote_addr.ip4.addr;
  pseudo.res = 0;
  pseudo.proto = PICO_PROTO_TCP;
  pseudo.tcp_len = short_be(f->transport_len);

  hdr->crc = 0;
  hdr->crc = pico_dualbuffer_checksum(&pseudo, sizeof(struct tcp_pseudo_hdr_ipv4), hdr, f->transport_len);
  hdr->crc = short_be(hdr->crc);
  return 0;
}

static int pico_tcp_process_out(struct pico_protocol *self, struct pico_frame *f)
{
  pico_network_send(f);
  return 0;
}

int pico_tcp_push(struct pico_protocol *self, struct pico_frame *data);

/* Interface: protocol definition */
struct pico_protocol pico_proto_tcp = {
  .name = "tcp",
  .proto_number = PICO_PROTO_TCP,
  .layer = PICO_LAYER_TRANSPORT,
  .process_in = pico_transport_process_in,
  .process_out = pico_tcp_process_out,
  .push = pico_tcp_push,
  .q_in = &in,
  .q_out = &out,
};

static uint32_t pico_paws(void)
{
  static unsigned long _paws;
  dbg("PAWS!\n");
  _paws = pico_tick +  0xc0cac01a + _paws;
  return long_be(_paws); /*XXX: implement paws */
}

static void tcp_add_options(struct pico_socket_tcp *ts, struct pico_frame *f, int optsiz)
{
  uint32_t tsval = long_be(pico_tick);
  uint32_t tsecr = long_be(ts->ts_nxt);
  int i = 0;
  dbg("SETTING OPTIONS, len: %d\n", optsiz);
  f->start = f->transport_hdr + PICO_SIZE_TCPHDR;

  memset(f->start, PICO_TCP_OPTION_NOOP, optsiz); /* fill blanks with noop */

  if (optsiz >= 20) { 
    f->start[i++] = PICO_TCP_OPTION_MSS;
    f->start[i++] = PICO_TCPOPTLEN_MSS;
    f->start[i++] = (ts->mss >> 8) & 0xFF;
    f->start[i++] = ts->mss & 0xFF;
    f->start[i++] = PICO_TCP_OPTION_SACK_OK;
    f->start[i++] = PICO_TCPOPTLEN_SACK_OK;
  }

  f->start[i++] = PICO_TCP_OPTION_WS;
  f->start[i++] = PICO_TCPOPTLEN_WS;
  f->start[i++] = ts->wnd_scale;

  if (optsiz >= 12) {
    f->start[i++] = PICO_TCP_OPTION_TIMESTAMP;
    f->start[i++] = PICO_TCPOPTLEN_TIMESTAMP;
    memcpy(f->start + i, &tsval, 4);
    i += 4;
    memcpy(f->start + i, &tsecr, 4);
    i += 4;
  }
  f->start[ optsiz - 1 ] = PICO_TCP_OPTION_END;
}

static void tcp_set_space(struct pico_socket_tcp *t)
{
  int mtu = t->mss + PICO_SIZE_TCPHDR + PICO_SIZE_TCPOPT_SYN ;
  int space;
  int shift = 0;
  if (t->sock.q_in.max_size == 0) {
    space = 1024 * 1024 * 1024; /* One Gigabyte, for unlimited sockets. */
  } else {
    space = ((t->sock.q_in.max_size - t->sock.q_in.size) / mtu) * t->mss;
  }
  if (space < 0)
    space = 0;
  while(space > 0xFFFF) {
    space >>= 1;
    shift++;
  }
  t->wnd = space;
  t->wnd_scale = shift;
}


/* Return 32-bit aligned option size */
static int tcp_options_size(struct pico_socket_tcp *t, uint16_t flags)
{
  int size = 0;

  if (flags & PICO_TCP_SYN) {  /* Full options */ 
    size = PICO_TCPOPTLEN_MSS + PICO_TCP_OPTION_SACK_OK + PICO_TCPOPTLEN_WS + PICO_TCPOPTLEN_TIMESTAMP;
  } else {

   /* Always update window scale. */
    size += PICO_TCPOPTLEN_WS;

    if (t->ts_ok)
      size += PICO_TCPOPTLEN_TIMESTAMP;

    size+= PICO_TCPOPTLEN_END;
  }
  size = (((size + 3) >> 2) << 2);
  return size;
}

int pico_tcp_overhead(struct pico_socket *s)
{
  if (!s)
    return 0;

  return PICO_SIZE_TCPHDR + tcp_options_size((struct pico_socket_tcp *)s, 0); /* hdr + Options size for data pkt */

}

static void tcp_parse_options(struct pico_frame *f)
{
  struct pico_socket_tcp *t = (struct pico_socket_tcp *)f->sock;
  uint8_t *opt = f->transport_hdr + PICO_SIZE_TCPHDR;
  int i = 0;
  while (i < (f->transport_len - PICO_SIZE_TCPHDR)) {
    uint8_t type =  opt[i++];
    uint8_t len =  opt[i++];
    if (f->payload && ((opt + i) > f->payload))
      break;
    switch (type) {
      case PICO_TCP_OPTION_NOOP:
      case PICO_TCP_OPTION_END:
        i--; /* unread len */
        break;
      case PICO_TCP_OPTION_WS:
        if (len != PICO_TCPOPTLEN_WS) {
          dbg("TCP Window scale: bad len received.\n");
          i += len - 2;
          break;
        }
        t->rwnd_scale = opt[i++];
        break;
      case PICO_TCP_OPTION_SACK_OK:
        if (len != PICO_TCPOPTLEN_SACK_OK) {
          dbg("TCP option sack: bad len received.\n");
          i += len - 2;
          break;
        }
        t->sack_ok = 1;
        break;
      case PICO_TCP_OPTION_MSS: {
        uint16_t *mss;
        if (len != PICO_TCPOPTLEN_MSS) {
          dbg("TCP option mss: bad len received.\n");
          i += len - 2;
          break;
        }
        t->mss_ok = 1;
        mss = (uint16_t *)(opt + i);
        i += sizeof(uint16_t);
        if (t->mss > short_be(*mss))
          t->mss = short_be(*mss);
        break;
      }
      case PICO_TCP_OPTION_TIMESTAMP: {
        uint32_t *tsval, *tsecr;
        dbg("TIMESTAMP!\n");
        if (len != PICO_TCPOPTLEN_TIMESTAMP) {
          dbg("TCP option timestamp: bad len received.\n");
          i += len - 2;
          break;
        }
        t->ts_ok = 1;
        tsval = (uint32_t *)(opt + i);
        i += sizeof(uint32_t);
        tsecr = (uint32_t *)(opt + i);
        i += sizeof(uint32_t);

        t->ts_nxt = long_be(*tsval);
        break;
      }
      default:
        dbg("TCP: received unsupported option %u\n", type);
    }
  }
}


static int tcp_send(struct pico_socket_tcp *ts, struct pico_frame *f)
{
  struct pico_tcp_hdr *hdr= (struct pico_tcp_hdr *) f->transport_hdr;
  uint32_t next_to_send;
  struct pico_socket *s = (struct pico_socket *)ts;
  hdr->trans.sport = ts->sock.local_port;
  hdr->trans.dport = ts->sock.remote_port;
  hdr->seq = long_be(ts->snd_nxt);

  dbg ("TCP> IN TCP SEND, i have: rcv_nxt = %08x, rcv_ackd = %08x\n", ts->rcv_nxt, ts->rcv_ackd);
  if (ts->rcv_nxt != 0) {
    if ( (ts->rcv_ackd == 0) || (seq_compare(ts->rcv_ackd, ts->rcv_nxt) != 0) || (hdr->flags & PICO_TCP_ACK)) {
      hdr->flags |= PICO_TCP_ACK;
      hdr->ack = long_be(ts->rcv_nxt);
      ts->rcv_ackd = ts->rcv_nxt;
    }
  }

  next_to_send = ts->snd_nxt;

  if (hdr->flags & PICO_TCP_SYN)
    next_to_send++;
  if (f->payload_len > 0) {
    next_to_send = SEQN(f) + f->payload_len;
    hdr->flags |= PICO_TCP_PSH;
  }


  if (seq_compare(next_to_send, ts->snd_nxt) > 0) {
    ts->snd_nxt = next_to_send;
  }

  f->start = f->transport_hdr + PICO_SIZE_TCPHDR;
  hdr->rwnd = short_be(ts->wnd);
  pico_tcp_checksum_ipv4(f);
  pico_enqueue(&out, f);
  dbg("DBG> [tcp output] socket: %p state: %d --> local port:%d remote port: %d seq: %08x ack: %08x flags: %02x = t_len: %d, hdr: %u payload: %d\n",
      s, s->state, short_be(hdr->trans.dport), short_be(hdr->trans.sport), SEQN(f), ACKN(f), hdr->flags, f->transport_len, hdr->len >> 2, f->payload_len );
  dbg("Packet enqueued for TCP transmission.\n");
  return 0;
}

struct pico_socket *pico_tcp_open(void)
{
  struct pico_socket_tcp *t = pico_zalloc(sizeof(struct pico_socket_tcp));
  if (!t)
    return NULL;
  t->mss = PICO_TCP_DEFAULT_MSS;
  return &t->sock;
}


int pico_tcp_read(struct pico_socket *s, void *buf, int len)
{
  struct pico_socket_tcp *t = TCP_SOCK(s);
  struct pico_frame *f, *old;
  uint32_t in_frame_off, in_frame_len;
  int tot_rd_len = 0;


  while (tot_rd_len < len) {
    /* To be sure we don't have garbage at the beginning */
    pico_queue_release_until(&s->q_in, t->rcv_processed);
    f = pico_queue_peek_first(&s->q_in);
    if (!f)
      return tot_rd_len;

    /* Hole at the beginning of data, awaiting retransmissions. */
    if(seq_compare(t->rcv_processed, SEQN(f)) < 0) {
      return tot_rd_len;
    }

    if(seq_compare(t->rcv_processed, SEQN(f)) > 0) {
      in_frame_off = t->rcv_processed - SEQN(f);
      in_frame_len = f->payload_len - in_frame_off;
    } else {
      in_frame_off = 0;
      in_frame_len = f->payload_len;
    }

    if ((in_frame_len + tot_rd_len) > len) {
      in_frame_len = len - tot_rd_len;
    }

    memcpy(buf + tot_rd_len, f->payload + in_frame_off, in_frame_len);
    tot_rd_len += in_frame_len;
    t->rcv_processed += in_frame_len;

    if ((in_frame_len == 0) || (in_frame_len == f->payload_len)) {
      dbg("TCP> Burning...");
      old = pico_dequeue(&s->q_in);
      pico_frame_discard(old);
    }
    tcp_set_space(t);
  }
  //if (seq_compare(t->rcv_processed, SEQN(f)) >= 0) {
  //  dbg("TCP> Read: retry.\n");
  //  pico_timer_add(10, &wakeup_read, &s);
 // }
  return tot_rd_len;
}

int pico_tcp_initconn(struct pico_socket *s)
{
  struct pico_socket_tcp *ts = TCP_SOCK(s);
  struct pico_frame *syn;
  struct pico_tcp_hdr *hdr;
  int opt_len = tcp_options_size(ts, PICO_TCP_SYN);

  syn = s->net->alloc(s->net, PICO_SIZE_TCPHDR + opt_len);
  if (!syn)
    return -1;
  hdr = (struct pico_tcp_hdr *) syn->transport_hdr;

  ts->snd_nxt = long_be(pico_paws());
  ts->snd_last = ts->snd_nxt;
  syn->sock = s;
  hdr->seq = long_be(ts->snd_nxt);
  hdr->len = (PICO_SIZE_TCPHDR + opt_len) << 2;
  hdr->flags = PICO_TCP_SYN;
  hdr->rwnd = short_be(ts->wnd);
  ts->snd_una = short_be(hdr->seq);
  tcp_set_space(ts);
  tcp_add_options(ts,syn, opt_len);
  tcp_send(ts, syn);
  return 0;
}


static int tcp_send_synack(struct pico_socket *s)
{
  struct pico_socket_tcp *ts = TCP_SOCK(s);
  struct pico_frame *synack;
  struct pico_tcp_hdr *hdr;
  int opt_len = tcp_options_size(ts, PICO_TCP_SYN | PICO_TCP_ACK);


  synack = s->net->alloc(s->net, PICO_SIZE_TCPHDR + opt_len);
  if (!synack)
    return -1;
  hdr = (struct pico_tcp_hdr *) synack->transport_hdr;

  synack->sock = s;
  hdr->len = (PICO_SIZE_TCPHDR + opt_len) << 2;
  hdr->flags = PICO_TCP_SYN | PICO_TCP_ACK;
  hdr->rwnd = short_be(ts->wnd);
  hdr->seq = short_be(ts->snd_nxt);
  ts->rcv_processed = long_be(hdr->seq);
  ts->snd_last = ts->snd_nxt + 1;
  tcp_set_space(ts);
  tcp_add_options(ts,synack, opt_len);
  synack->payload_len = 0;
  //pico_enqueue_segment(&s->q_out,synack);
  tcp_send(ts, synack);
  return 0;
}



static void tcp_send_ack(struct pico_socket_tcp *t)
{
  struct pico_frame *f;
  struct pico_tcp_hdr *hdr;
  int opt_len = tcp_options_size(t, PICO_TCP_ACK);

  f = t->sock.net->alloc(t->sock.net, PICO_SIZE_TCPHDR + opt_len);
  if (!f) {
    return;
  }
  f->sock = &t->sock;
  hdr= (struct pico_tcp_hdr *) f->transport_hdr;
  hdr->len = (PICO_SIZE_TCPHDR + opt_len) << 2;
  hdr->flags = PICO_TCP_ACK;
  hdr->rwnd = short_be(t->wnd);
  tcp_set_space(t);
  tcp_add_options(t,f, opt_len);
  tcp_send(t,f);

}

static int tcp_data_in(struct pico_socket *s, struct pico_frame *f)
{
  struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
  if ((hdr->len >> 2) < f->transport_len) {

    f->payload = f->transport_hdr + (hdr->len >>2);
    f->payload_len = f->transport_len - (hdr->len >>2);

    dbg("TCP> [tcp input] RCVD data. seq: %08x flags: %02x data_len: %d\n", SEQN(f), hdr->flags, f->payload_len);
    if (seq_compare(SEQN(f) + f->payload_len, t->rcv_nxt) > 0) {
      dbg("TCP> hey, I've got a new segment!\n");
      pico_enqueue_segment(&t->sock.q_in, f);
      if (seq_compare(SEQN(f) + f->payload_len, t->rcv_nxt) > 0) {
        dbg("TCP> exactly what I was expecting!\n");
        if (t->sock.wakeup)
          t->sock.wakeup(PICO_SOCK_EV_RD, &t->sock);
        t->rcv_nxt = SEQN(f) + f->payload_len;
      } else {
        dbg("TCP> hi segment. Possible packet loss. I'll dupack this.\n");
        /* XXX: differentiate dupack to insert sacks. */
      }

    }
    /* In either case, ack til recv_nxt. */
    tcp_send_ack(t);
    return 0;
  } else {
    dbg("TCP> No data. tcp_len: %d, transport_len: %d\n", (hdr->len>>2), f->transport_len);
    return -1;
  }
}

static int tcp_ack_advance_una(struct pico_socket_tcp *t, struct pico_frame *f)
{
  int ret =  pico_queue_release_until(&t->sock.q_out, ACKN(f));
  t->snd_una = ACKN(f);
  return ret;
}

static uint16_t time_diff(unsigned long a, unsigned long b)
{
  if (a >= b)
    return (a - b);
  else
    return (b - a);
}

static int fresh_ack(struct pico_frame *f)
{
  struct pico_socket_tcp *t = (struct pico_socket_tcp *)f->sock;
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
  if (hdr->flags & PICO_TCP_ACK) {
    if (seq_compare(long_be(hdr->ack), t->snd_una) >= 0) {
      return 1;
    }
  }
  dbg(" ----> NO FRSH ACK! exp: %08x got %08x\n", t->snd_una, long_be(hdr->ack));
  return 0;

}

static int tcp_ack(struct pico_socket *s, struct pico_frame *f)
{
  struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
  uint16_t rtt = 0;
  if ((hdr->flags & PICO_TCP_ACK) == 0)
    return -1;

  tcp_parse_options(f);

  dbg("Expected ack: %08x, got %08x\n", t->snd_una, ACKN(f));
  if (fresh_ack(f)) {
    struct pico_frame *qf = pico_queue_peek(&t->sock.q_out,ACKN(f));
    t->in_flight -= tcp_ack_advance_una(t, f);
    if (qf)
      rtt = time_diff(pico_tick, qf->timestamp);
    dbg("TCP> new ack: %08x, rtt (calculated): %u. in flight: %d\n", ACKN(f),rtt, t->in_flight);
  } else {
    /* one gets to dst, one is lost */
    t->in_flight-= 2;
    dbg("TCP> DUPACK! snd_una: %08x, snd_nxt: %08x, acked now: %08x\n", t->snd_una, t->snd_nxt, ACKN(f));
  }
  return 0;
}

static int tcp_syn(struct pico_socket *s, struct pico_frame *f)
{
  /* TODO: Check against backlog length */
  struct pico_socket_tcp *new = (struct pico_socket_tcp *)pico_socket_clone(s);
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *)f->transport_hdr;
  if (!new)
    return -1;
  new->sock.remote_port = ((struct pico_trans *)f->transport_hdr)->sport;
#ifdef PICO_SUPPORT_IPV4
  if (IS_IPV4(f))
    new->sock.remote_addr.ip4.addr = ((struct pico_ipv4_hdr *)(f->net_hdr))->src.addr;
#endif
#ifdef PICO_SUPPORT_IPV6
  if (IS_IPV4(f))
    memcpy(new->sock.remote_addr.ip6.addr, ((struct pico_ipv6_hdr *)(f->net_hdr))->src, PICO_SIZE_IP6);
#endif

  /* Set socket limits */
  new->sock.q_in.max_size = PICO_DEFAULT_SOCKETQ;
  new->sock.q_out.max_size = PICO_DEFAULT_SOCKETQ;

  f->sock = &new->sock;
  tcp_parse_options(f);
  new->mss = PICO_TCP_DEFAULT_MSS;
  new->rcv_nxt = long_be(hdr->seq) + 1;
  new->snd_nxt = long_be(pico_paws());
  new->snd_una = new->snd_nxt;
  new->snd_last = new->snd_nxt;
  dbg("------------ Set snd_una to %08x\n", new->snd_una);
  new->cwnd = short_be(2);
  new->ssthresh = short_be(0xFFFF);
  new->rwnd = short_be(hdr->rwnd);
  new->sock.parent = s;
  new->sock.wakeup = s->wakeup;
  /* Initialize timestamp values */
  new->sock.state = PICO_SOCKET_STATE_BOUND | PICO_SOCKET_STATE_CONNECTED | PICO_SOCKET_STATE_TCP_SYN_RECV;
  pico_socket_add(&new->sock);
  tcp_send_synack(&new->sock);
  dbg("SYNACK sent, socket added.\n");
  return 0;
}

static void tcp_set_init_point(struct pico_socket *s)
{
  struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
  t->rcv_processed = t->rcv_nxt;
}

static int tcp_synack(struct pico_socket *s, struct pico_frame *f)
{
  return 0;
}

static int tcp_first_ack(struct pico_socket *s, struct pico_frame *f)
{
  if (fresh_ack(f)) {
    s->state &= 0x00FF;
    s->state |= PICO_SOCKET_STATE_TCP_ESTABLISHED;
    tcp_set_init_point(s);
    tcp_ack(s, f);
    tcp_data_in(s, f);
    dbg("TCP: Established.\n");
    if (s->parent && s->parent->wakeup) {
      s->parent->wakeup(PICO_SOCK_EV_CONN, s->parent);
    }
    return 0;
  } else {
    //tcp_send_synack(s);
    return 0;
  }
}

static int tcp_fin(struct pico_socket *s, struct pico_frame *f)
{
  return 0;
}

static int tcp_finack(struct pico_socket *s, struct pico_frame *f)
{
  return 0;
}

static int tcp_rst(struct pico_socket *s, struct pico_frame *f)
{
  return 0;
}



struct tcp_action_entry {
  uint16_t tcpstate;
  int (*syn)(struct pico_socket *s, struct pico_frame *f);
  int (*synack)(struct pico_socket *s, struct pico_frame *f);
  int (*ack)(struct pico_socket *s, struct pico_frame *f);
  int (*data)(struct pico_socket *s, struct pico_frame *f);
  int (*fin)(struct pico_socket *s, struct pico_frame *f);
  int (*finack)(struct pico_socket *s, struct pico_frame *f);
  int (*rst)(struct pico_socket *s, struct pico_frame *f);
};

static struct tcp_action_entry tcp_fsm[] = {
    /* State                            syn              synack       ack             data          fin       finack      rst*/
  { PICO_SOCKET_STATE_TCP_UNDEF,        NULL,            NULL,        NULL,           NULL,         NULL,     NULL,        NULL     },
  { PICO_SOCKET_STATE_TCP_CLOSED,       NULL,            NULL,        NULL,           NULL,         NULL,     NULL,        NULL     },
  { PICO_SOCKET_STATE_TCP_LISTEN,       &tcp_syn,        NULL,        NULL,           NULL,         NULL,     NULL,        NULL     },
  { PICO_SOCKET_STATE_TCP_SYN_SENT,     NULL,            &tcp_synack, NULL,           NULL,         NULL,     NULL,        &tcp_rst },
  { PICO_SOCKET_STATE_TCP_SYN_RECV,     NULL,            NULL,        &tcp_first_ack, NULL,         NULL,     NULL,        &tcp_rst },
  { PICO_SOCKET_STATE_TCP_ESTABLISHED,  NULL,            NULL,        &tcp_ack,       &tcp_data_in, &tcp_fin, &tcp_finack, &tcp_rst },
  { PICO_SOCKET_STATE_TCP_CLOSE_WAIT,   NULL,            NULL,        &tcp_ack,       NULL,         &tcp_fin, &tcp_finack, &tcp_rst },
  { PICO_SOCKET_STATE_TCP_LAST_ACK,     NULL,            NULL,        &tcp_ack,       &tcp_data_in, &tcp_fin, &tcp_finack, &tcp_rst },
  { PICO_SOCKET_STATE_TCP_FIN_WAIT1,    NULL,            NULL,        &tcp_ack,       &tcp_data_in, &tcp_fin, &tcp_finack, &tcp_rst },
  { PICO_SOCKET_STATE_TCP_FIN_WAIT2,    NULL,            NULL,        &tcp_ack,       &tcp_data_in, &tcp_fin, &tcp_finack, &tcp_rst },
  { PICO_SOCKET_STATE_TCP_CLOSING,      NULL,            NULL,        &tcp_ack,       &tcp_data_in, &tcp_fin, &tcp_finack, &tcp_rst },
  { PICO_SOCKET_STATE_TCP_TIME_WAIT,    NULL,            NULL,        &tcp_ack,       &tcp_data_in, &tcp_fin, &tcp_finack, &tcp_rst }
};

int pico_tcp_input(struct pico_socket *s, struct pico_frame *f)
{
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) (f->transport_hdr);
  int ret = -1;
  uint8_t flags = hdr->flags;
  struct tcp_action_entry *action = &tcp_fsm[s->state >> 8];

  if (!hdr)
    goto discard;

  f->payload = (f->transport_hdr + (hdr->len>>2));
  f->payload_len = f->transport_len - (hdr->len >> 2);

  dbg("[%lu] TCP> [tcp input] socket: %p state: %d <-- local port:%d remote port: %d seq: %08x ack: %08x flags: %02x = t_len: %d, hdr: %u payload: %d\n", pico_tick,
      s, s->state >> 8, short_be(hdr->trans.dport), short_be(hdr->trans.sport), SEQN(f), ACKN(f), hdr->flags, f->transport_len, hdr->len >> 2, f->payload_len );

  /* This copy of the frame has the current socket as owner */
  f->sock = s;

  /* Those are not supported at this time. */
  flags &= ~(PICO_TCP_CWR | PICO_TCP_URG | PICO_TCP_ECN);
  if (flags == PICO_TCP_SYN) {
    if (action->syn)
      action->syn(s,f);
  } else if (flags == (PICO_TCP_SYN | PICO_TCP_ACK)) {
    if (action->synack)
      action->synack(s,f);
  } else {
    if (f->payload_len > 0) {
      if (action->data)
        action->data(s,f);
      flags &= ~PICO_TCP_PSH;
    }
    if (flags == PICO_TCP_FIN) {
    }
      if (action->fin)
        action->fin(s,f);
    }
    if (flags == (PICO_TCP_FIN | PICO_TCP_ACK)) {
      if (action->finack)
        action->finack(s,f);
    }
    if (flags & PICO_TCP_RST) {
      if (action->rst)
        action->rst(s,f);
    }
    if (flags == PICO_TCP_ACK) {
      if (action->ack)
        action->ack(s,f);
    }

  //tcp_parse_options(f);

#if 0
  switch (TCPSTATE(s)) {
    case PICO_SOCKET_STATE_TCP_LISTEN:
      break;

    case PICO_SOCKET_STATE_TCP_SYN_RECV:
    {
      dbg("In TCP Syn recv.\n");
      if (fresh_ack(f)) {

        if (flags & PICO_TCP_SYN) {
          break;
        }

        s->state &= 0x00FF;
        s->state |= PICO_SOCKET_STATE_TCP_ESTABLISHED;
        tcp_set_init_point(s);
        tcp_ack(s, f);
        tcp_data_in(f);
        dbg("TCP: Established.\n");
        if (s->parent && s->parent->wakeup) {
          s->parent->wakeup(PICO_SOCK_EV_CONN, s->parent);
        }
      }
    }
    break;

    case PICO_SOCKET_STATE_TCP_ESTABLISHED:
      tcp_ack(f);
      if(tcp_data_in(f) == 0)
        return ret;
    break;

    default:
      break;
  }
#endif

discard:
  dbg("Discard.\n\n\n");
  pico_frame_discard(f);
  return ret;
}



int pico_tcp_push(struct pico_protocol *self, struct pico_frame *f)
{
  struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *)f->transport_hdr;
  struct pico_socket_tcp *t = (struct pico_socket_tcp *) f->sock;
  hdr->seq = long_be(t->snd_last + 1);
  hdr->len = (f->payload - f->transport_hdr) << 2;
  t->snd_last += f->payload_len;
  dbg("TCP> ENQUEUE pkt %08x len=%d (snd->nxt is %08x, snd->last is now %08x)\n", long_be(hdr->seq), f->payload_len, t->snd_nxt, t->snd_last);
  if (pico_enqueue_segment(&f->sock->q_out,f) > 0)
    return f->payload_len;
  else return 0;
}

void pico_tcp_output(struct pico_socket *s)
{
  struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
  struct pico_frame *f;

  f = pico_queue_peek(&s->q_out, t->snd_nxt + 1);
  while(f && (t->in_flight <= t->cwnd)) {
    dbg("TCP> DEQUEUED (for output) frame %08x, len= %d\n", SEQN(f), f->payload_len);
    f->timestamp = pico_tick;
    tcp_add_options(t, f, tcp_options_size(t, f->flags));
    tcp_send(t, pico_frame_copy(f));
    t->in_flight++;
    f = pico_queue_peek(&s->q_out, t->snd_nxt + 1);

    if (!f && (t->x_mode > PICO_TCP_LOOKAHEAD)) {
      f = pico_queue_peek_first(&s->q_out); /* Try to restart the queue when in retransmission */
      if (f)
        t->snd_nxt = SEQN(f) + f->payload_len;
    }
  }
}
