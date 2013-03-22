/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

*********************************************************************/
#ifndef _INCLUDE_PICO_TCP
#define _INCLUDE_PICO_TCP
#include "pico_addressing.h"
#include "pico_protocol.h"
#include "pico_socket.h"

extern struct pico_protocol pico_proto_tcp;

struct __attribute__((packed)) pico_tcp_hdr {
  struct pico_trans trans;
  uint32_t seq;
  uint32_t ack;
  uint8_t  len;
  uint8_t flags;
  uint16_t  rwnd;
  uint16_t crc;
  uint16_t urgent;
};

struct __attribute__((packed)) tcp_pseudo_hdr_ipv4
{
  struct pico_ip4 src;
  struct pico_ip4 dst;
  uint16_t tcp_len;
  uint8_t res;
  uint8_t proto;
};

#define PICO_TCPHDR_SIZE 20
#define PICO_SIZE_TCPOPT_SYN 20
#define PICO_SIZE_TCPHDR (sizeof(struct pico_tcp_hdr))

#define PICO_TCP_DEFAULT_MSS 1444



/* TCP options */
#define PICO_TCP_OPTION_END         0x00
#define PICO_TCPOPTLEN_END        1
#define PICO_TCP_OPTION_NOOP        0x01
#define PICO_TCPOPTLEN_NOOP       1
#define PICO_TCP_OPTION_MSS         0x02
#define PICO_TCPOPTLEN_MSS        4
#define PICO_TCP_OPTION_WS          0x03
#define PICO_TCPOPTLEN_WS         3
#define PICO_TCP_OPTION_SACK_OK        0x04
#define PICO_TCPOPTLEN_SACK_OK       2
#define PICO_TCP_OPTION_SACK        0x05
#define PICO_TCPOPTLEN_SACK       2 /* Plus the block */
#define PICO_TCP_OPTION_TIMESTAMP   0x08
#define PICO_TCPOPTLEN_TIMESTAMP  10

/* TCP flags */
#define PICO_TCP_FIN 0x01
#define PICO_TCP_SYN 0x02
#define PICO_TCP_RST 0x04
#define PICO_TCP_PSH 0x08
#define PICO_TCP_ACK 0x10
#define PICO_TCP_URG 0x20
#define PICO_TCP_ECN 0x40
#define PICO_TCP_CWR 0x80



struct __attribute__((packed)) pico_tcp_option
{
  uint8_t kind;
  uint8_t len;
#if 0
  union {
   uint16_t mss;
    uint8_t wshift;
    struct {
      uint32_t tsval;
      uint32_t tsecr;
    } timestamp;
  } data;
#endif
};

struct pico_socket *pico_tcp_open(void);
int pico_tcp_read(struct pico_socket *s, void *buf, int len);
int pico_tcp_initconn(struct pico_socket *s);
int pico_tcp_input(struct pico_socket *s, struct pico_frame *f);
uint16_t pico_tcp_checksum_ipv4(struct pico_frame *f);
int pico_tcp_overhead(struct pico_socket *s);
int pico_tcp_output(struct pico_socket *s, int loop_score);
int pico_tcp_queue_in_is_empty(struct pico_socket *s);
int pico_tcp_reply_rst(struct pico_frame *f);

#endif
