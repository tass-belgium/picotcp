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

#define PICO_TCPHDR_SIZE 20
#define PICO_SIZE_TCP_DATAHDR (40)
#define PICO_SIZE_TCPHDR (sizeof(struct pico_tcp_hdr))


/* TCP options */
#define PICO_TCP_OPTION_END         0x00
#define PICO_TCPOPTLEN_END        1
#define PICO_TCP_OPTION_NOOP        0x01
#define PICO_TCPOPTLEN_NOOP       1
#define PICO_TCP_OPTION_MSS         0x02
#define PICO_TCPOPTLEN_MSS        4
#define PICO_TCP_OPTION_WS          0x03
#define PICO_TCPOPTLEN_WS         3
#define PICO_TCP_OPTION_SACK        0x04
#define PICO_TCPOPTLEN_SACK       2
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
int pico_tcp_initconn(struct pico_socket *s);
int pico_tcp_input(struct pico_socket *s, struct pico_frame *f);


#endif
