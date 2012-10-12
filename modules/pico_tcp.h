#ifndef _INCLUDE_PICO_TCP
#define _INCLUDE_PICO_TCP
#include "pico_addressing.h"
#include "pico_protocol.h"

extern struct pico_protocol pico_proto_tcp;

struct __attribute__((packed)) pico_tcp_hdr {
  struct pico_trans trans;
  uint32_t seq;
  uint32_t ack;
  uint16_t flags;
  uint16_t  rwnd;
  uint16_t crc;
  uint16_t urgent;
};

#define PICO_TCPHDR_SIZE 20

#define PICO_TCP_OPTION_END 0x00
#define PICO_TCPOPTLEN_END 1
#define PICO_TCP_OPTION_NOOP 0x01
#define PICO_TCPOPTLEN_NOOP 1
#define PICO_TCP_OPTION_MSS  0x02
#define PICO_TCPOPTLEN_MSS 4
#define PICO_TCP_OPTION_WS   0x03
#define PICO_TCPOPTLEN_WS 3
#define PICO_TCP_OPTION_TIMESTAMP   0x08
#define PICO_TCPOPTLEN_TIMESTAMP 10

struct __attribute__((packed)) pico_tcp_option
{
  uint8_t kind;
  uint8_t len;
  union {
    uint16_t mss;
    uint8_t wshift;
    struct {
      uint32_t tsval;
      uint32_t tsecr;
    } timestamp;
  } data;
};

struct pico_socket *pico_tcp_open(void);
int pico_tcp_initconn(struct pico_socket *s);


#endif
