#ifndef _INCLUDE_PICO_UDP
#define _INCLUDE_PICO_UDP
#include "pico_addressing.h"
#include "pico_protocol.h"

extern struct pico_protocol pico_proto_udp;

struct __attribute__((packed)) pico_udp_hdr {
  struct pico_trans trans;
  uint16_t len;
  uint16_t crc;
};
#define PICO_UDPHDR_SIZE 8

struct pico_socket *pico_udp_open(void);
int pico_udp_recv(struct pico_socket *s, void *buf, int len, void *src, uint16_t *port);



#endif
