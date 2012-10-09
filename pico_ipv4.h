#ifndef _INCLUDE_PICO_IPV4
#define _INCLUDE_PICO_IPV4
#include "pico_addressing.h"
#include "pico_protocol.h"

extern struct pico_protocol pico_proto_ipv4;


struct __attribute__((packed)) pico_ipv4_hdr {
  uint8_t vhl;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t frag;
  uint8_t ttl;
  uint8_t proto;
  uint16_t crc;
  struct pico_ip4 src;
  struct pico_ip4 dst;
};

#define PICO_SIZE_IP4HDR ((sizeof(struct pico_ipv4_hdr)))

void pico_proto_ipv4_init(void);


#endif
