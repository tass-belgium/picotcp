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


#endif
