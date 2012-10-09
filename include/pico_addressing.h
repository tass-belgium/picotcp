#ifndef _INCLUDE_PICO_ADDRESSING
#define _INCLUDE_PICO_ADDRESSING
#include <stdint.h>


struct pico_ip4
{
  uint32_t addr;
};
#define PICO_SIZE_IP4 4

struct pico_ip6
{
  uint8_t addr[16];
};
#define PICO_SIZE_IP6 16

struct pico_eth
{
  uint8_t addr[6];
  uint8_t padding[2];
};
#define PICO_SIZE_ETH 6

extern const uint8_t PICO_ETHADDR_ANY[];


struct pico_trans
{
  uint16_t sport;
  uint16_t dport;

};
#define PICO_SIZE_TRANS 8

#endif
