/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.
  
Authors: Kristof Roelants
*********************************************************************/

#ifndef _INCLUDE_PICO_NAT
#define _INCLUDE_PICO_NAT
#include "pico_frame.h"

void pico_ipv4_nat_print_table(void);
int pico_ipv4_nat_add(uint32_t private_addr, uint16_t private_port, uint8_t proto, uint32_t nat_addr, uint16_t nat_port);
int pico_ipv4_nat_del(uint8_t proto, uint16_t nat_port);
int pico_ipv4_nat_find(uint32_t private_addr, uint16_t private_port, uint8_t proto, uint16_t nat_port);
int pico_ipv4_nat(struct pico_frame* f, struct pico_ip4 nat_addr);

#endif /* _INCLUDE_PICO_NAT */

