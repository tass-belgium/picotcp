/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.
  
Authors: Kristof Roelants
*********************************************************************/

#ifndef _INCLUDE_PICO_DNS_CLIENT
#define _INCLUDE_PICO_DNS_CLIENT

#define PICO_DNS_NS_DEL 0
#define PICO_DNS_NS_ADD 1
#include <stdint.h>

int pico_dns_client_init();
/* flag is PICO_DNS_NS_DEL or PICO_DNS_NS_ADD */
int pico_dns_client_nameserver(struct pico_ip4 *ns, uint8_t flag);
int pico_dns_client_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_dns_client_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg);

#endif /* _INCLUDE_PICO_DNS_CLIENT */
