/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.
  
Authors: Kristof Roelants
*********************************************************************/

#ifndef _INCLUDE_PICO_DNS_CLIENT
#define _INCLUDE_PICO_DNS_CLIENT

int pico_dns_client_getaddr(const char *url, void (*callback)(char *ip));
int pico_dns_client_getname(const char *ip, void (*callback)(char *url));

#endif /* _INCLUDE_PICO_DNS_CLIENT */
