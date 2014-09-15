/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.
   .
   Author: Toon Stegen
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_MDNS

int pico_mdns_init(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg);
int pico_mdns_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_mdns_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg);

#ifdef PICO_SUPPORT_IPV6
int pico_mdns_getaddr6(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_mdns_getname6(const char *ip, void (*callback)(char *url, void *arg), void *arg);
#endif

#endif /* PICO_SUPPORT_MDNS */
