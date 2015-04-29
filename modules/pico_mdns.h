/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.
   .
   Author: Toon Stegen
 *********************************************************************/
#ifndef INCLUDE_PICO_MDNS
#define INCLUDE_PICO_MDNS

#define PICO_MDNS_DEST_ADDR4 "224.0.0.251"

int pico_mdns_init(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg);
int pico_mdns_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_mdns_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg);
int pico_mdns_flush_cache(void);

#ifdef PICO_SUPPORT_IPV6
#define PICO_MDNS_DEST_ADDR6 "FF02::FB"
int pico_mdns_getaddr6(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_mdns_getname6(const char *ip, void (*callback)(char *url, void *arg), void *arg);
#endif

#endif /* _INCLUDE_PICO_MDNS */
