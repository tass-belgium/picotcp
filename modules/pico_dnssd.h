/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.
   .
   Author: Devon Kerkhove
 *********************************************************************/
#ifndef INCLUDE_PICO_DNSSD
#define INCLUDE_PICO_DNSSD

int pico_dnssd_getservices(const char *type, const char *domain, void (*callback)(void *instance_lst, void *arg), void *arg);

#endif /* _INCLUDE_PICO_DNSSD */
