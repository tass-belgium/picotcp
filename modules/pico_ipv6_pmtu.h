/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_IPV6_PMTU
#define _INCLUDE_PICO_IPV6_PMTU

#include "pico_addressing.h"
#define PICO_PMTU_OK (0)
#define PICO_PMTU_ERROR (-1)
#define PICO_PMTU_CACHE_CLEANUP_INTERVAL (10 * (60 * 1000))

struct pico_ipv6_path_id {
    struct pico_ip6 dst;
};


uint32_t pico_ipv6_pmtu_get(const struct pico_ipv6_path_id *path);
int pico_ipv6_path_add(const struct pico_ipv6_path_id *path, uint32_t mtu);
int pico_ipv6_path_update(const struct pico_ipv6_path_id *path, uint32_t mtu);
int pico_ipv6_path_del(const struct pico_ipv6_path_id *path);
void pico_ipv6_path_init(pico_time interval);

#endif
