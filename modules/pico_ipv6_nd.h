/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_ND
#define _INCLUDE_PICO_ND
#include "pico_frame.h"
#include "pico_ipv6.h"

/* RFC constants */
#define PICO_ND_REACHABLE_TIME         30000 /* msec */
#define PICO_ND_RETRANS_TIMER          1000 /* msec */

struct pico_nd_hostvars {
    uint8_t routing;
    uint8_t hoplimit;
    pico_time basetime;
    pico_time reachabletime;
    pico_time retranstime;
};

void pico_ipv6_nd_init(void);
struct pico_eth *pico_ipv6_get_neighbor(struct pico_frame *f);
void pico_ipv6_nd_postpone(struct pico_frame *f);
int pico_ipv6_nd_recv(struct pico_frame *f);

#ifdef PICO_SUPPORT_SIXLOWPAN
int pico_6lp_nd_start_solicitating(struct pico_ipv6_link *l);
#endif /* PICO_SUPPORT_SIXLOWPAN */

#endif
