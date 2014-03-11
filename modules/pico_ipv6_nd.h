/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_ND
#define _INCLUDE_PICO_ND
#include "pico_frame.h"

/* RFC constants */
#define PICO_ND_REACHABLE_TIME         30000 /* msec */
#define PICO_ND_RETRANS_TIMER          1000 /* msec */

struct pico_nd_hostvars {
    uint32_t mtu;
    uint8_t hoplimit;
    pico_time basetime;
    pico_time reachabletime;
    pico_time retranstime;
};

void pico_nd_init(void);
struct pico_eth *pico_nd_get(struct pico_frame *f);
int pico_nd_neigh_sol_recv(struct pico_frame *f);
int pico_nd_neigh_adv_recv(struct pico_frame *f);
int pico_nd_router_sol_recv(struct pico_frame *f);
int pico_nd_router_adv_recv(struct pico_frame *f);
int pico_nd_redirect_recv(struct pico_frame *f);
#endif
