/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Author: Andrei Carp <andrei.carp@tass.be>
*********************************************************************/

#ifndef PICO_SIMPLE_HTTP
#define PICO_SIMPLE_HTTP

extern int pico_startHttpServer(struct pico_ip4 * address);
extern int pico_stopHttpServer(void);

#endif
