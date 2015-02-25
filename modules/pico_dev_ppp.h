/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_PPP
#define INCLUDE_PICO_PPP
#include "pico_config.h"
#include "pico_device.h"

void pico_ppp_destroy(struct pico_device *ppp);
struct pico_device *pico_ppp_create(void);

void pico_ppp_set_serial_read(struct pico_device *, int (*sread)(struct pico_device *, void *, int));
void pico_ppp_set_serial_write(struct pico_device *, int (*swrite)(struct pico_device *, void *, int));
void pico_ppp_set_serial_set_speed(struct pico_device *dev, int (*sspeed)(struct pico_device *, uint32_t));

#endif

