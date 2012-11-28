/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

*********************************************************************/
#ifndef _INCLUDE_PICO_TUN
#define _INCLUDE_PICO_TUN
#include "pico_config.h"
#include "pico_device.h"

void pico_tun_destroy(struct pico_device *tun);
struct pico_device *pico_tun_create(char *name);

#endif

