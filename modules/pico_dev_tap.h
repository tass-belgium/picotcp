/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_TAP
#define INCLUDE_PICO_TAP
#include "pico_config.h"
#include "pico_device.h"

void pico_tap_destroy(struct pico_device *tap);
struct pico_device *pico_tap_create(char *name);

#endif

