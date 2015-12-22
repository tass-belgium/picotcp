/*********************************************************************
   PicoTCP. Copyright (c) 2014-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_TAP
#define INCLUDE_PICO_TAP
#include "pico_config.h"
#include "pico_device.h"

/* will look for the first TAP device available, and use it */
struct pico_device *pico_tap_create(char *name, uint8_t *mac);
/* TODO: not implemented yet */
/* void pico_tap_destroy(struct pico_device *null); */

#endif

