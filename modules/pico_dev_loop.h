/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_LOOP
#define INCLUDE_PICO_LOOP
#include "pico_config.h"
#include "pico_device.h"

void pico_loop_destroy(struct pico_device *loop);
struct pico_device *pico_loop_create(void);

#endif

