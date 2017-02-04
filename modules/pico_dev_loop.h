/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_LOOP
#define INCLUDE_PICO_LOOP
#include "pico_config.h"
#include "pico_device.h"

void pico_loop_destroy(struct pico_device *loop);
struct pico_device *pico_loop_create(void);

#endif

