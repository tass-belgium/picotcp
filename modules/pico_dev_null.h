/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_NULL
#define INCLUDE_PICO_NULL
#include "pico_config.h"
#include "pico_device.h"

void pico_null_destroy(struct pico_device *null);
struct pico_device *pico_null_create(char *name);

#endif

