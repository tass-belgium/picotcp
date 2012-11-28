/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

*********************************************************************/
#ifndef _INCLUDE_PICO_NULL
#define _INCLUDE_PICO_NULL
#include "pico_config.h"
#include "pico_device.h"

void pico_null_destroy(struct pico_device *null);
struct pico_device *pico_null_create(char *name);

#endif

