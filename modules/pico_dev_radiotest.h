/*********************************************************************
 PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.

 Authors: Daniele Lacamera, Jelle De Vleeschouwer
 *********************************************************************/

#ifndef INCLUDE_PICO_DEV_RADIOTEST
#define INCLUDE_PICO_DEV_RADIOTEST

#include "pico_device.h"
#include "pico_config.h"

struct pico_device *pico_radiotest_create(uint8_t addr, uint8_t area0, uint8_t area1, int loop, char *dump);

#endif /* INCLUDE_PICO_DEV_RADIOTEST */
