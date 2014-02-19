/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.


 *********************************************************************/
#ifndef INCLUDE_PICO_VDE
#define INCLUDE_PICO_VDE
#include "pico_config.h"
#include "pico_device.h"
#include <libvdeplug.h>

void pico_vde_destroy(struct pico_device *vde);
struct pico_device *pico_vde_create(char *sock, char *name, uint8_t *mac);

#endif

