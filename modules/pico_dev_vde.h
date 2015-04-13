/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.


 *********************************************************************/
#ifndef INCLUDE_PICO_VDE
#define INCLUDE_PICO_VDE
#include "pico_config.h"
#include "pico_device.h"
#include <libvdeplug.h>

void pico_vde_destroy(struct pico_device *vde);
struct pico_device *pico_vde_create(char *sock, char *name, uint8_t *mac);
void pico_vde_set_packetloss(struct pico_device *dev, uint32_t in_pct, uint32_t out_pct);

#endif

