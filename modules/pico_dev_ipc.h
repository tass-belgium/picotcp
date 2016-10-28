/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_IPC
#define INCLUDE_PICO_IPC
#include "pico_config.h"
#include "pico_device.h"

void pico_ipc_destroy(struct pico_device *ipc);
struct pico_device *pico_ipc_create(const char *sock_path, const char *name, const uint8_t *mac);

#endif

