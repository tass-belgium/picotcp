#ifndef _INCLUDE_PICO_VDE
#define _INCLUDE_PICO_VDE
#include "pico_config.h"
#include "pico_device.h"
#include <libvdeplug.h>

void pico_vde_destroy(struct pico_device *vde);
struct pico_device *pico_vde_create(char *sock, char *name, uint8_t *mac);

#endif

