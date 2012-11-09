#ifndef _INCLUDE_PICO_TUN
#define _INCLUDE_PICO_TUN
#include "pico_config.h"
#include "pico_device.h"

void pico_tun_destroy(struct pico_device *tun);
struct pico_device *pico_tun_create(char *name);

#endif

