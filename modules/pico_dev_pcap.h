/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.


  Author: Daniele Lacamera <daniele.lacamera@tass.be>
 *********************************************************************/
#ifndef _INCLUDE_PICO_PCAP
#define _INCLUDE_PICO_PCAP
#include "pico_config.h"
#include "pico_device.h"
#include <pcap.h>

void pico_pcap_destroy(struct pico_device *pcap);
struct pico_device *pico_pcap_create(char *sock, char *name, uint8_t *mac);

#endif

