/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.


   Author: Daniele Lacamera <daniele.lacamera@altran.com>
 *********************************************************************/
#ifndef INCLUDE_PICO_PCAP
#define INCLUDE_PICO_PCAP
#include "pico_config.h"
#include "pico_device.h"
#include <pcap.h>

void pico_pcap_destroy(struct pico_device *pcap);
struct pico_device *pico_pcap_create_live(char *ifname, char *name, uint8_t *mac);
struct pico_device *pico_pcap_create_fromfile(char *filename, char *name, uint8_t *mac);

#endif

