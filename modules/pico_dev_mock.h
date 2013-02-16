/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_MOCK
#define _INCLUDE_PICO_MOCK
#include "pico_config.h"
#include "pico_device.h"

//A mockup-device for the purpose of testing. It provides a couple of extra "network"-functions, which represent the network-side of the device. A network_send will result in mock_poll reading something, a network_read will see if the stack has sent anything through our mock-device.
void pico_mock_destroy(struct pico_device *mock);
struct pico_device *pico_mock_create(uint8_t* mac);

int pico_mock_network_read(struct pico_device* mock, void *buf, int len);
int pico_mock_network_write(struct pico_device* mock, const void *buf, int len);

//TODO
//we could use a few checking functions, e.g. one to see if it's a valid IP packet, if it's TCP, if the IP-address matches,...
//That would be useful to avoid having to manually create buffers of what you expect, probably with masks for things that are random,...

#endif
