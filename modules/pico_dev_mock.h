/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_MOCK
#define INCLUDE_PICO_MOCK
#include "pico_config.h"
#include "pico_device.h"


struct mock_frame {
    uint8_t*buffer;
    int len;
    int read;

    struct mock_frame*next;
};

struct mock_device {
    struct pico_device*dev;
    struct mock_frame*in_head;
    struct mock_frame*in_tail;
    struct mock_frame*out_head;
    struct mock_frame*out_tail;

    uint8_t*mac;

};

struct mock_device;
/* A mockup-device for the purpose of testing. It provides a couple of extra "network"-functions, which represent the network-side of the device. A network_send will result in mock_poll reading something, a network_read will see if the stack has sent anything through our mock-device. */
void pico_mock_destroy(struct pico_device *dev);
struct mock_device *pico_mock_create(uint8_t*mac);

int pico_mock_network_read(struct mock_device*mock, void *buf, int len);
int pico_mock_network_write(struct mock_device*mock, const void *buf, int len);

/* TODO */
/* we could use a few checking functions, e.g. one to see if it's a valid IP packet, if it's TCP, if the IP-address matches,... */
/* That would be useful to avoid having to manually create buffers of what you expect, probably with masks for things that are random,... */
uint32_t mock_get_sender_ip4(struct mock_device*mock, void*buf, int len);

int mock_ip_protocol(struct mock_device*mock, void*buf, int len);
int mock_icmp_type(struct mock_device*mock, void*buf, int len);
int mock_icmp_code(struct mock_device*mock, void*buf, int len);
#endif
