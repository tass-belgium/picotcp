#ifndef PICO_SETUP_H
#define PICO_SETUP_H

/* Setup: POSIX */

/* Get numeric types from stdint.h */
#include <stdint.h>

/* Pre-defined string functions */
#include <string.h>

/* input/output library */
#include <stdio.h>

/* Use stdlib.h */
#include <stdlib.h>
#define pico_zalloc(x) calloc(1,x)
#define pico_alloc(x) malloc(x)
#define pico_free(x) free(x)


/* modules */
/* Uncomment to enable */

/* PROTOCOLS/APPS */
#define PICO_MODULE_IPV4
//#define PICO_MODULE_IPV6
//#define PICO_MODULE_ETH
//#define PICO_MODULE_ARP
//#define PICO_MODULE_TCP
//#define PICO_MODULE_UDP
//#define PICO_MODULE_DNS
//#define PICO_MODULE_DHCPD

/* DEVICES */
//#define PIC_MODULE_VDE

#include "modules.h"




#endif
