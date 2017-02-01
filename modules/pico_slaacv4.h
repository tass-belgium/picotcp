/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Bogdan Lupu
 *********************************************************************/
#ifndef INCLUDE_PICO_SUPPORT_SLAACV4
#define INCLUDE_PICO_SUPPORT_SLAACV4
#include "pico_arp.h"

#define PICO_SLAACV4_SUCCESS  0
#define PICO_SLAACV4_ERROR    1

int     pico_slaacv4_claimip(struct pico_device *dev, void (*cb)(struct pico_ip4 *ip,  uint8_t code));
void    pico_slaacv4_unregisterip(void);

#endif /* _INCLUDE_PICO_SUPPORT_SLAACV4 */

