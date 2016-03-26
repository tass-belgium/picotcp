/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/

#ifndef INCLUDE_PICO_ETHERNET
#define INCLUDE_PICO_ETHERNET

#include "pico_config.h"
#include "pico_frame.h"

#ifdef PICO_SUPPORT_ETH
int32_t pico_ethernet_send(struct pico_frame *f);

/* The pico_ethernet_receive() function is used by
 * those devices supporting ETH in order to push packets up
 * into the stack.
 */
/* DATALINK LEVEL */
int32_t pico_ethernet_receive(struct pico_frame *f);

#else
/* When ETH is not supported by the stack... */
#   define pico_ethernet_send(f)    (-1)
#   define pico_ethernet_receive(f) (-1)
#endif

#endif /* INCLUDE_PICO_ETHERNET */
