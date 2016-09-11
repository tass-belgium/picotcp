/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#ifndef INCLUDE_PICO_6LOWPAN
#define INCLUDE_PICO_6LOWPAN

#include "pico_protocol.h"
#include "pico_device.h"
#include "pico_config.h"
#include "pico_frame.h"

#define PICO_6LOWPAN_IPHC_ENABLED

/******************************************************************************
 * Public variables
 ******************************************************************************/

extern struct pico_protocol pico_proto_6lowpan;

/******************************************************************************
 * Public functions
 ******************************************************************************/

int pico_6lowpan_pull(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst);

#endif /* INCLUDE_PICO_6LOWPAN */
