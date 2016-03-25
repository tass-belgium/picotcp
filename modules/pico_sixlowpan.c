/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

//===----------------------------------------------------------------------===//
//  Custom includes
//===----------------------------------------------------------------------===//
#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "pico_udp.h"

#ifdef PICO_SUPPORT_SIXLOWPAN

//===----------------------------------------------------------------------===//
//  API Functions
//===----------------------------------------------------------------------===//

int pico_sixlowpan_send(struct pico_frame *f)
{

}

void pico_sixlowpan_receive(struct pico_frame *f)
{

}

#endif /* PICO_SUPPORT_SIXLOWPAN */

//===----------------------------------------------------------------------===//
//===----------------------------------------------------------------------===//
