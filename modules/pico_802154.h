/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/
#ifndef INCLUDE_PICO_802154
#define INCLUDE_PICO_802154

#include "pico_device.h"
#include "pico_config.h"

/******************************************************************************
 * Size definitions
 ******************************************************************************/

#define MTU_802154_PHY                  (128u)
#define MTU_802154_MAC                  (125u) // 127 - Frame Check Sequence

#define SIZE_802154_MHR_MIN             (5u)
#define SIZE_802154_MHR_MAX             (23u)
#define SIZE_802154_FCS                 (2u)
#define SIZE_802154_LEN                 (1u)
#define SIZE_802154_PAN                 (2u)

/******************************************************************************
 * Public variables
 ******************************************************************************/
extern struct pico_protocol pico_proto_802154;

/******************************************************************************
 * Structure definitions
 ******************************************************************************/

PACKED_STRUCT_DEF pico_802154_hdr
{
    uint16_t fcf;
    uint8_t seq;
    uint16_t pan_id;
};

/******************************************************************************
 * Public
 ******************************************************************************/

/* Interface from the 6LoWPAN layer towards the link layer, either enqueues the
 * frame for later processing, or returns the amount of bytes available after
 * prepending the MAC header and additional headers */
int
pico_802154_frame_push(struct pico_frame *f, struct pico_ip6 *src, struct pico_ip6 *dst);

#endif /* INCLUDE_PICO_802154 */
