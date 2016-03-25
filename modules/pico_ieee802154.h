/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/
#ifndef INCLUDE_PICO_IEEE802154
#define INCLUDE_PICO_IEEE802154

#include "pico_device.h"
#include "pico_config.h"

//===----------------------------------------------------------------------===//
//  Size definitions
//===----------------------------------------------------------------------===//

#define IEEE_PHY_MTU                (128u)
#define IEEE_MAC_MTU                (125u)

//===----------------------------------------------------------------------===//
//  Structure definitions
//===----------------------------------------------------------------------===//

PACKED_STRUCT_DEF ieee802154_fcf
{
    uint8_t frame_type: 3;          /* Type of frame, see PICO_FRAME_TYPE_x */
    uint8_t security_enabled: 1;    /* '1' When frame is secured */
    uint8_t frame_pending: 1;       /* '1' When the sending host has more data */
    uint8_t ack_required: 1;        /* Request for an acknowledgement */
    uint8_t intra_pan: 1;           /* PAN ID's are equal, src-PAN is elided */
    uint8_t res0: 1;                /* 1 reserved bit */
    uint8_t res1: 2;                /* 2 reserved bits */
    uint8_t dam: 2;                 /* Destination AM, see PICO_ADDR_MODE_x */
    uint8_t frame_version: 2;       /* Version, see PICO_FRAME_VERSION_x */
    uint8_t sam: 2;                 /* Source AM, see PICO_ADDR_MODE_x */
};

PACKED_STRUCT_DEF ieee802154_hdr
{
    struct ieee802154_fcf fcf;
    uint8_t seq;
    uint16_t pan;
    uint8_t addresses[0];
};

struct ieee802154_frame
{
    uint8_t *len;
    struct ieee802154_hdr *hdr;
    uint8_t *payload;
    uint8_t *fcs;
};

//===----------------------------------------------------------------------===//
//  API Functions
//===----------------------------------------------------------------------===//

///
/// Compares 2 IEEE802.15.4 addresses. Takes extended and short address into
/// account.
///
int pico_ieee802154_addr_cmp(void *va, void *vb);

#endif /* INCLUDE_PICO_IEEE802154 */
