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

#define IEEE802154_PHY_MTU                  (128u)
#define IEEE802154_MAC_MTU                  (125u)
#define IEEE802154_SIZE_MHR_MIN             (5u)
#define IEEE802154_SIZE_FCS                 (2u)
#define IEEE802154_SIZE_LEN                 (1u)
#define IEEE802154_SIZE_PAN                 (2u)

//===----------------------------------------------------------------------===//
//  Structure definitions
//===----------------------------------------------------------------------===//

PACKED_STRUCT_DEF pico_ieee802154_fcf
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

PACKED_STRUCT_DEF pico_ieee802154_hdr
{
    struct pico_ieee802154_fcf fcf;
    uint8_t seq;
    uint8_t addresses[0];
};

//===----------------------------------------------------------------------===//
//  API Functions
//===----------------------------------------------------------------------===//

/**
 *  Compares 2 IEEE802.15.4 addresses. Takes extended and short addresses into
 *  account.
 */
int
pico_ieee802154_addr_cmp(void *, void *);

/**
 *      RECEIVING FRAMES
 *
 *  +--------------------------------------------------+    +------------------+
 *  |          dev->poll(dev, loop_score);         <<<<---------- SCHEDULER    |
 *  |                       |                          |    |                  |
 *  +-----------------------V--------------------------+    +------------------+
 *  |            radio_tx(radio, buf, len);            |
 *  |                       |                          |           [PHY]
 *  +-----------------------V--------------------------+
 *  |         pico_stack_recv(dev, buf, len)           |
 *  |                       |                          |         ~~STACK~~
 *  +-----------------------V--------------------------+
 *  |           pico_enqueue(dev.q_in, f);             |
 *  |                                                  |         ~~STACK~~
 *  +----------------------END-------------------------+
 *
 *                                                             (another time)
 *  +--------------------------------------------------+    +------------------+
 *  |           pico_dequeue(dev.q_in, f);         <<<<---------- SCHEDULER    |
 *  |                       |                          |    |                  |
 *  +-----------------------V--------------------------+    +------------------+
 *  |         pico_ieee802154_receive(f);              |
 *  |                       |                          |        [DATALINK]
 *  +-----------------------V--------------------------+
 *  | pico_sixlowpan_receive(f, srciid, dstiid);       |
 *  |                       |                          |     [ADAPTION LAYER]
 *  +-----------------------V--------------------------+
 *  |           pico_enqueue(proto_ipv6.q_in, f);      |
 *  |                                                  |      [NETWORK LAYER]
 *  +----------------------END-------------------------+
 **/

/**
 *  Receives a frame from the device and prepares it for higher layers.
 **/
void
pico_ieee802154_receive(struct pico_frame *f);

/**
 *   SENDING FRAMES
 *  ================
 *
 *  +--------------------------------------------------+
 *  |               pico_sendto_dev(f);                |
 *  |                       |                          |     [NETWORK LAYER]
 *  +-----------------------V--------------------------+
 *  |           pico_enqueue(f->dev.q_out, f);         |
 *  |                                                  |         ~~STACK~~
 *  +----------------------END-------------------------+
 *
 *                                                             (another time)
 *  +--------------------------------------------------+    +------------------+
 *  |           f = pico_dequeue(dev.q_in);        <<<<---------- SCHEDULER    |
 *  |                       |                          |    |                  |
 *  +-----------------------V--------------------------+    +------------------+
 *  |             pico_sixlowpan_send(f);              |
 *  |                       |                          |
 *  +-----------------------V--------------------------+
 *  |       pico_ieee802154_send(dev, buf, ...);       |
 *  |                       |                          |
 *  +-----------------------V--------------------------+
 *  |            dev->send(dev, buf, len);             |
 *  |                       |                          |
 *  +-----------------------V--------------------------+
 *  |            radio_tx(radio, buf, len);            |
 *  |                                                  |
 *  +----------------------END-------------------------+
 **/

/**
 *  Sends a buffer through IEEE802.15.4 encapsulation to the device.
 *  Return -1 when an error occured, 0 when the frame was transmitted
 *  successfully or 'ret > 0' to indicate that the provided buffer was to large
 *  to fit inside the IEEE802.15.4 frame after providing the MAC header with
 *  addresses and possibly a security header. Calls dev->send() finally.
 **/
int
pico_ieee802154_send(struct pico_device *dev,
                     struct pico_ip6 src,
                     struct pico_ip6 dst,
                     uint8_t *buf,
                     uint8_t len);

#endif /* INCLUDE_PICO_IEEE802154 */
