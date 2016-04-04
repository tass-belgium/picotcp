/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#ifndef INCLUDE_PICO_SIXLOWPAN
#define INCLUDE_PICO_SIXLOWPAN

#include "pico_device.h"
#include "pico_config.h"
#include "pico_frame.h"

///
/// Gets called by pico when it wants to transmit a IPv6-frame in 'devloop_out'.
///
/// This translates the IPv6-datagram to a 6LoWPAN-frame and possibly compresses
/// it or sends the next fragment of the frame. In that case the frame has to be
/// kept in the dev-queue.
///
/// Eventually, the adaption-layer will call dev->send on its turn to transmit
/// the frame on the network.
///
/// @returns    -1 when the frame needs to be kept in the queue. Could be for:
///                 - Subsequent fragments of the IPv6-datagram need to be
///                   transmitted.
///                 - The transmission failed and has to be retried.
///                 - The frame is not auto-ACK'ed.
///             0 when the frame can be removed from the dev-queue and thus the
///             frame is succesfully transmitted
///
int
pico_sixlowpan_send(struct pico_frame *f);

///
/// Gets called by pico when it has time to parse a 6LoWPAN-frame received by
/// the device-driver.
///
/// This translates the IPv6-datagram to an IPv6-frame and possibly decompresses
/// it or starts a reassembly-procedure. Loose fragments are kept by the
/// adaption-layer itself. When a reassembly-procedure timed out. The gathered
/// fragments will be flushed.
///
/// Eventually, the adaption-layer will enqueue a fully translated IPv6-frame
/// into the IPv6 protocol-queue.
///
/// @returns    void, either the frame is enqueued in the IPv6-protocol queue or
///             the translation failed and the received frame is discarded.
///
void
pico_sixlowpan_receive(struct pico_frame *f);

///
/// Checks whether or not an IPv6-address is derived from a 16-bit short address
///
int
pico_ipv6_is_derived_16(struct pico_ip6 addr);

#endif /* INCLUDE_PICO_SIXLOWPAN */
