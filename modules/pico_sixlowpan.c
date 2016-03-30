/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

//===----------------------------------------------------------------------===//
//  Includes
//===----------------------------------------------------------------------===//

#include "pico_ieee802154.h"
#include "pico_sixlowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "pico_udp.h"

#ifdef PICO_SUPPORT_SIXLOWPAN

//===----------------------------------------------------------------------===//
//  Macros
//===----------------------------------------------------------------------===//

#define DEBUG
#ifdef DEBUG
    #define PAN_DBG(s, ...)         dbg("[6LoWPAN]$ " s, \
                                        ##__VA_ARGS__)
    #define PAN_ERR(s, ...)         dbg("[6LoWPAN]$ ERROR: %s: %d: " s, \
                                        __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define PAN_DBG_C               dbg
#else
    #define PAN_DBG(...)            do {} while(0)
    #define PAN_DBG_C(...)          do {} while(0)
    #define PAN_ERR(...)            do {} while(0)
#endif

//===----------------------------------------------------------------------===//
//  Constants
//===----------------------------------------------------------------------===//



//===----------------------------------------------------------------------===//
//  Type definitions
//===----------------------------------------------------------------------===//

///
/// 6LoWPAN is big endian, IEEE is little endian
///
enum endian
{
    ENDIAN_IEEE = 0,
    ENDIAN_SIXLOWPAN
};

//===----------------------------------------------------------------------===//
//  Global variables
//===----------------------------------------------------------------------===//
static uint8_t buf[IEEE_PHY_MTU];

//===----------------------------------------------------------------------===//
//  Forward declarations
//===----------------------------------------------------------------------===//



//===----------------------------------------------------------------------===//
//  API Functions
//===----------------------------------------------------------------------===//

int pico_sixlowpan_send(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);

    return 0;
}

void pico_sixlowpan_receive(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
}

///
///
///
int pico_ipv6_is_derived_16(struct pico_ip6 addr)
{
    uint8_t *iid = addr.addr + 8;

    /*  IID formed from 16-bit short address [RFC4944]:
     *
     *  +------+------+------+------+------+------+------+------+
     *  |  PAN |  PAN | 0x00 | 0xFF | 0xFE | 0x00 | xxxx | xxxx |
     *  +------+------+------+------+------+------+------+------+
     */

    return ((0x00 == iid[2] && 0xFF == iid[3] && 0xFE == iid[4] && 0x00 == iid[5]) ? 1 : 0);
}

#endif /* PICO_SUPPORT_SIXLOWPAN */

//===----------------------------------------------------------------------===//
//===----------------------------------------------------------------------===//
