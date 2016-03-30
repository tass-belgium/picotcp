/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_ieee802154.h"
#include "pico_addressing.h"

#ifdef PICO_SUPPORT_IEEE802154

//===----------------------------------------------------------------------===//
//  API Functions
//===----------------------------------------------------------------------===//

///
/// Compares 2 IEEE802.15.4 16-bit short addresses.
///
/// TODO: Test properly
static int pico_ieee802154_addr_short_cmp(struct pico_ieee802154_addr_short *a,
                                          struct pico_ieee802154_addr_short *b)
{
    return (int)((int)a->addr - (int)b->addr);
} /* Static path count: 1 */

///
/// Compares 2 IEEE802.15.4 64-bit extended addresses.
///
/// TODO: Test properly
static int pico_ieee802154_addr_ext_cmp(struct pico_ieee802154_addr_ext *a,
                                        struct pico_ieee802154_addr_ext *b)
{
    return (int)(memcmp(b->addr, a->addr, PICO_SIZE_IEEE802154_EXT));
} /* static path count: 1 */

///
/// Compares 2 IEEE802.15.4 addresses. Takes extended and short address into
/// account.
///
/// TODO: Test properly
int pico_ieee802154_addr_cmp(void *va, void *vb)
{
    struct pico_ieee802154_addr *a = (struct pico_ieee802154_addr *)va;
    struct pico_ieee802154_addr *b = (struct pico_ieee802154_addr *)vb;
    uint8_t aam = a->mode, bam = b->mode;

    if (aam != bam) {
        /* Comparison on modes */
        return (int)((int)a->mode - (int)b->mode);
    } else if (IEEE802154_AM_SHORT == a->mode) {
        /* Compare short addresses if both are */
        return pico_ieee802154_addr_short_cmp(&(a->addr._short),
                                              &(b->addr._short));
    } else if (IEEE802154_AM_EXTENDED == a->mode) {
        /* Compare extended addresses if both are */
        return pico_ieee802154_addr_ext_cmp(&(a->addr._ext),
                                            &(b->addr._ext));
    }

    return 0;
} /* Static path count: 4 */

#endif /* PICO_SUPPORT_IEEE802154 */
