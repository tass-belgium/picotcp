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
/// Compares 2 IEEE802.15.4 addresses. Takes extended and short address into
/// account.
///
/// TODO: Test properly
/// TODO: Decrease static path count
int pico_ieee802154_addr_cmp(void *va, void *vb)
{
    struct pico_ieee_addr *a = (struct pico_ieee_addr *)va;
    struct pico_ieee_addr *b = (struct pico_ieee_addr *)vb;
    uint8_t aam = IEEE_AM_NONE, bam = IEEE_AM_NONE;
    int ret = 0;

    if (!a || !b) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Don't want to compare with AM_BOTH, convert to short if address has AM_BOTH */
    aam = a->_mode;
    bam = b->_mode;
    if (IEEE_AM_BOTH == aam && IEEE_AM_BOTH == bam) {
        /* Only need to compare short address */
        aam = IEEE_AM_SHORT;
        bam = IEEE_AM_SHORT;
    } else if (IEEE_AM_BOTH == aam && IEEE_AM_BOTH != bam) {
        /* A has both, compare only the address of A that B has as well */
        aam = bam;
    } else if (IEEE_AM_BOTH == bam && IEEE_AM_BOTH != aam) {
        /* B has both, compare only the address of B that A has as well */
        bam = aam;
    }

    /* Only check for either short address of extended address */
    if (aam != bam)
        return (int)((int)a->_mode - (int)b->_mode);

    /* Check for short if both modes are short */
    if ((IEEE_AM_SHORT == a->_mode) && (a->_short.addr != b->_short.addr))
        return (int)((int)a->_short.addr - (int)b->_short.addr);

    /* Check for extend if both mode are extended */
    if (IEEE_AM_EXTENDED == a->_mode && (ret = memcmp(a->_ext.addr, b->_ext.addr, PICO_SIZE_IEEE_EXT)))
        return ret;

    return 0;
} /* Static path count: 48 */

#endif /* PICO_SUPPORT_IEEE802154 */
