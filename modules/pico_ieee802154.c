/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_ieee802154.h"
#include "pico_addressing.h"

#ifdef PICO_SUPPORT_IEEE802154

//===----------------------------------------------------------------------===//
//  Macro's
//===----------------------------------------------------------------------===//

#define IEEE_DEBUG
#ifdef IEEE_DEBUG
    #define IEEE_DBG(s, ...)         dbg("[IEEE802.15.4]$ INFO: " s,           \
                                        ##__VA_ARGS__)
    #define IEEE_ERR(s, ...)         dbg("[IEEE802.15.4]$ ERROR: %s: %d: " s,  \
                                        __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define IEEE_DBG_C               dbg
#else
    #define IEEE_DBG(...)            do {} while(0)
    #define IEEE_DBG_C(...)          do {} while(0)
    #define IEEE_ERR(...)            do {} while(0)
#endif

//===----------------------------------------------------------------------===//
//  Addresses
//===----------------------------------------------------------------------===//

///
/// Compares 2 IEEE802.15.4 16-bit short addresses.
///
static int
pico_ieee802154_addr_short_cmp(struct pico_ieee802154_addr_short *a,
                               struct pico_ieee802154_addr_short *b)
{
    return (int)((int)a->addr - (int)b->addr);
} /* Static path count: 1 */

///
/// Compares 2 IEEE802.15.4 64-bit extended addresses.
///
static int
pico_ieee802154_addr_ext_cmp(struct pico_ieee802154_addr_ext *a,
                             struct pico_ieee802154_addr_ext *b)
{
    return (int)(memcmp(b->addr, a->addr, PICO_SIZE_IEEE802154_EXT));
} /* static path count: 1 */

///
/// Converts an IEEE802.15.4 64-bit extended address from host order to
/// IEEE-endianness, that is little-endian.
///
static void
pico_ieee802154_addr_ext_to_le(struct pico_ieee802154_addr_ext *addr)
{
    uint8_t i = 0, temp = 0;

    for (i = 0; i < 4; i++) {
        temp = addr->addr[i];
        addr->addr[i] = addr->addr[8 - (i + 1)];
        addr->addr[8 - (i + 1)] = temp;
    }
} /* Static path count: 1 */

///
/// Get a pico-compatible IEEE802.15.4-address structure from a flat buffer
/// chunk.
///
/// TODO: properly test
static struct pico_ieee802154_addr
pico_ieee802154_addr_get_from_buf(uint8_t *buf, uint8_t address_mode)
{
    struct pico_ieee802154_addr addr;

    /* Copy from buf for length defined by address mode */
    memcpy(addr.addr._ext.addr, buf, PICO_IEEE802154_AM_SIZE(address_mode));

    /* Convert to host endianness */
    pico_ieee802154_addr_to_host(&addr);

    return addr;
} /* Static path count: 1 */

///
/// Fill a buffer with a pico-compatible IEEE802.15.4-address structure.
///
/// TODO: Properly test
static void
pico_ieee802154_addr_set_in_buf(uint8_t *buf, struct pico_ieee802154_addr addr)
{
    /* First convert to IEEE endianness, that is little endian */
    pico_ieee802154_addr_to_le(&addr);

    /* Copy from address into buf for length defined by address mode */
    memcpy(buf, addr.addr._ext.addr, PICO_IEEE802154_AM_SIZE(addr.mode));
} /* Static path count: 1 */

///
/// Get the IEEE802.15.4 source address from a IEEE802.15.4 frame.
/// Fails when the address mode of the destination is not properly set.
///
/// TODO: Properly test
static struct pico_ieee802154_addr
pico_ieee802154_addr_get_src(struct pico_ieee802154_frame *frame)
{
    uint8_t *src = frame->hdr->addresses +
        PICO_IEEE802154_AM_SIZE(frame->hdr->fcf.dam);

    return pico_ieee802154_addr_get_from_buf(src, frame->hdr->fcf.sam);
} /* Static path count: 1 */

///
/// Get the IEEE802.15.4 destination address from a IEEE802.15.4 frame.
/// Never fails since it's the first address in the header.
///
/// TODO: Properly test
static struct pico_ieee802154_addr
pico_ieee802154_addr_get_dst(struct pico_ieee802154_frame *frame)
{
    uint8_t *dst = frame->hdr->addresses;

    return pico_ieee802154_addr_get_from_buf(dst, frame->hdr->fcf.dam);
} /* Static path count: 1 */

///
/// Set the IEEE802.15.4 source address in a IEEE802.15.4 frame.
/// Fails when the address mode of the destination is not properly set.
///
/// TODO: Properly test
static void
pico_ieee802154_addr_set_src(struct pico_ieee802154_frame *frame,
                             struct pico_ieee802154_addr src)
{
    uint8_t *ptr = frame->hdr->addresses +
        PICO_IEEE802154_AM_SIZE(frame->hdr->fcf.dam);

    pico_ieee802154_addr_set_in_buf(ptr, src);
} /* Static path count: 1 */

///
/// Set the IEEE802.15.4 destination address in a IEEE802.15.4 frame.
/// Never fails since it's the first address in the header.
///
/// TODO: Properly test
static void
pico_ieee802154_addr_set_dst(struct pico_ieee802154_frame *frame,
                             struct pico_ieee802154_addr dst)
{
    uint8_t *ptr = frame->hdr->addresses;

    pico_ieee802154_addr_set_in_buf(ptr, dst);
} /* Static path count: 1 */

//===----------------------------------------------------------------------===//
//  Header
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  Frame
//===----------------------------------------------------------------------===//


//===----------------------------------------------------------------------===//
//  API Functions
//===----------------------------------------------------------------------===//

///
/// Compares 2 IEEE802.15.4 addresses. Takes extended and short addresses into
/// account.
///
int
pico_ieee802154_addr_cmp(void *va, void *vb)
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

///
/// Converts an IEEE802.15.4 address from host order to IEEE-endianness, that is
/// little-endian. Takes extended and short addresses into account.
///
void
pico_ieee802154_addr_to_le(struct pico_ieee802154_addr *addr)
{
    if (IEEE802154_AM_SHORT == addr->mode) {
#ifdef PICO_BIGENDIAN
        /* Only if the stack is compiled against big-endian */
        addr->addr._short.addr = short_be(addr->addr._short.addr);
#endif
        /* If the stack is compiled against little endian, nothing needs to be
         * done for native types */
    } else if (IEEE802154_AM_EXTENDED == addr->mode) {
        pico_ieee802154_addr_ext_to_le(&(addr->addr._ext));
    } else {
        /* Do nothing, don't want to scramble others' data */
    }
} /* Static path count: 3 */

///
/// Converts an IEEE802.15.4 address from IEEE-endianness, that is little-endian
/// to host endianness. Takes extended and short addresses into account.
///
void
pico_ieee802154_addr_to_host(struct pico_ieee802154_addr *addr)
{
    pico_ieee802154_addr_to_le(addr);
}

#endif /* PICO_SUPPORT_IEEE802154 */
