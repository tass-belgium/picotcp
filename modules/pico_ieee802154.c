/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_ieee802154.h"
#include "pico_dev_ieee802154.h"
#include "pico_addressing.h"

#ifdef PICO_SUPPORT_IEEE802154

//===----------------------------------------------------------------------===//
//  Macro's
//===----------------------------------------------------------------------===//

/**
 *  Debugging
 */
#define IEEE_DEBUG
#ifdef IEEE_DEBUG
    #define IEEE_DBG(s, ...)    dbg("[IEEE802.15.4]$ INFO: " s, ##__VA_ARGS__)
    #define IEEE_ERR(s, ...)    dbg("[IEEE802.15.4]$ ERROR: %s: %d: " s,  \
                                    __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define IEEE_DBG_C          dbg
#else
    #define IEEE_DBG(...)       (void)
    #define IEEE_DBG_C(...)     (void)
    #define IEEE_ERR(...)       (void)
#endif

/**
 *  Addresses
 */
#define IEEE_AM_SUPPORTED(mode) ((IEEE802154_AM_EXTENDED == (mode) || \
                                 IEEE802154_AM_SHORT == (mode)) ? 1 : 0)

/**
 *  Utilities
 */
#define PICO_SWAP(a, b)         (a) ^= (b);\
                                (b) ^= (b);\
                                (a) ^= (b)

//#define PICO_RPL
#define PICO_IEEE802154_MESH

//===----------------------------------------------------------------------===//
//  Constants
//===----------------------------------------------------------------------===//

// FRAME TYPE DEFINITIONS
#define IEEE_FRAME_TYPE_BEACON      (0u)
#define IEEE_FRAME_TYPE_DATA        (1u)
#define IEEE_FRAME_TYPE_ACK         (2u)
#define IEEE_FRAME_TYPE_COMMAND     (3u)

// FRAME VERSION DEFINITIONS
#define IEEE_FRAME_VERSION_2003     (0u)
#define IEEE_FRAME_VERSION_2006     (1u)

//===----------------------------------------------------------------------===//
//  Type definitions
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  Global variables
//===----------------------------------------------------------------------===//
static uint8_t buf[IEEE802154_PHY_MTU];
static uint8_t payload_offset = 0;

//===----------------------------------------------------------------------===//
//  Forward declarations
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  Link layer addresses
//===----------------------------------------------------------------------===//

static struct pico_ieee802154_addr
ieee802154_ll_src(struct pico_device *dev, struct pico_ip6 src)
{
    struct pico_ieee802154_addr ll_src;

    IGNORE_PARAMETER(dev);
    IGNORE_PARAMETER(src);

    /* TODO: Based on routing or mesh protocol chosen call the apropriate
     * function to derive the link-layer source address from the IPv6 src.
     * it may be desired that source address is updated so it complies to
     * the preferred protocol (e.g. using an extended ll-address instead of
     * short 16-bit address). So we hand over responsibility for this. */

    return ll_src;
}

static struct pico_ieee802154_addr
ieee802154_ll_dst(struct pico_device *dev, struct pico_ip6 dst)
{
    struct pico_ieee802154_addr ll_dst;

    IGNORE_PARAMETER(dev);
    IGNORE_PARAMETER(dst);

    /* TODO: Based on routing or mesh protocol chosen call the apropriate
     * function to derive the link-layer source address from the IPv6 dst.
     * it may be desired that the source address is updated because of routing
     * through a different link-layer host or to comply to the preferred
     * protocol (e.g. using an extend ll-address instead of a short 16-bit
     * address). So we hand over repsonsibility for this */

    return ll_dst;
}

static void
ieee802154_ll_get_pan(struct pico_device *dev, uint16_t *src, uint16_t *dst)
{
    IGNORE_PARAMETER(dev);
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);

    /* TODO: For link-layer meshing we only support intra_pan-messages for now,
     * so the source- and destination- pan are the same and thus are asked for
     * straight to the device since there is where it's decided which PAN to
     * join. */
}

//===----------------------------------------------------------------------===//
//  Frame/
//===----------------------------------------------------------------------===//

static struct pico_ieee802154_hdr *
ieee_mac_hdr(void)
{
    /* Never fails */
    return (struct pico_ieee802154_hdr *)(buf + IEEE802154_SIZE_LEN);
} /* Static path count: 1 */

static int
ieee_mac_dst_size(void)
{
    uint8_t dam = ieee_mac_hdr()->fcf.dam;

    if (!IEEE_AM_SUPPORTED(dam))
        return -1;

    return (int)(IEEE802154_SIZE_PAN + IEEE802154_AM_SIZE(dam));
} /* Static path count: 2 */

static int
ieee_mac_src_size(void)
{
    uint8_t sam = ieee_mac_hdr()->fcf.sam;
    int size = 0;

    if (!IEEE_AM_SUPPORTED(sam)) {
        return -1;
    } else if (!ieee_mac_hdr()->fcf.intra_pan) {
        size = (int)(size + (int)IEEE802154_SIZE_PAN);
    }

    return (int)(size + (int)IEEE802154_AM_SIZE(sam));
} /* Static path count: 3 */

static uint16_t *
ieee_mac_pan_dst(void)
{
    /* Never fails */
    return (uint16_t *)(ieee_mac_hdr()->addresses);
} /* Static path count: 1 */

static uint16_t *
ieee_mac_pan_src(void)
{
    uint8_t *addr = (uint8_t *)ieee_mac_pan_dst();
    int dsize = ieee_mac_dst_size();

    /* Intra-pan frames do not have src pan ID */
    if (dsize < 0 || ieee_mac_hdr()->fcf.intra_pan)
        return NULL;

    return (uint16_t *)(addr + dsize);
} /* Static path count: 2 */

static union pico_ieee802154_addr_u *
ieee_mac_addr_dst(void)
{
    /* Never fails */
    uint8_t *addr = (uint8_t *)ieee_mac_pan_dst();
    return (union pico_ieee802154_addr_u *)(addr + IEEE802154_SIZE_PAN);
}

static union pico_ieee802154_addr_u *
ieee_mac_addr_src(void)
{
    uint8_t *addr = (uint8_t *)ieee_mac_pan_dst();
    int dsize = ieee_mac_dst_size();

    /* Could we determine sizeof dst fields */
    if (dsize < 0) {
        return NULL;
    } else if (ieee_mac_hdr()->fcf.intra_pan) {
        addr = (uint8_t *)(addr + IEEE802154_SIZE_PAN);
    }

    return (union pico_ieee802154_addr_u *)(addr + dsize);
} /* Static path count: 3 */

static uint8_t *
ieee_frame_payload(void)
{
    uint8_t *ptr = (uint8_t *)ieee_mac_addr_src();
    int ssize = ieee_mac_src_size();

    if (!ptr || (ssize < 0))
        return NULL;

    return (uint8_t *)(ptr + ssize + payload_offset);
} /* Static path count */

static void
ieee_frame_init(void)
{
    memset(buf, 0, IEEE802154_PHY_MTU);
    buf[0] = (uint8_t)(IEEE802154_SIZE_LEN + IEEE802154_SIZE_FCS);
    payload_offset = 0;
} /* Static path count: 1 */

//===----------------------------------------------------------------------===//
//  Addresses
//===----------------------------------------------------------------------===//

static int
ieee_addr_short_cmp(struct pico_ieee802154_addr_short *a,
                    struct pico_ieee802154_addr_short *b)
{
    return (int)((int)a->addr - (int)b->addr);
} /* Static path count: 1 */

static int
ieee_addr_ext_cmp(struct pico_ieee802154_addr_ext *a,
                  struct pico_ieee802154_addr_ext *b)
{
    return (int)(memcmp(b->addr, a->addr, PICO_SIZE_IEEE802154_EXT));
} /* static path count: 1 */

static void
ieee_addr_ext_to_le(struct pico_ieee802154_addr_ext *addr)
{
    PICO_SWAP(addr->addr[0], addr->addr[7]);
    PICO_SWAP(addr->addr[1], addr->addr[6]);
    PICO_SWAP(addr->addr[2], addr->addr[5]);
    PICO_SWAP(addr->addr[3], addr->addr[4]);
} /* Static path count: 1 */

static void
ieee_addr_to_le(struct pico_ieee802154_addr *addr)
{
    if (IEEE802154_AM_SHORT == addr->mode) {
#ifdef PICO_BIGENDIAN
        /* Only if the stack is compiled against big-endian */
        addr->addr._short.addr = short_be(addr->addr._short.addr);
#endif
        /* If the stack is compiled against little endian, nothing needs to be
         * done for native types */
    } else if (IEEE802154_AM_EXTENDED == addr->mode) {
        ieee_addr_ext_to_le(&(addr->addr._ext));
    } else {
        /* Do nothing, don't want to scramble others' data */
    }
} /* Static path count: 3 */

static void
ieee_addr_to_host(struct pico_ieee802154_addr *addr)
{
    ieee_addr_to_le(addr);
} /* Static path count: 1 */

static void
ieee_mac_get_addresses(struct pico_ieee802154_addr *src,
                       struct pico_ieee802154_addr *dst)
{
    src->mode = ieee_mac_hdr()->fcf.sam;
    src->addr = *ieee_mac_addr_src();
    ieee_addr_to_host(src);

    dst->mode = ieee_mac_hdr()->fcf.dam;
    dst->addr = *ieee_mac_addr_dst();
    ieee_addr_to_host(dst);
} /* Static path count: 1 */

static int
ieee_mac_set_addresses(struct pico_ieee802154_addr src,
                       struct pico_ieee802154_addr dst,
                       uint16_t src_pan,
                       uint16_t dst_pan)
{
    uint8_t *src_ptr = NULL, *dst_ptr = NULL;

    if (IEEE_AM_SUPPORTED(src.mode) && IEEE_AM_SUPPORTED(dst.mode))
        return -1;

    /* First set destination fields */
#ifdef PICO_BIGENDIAN
    *ieee_mac_pan_dst() = short_be(dst_pan);
#else
    *ieee_mac_pan_dst() = dst_pan;
#endif

    /* The destination address itself */
    ieee_addr_to_le(&dst);
    dst_ptr = (uint8_t *)ieee_mac_addr_dst();
    memcpy(dst_ptr, (void *)&(dst.addr), IEEE802154_AM_SIZE(dst.mode));

    /* Now set the source fields */
    if (src_pan == dst_pan) {
        ieee_mac_hdr()->fcf.intra_pan = 1;
    } else {
#ifdef PICO_BIGENDIAN
        *ieee_mac_pan_src() = short_be(src_pan);
#else
        *ieee_mac_pan_src() = src_pan;
#endif
    }

    /* Finally the source address */
    ieee_addr_to_le(&src);
    src_ptr = (uint8_t *)ieee_mac_addr_src();
    memcpy(src_ptr, (void *)&(dst.addr), IEEE802154_AM_SIZE(src.mode));

    return 0;
} /* Static path count: 4 */

//===----------------------------------------------------------------------===//
//  Header
//===----------------------------------------------------------------------===//
static int
ieee_mac_hdr_size(void)
{
    uint8_t *payload = ieee_frame_payload();

    if (!payload)
        return -1;

    return (int)((void *)payload - (void *)(ieee_mac_hdr()));
} /* Static path count: 2 */

/**
 *  Initialises the MAC Header and returns the amount still available for
 *  payload
 */
static int
ieee_mac_hdr_init(struct pico_ieee802154_addr src,
                  struct pico_ieee802154_addr dst,
                  uint16_t src_pan,
                  uint16_t dst_pan)
{
    struct pico_ieee802154_fcf *fcf = &(ieee_mac_hdr()->fcf);
    int mhr_size = 0;

    fcf->frame_type = IEEE_FRAME_TYPE_DATA;
    fcf->security_enabled = 0;
    fcf->frame_pending = 0;
    fcf->ack_required = 0;
    fcf->frame_version = IEEE_FRAME_VERSION_2003;

    if (ieee_mac_set_addresses(src, dst, src_pan, dst_pan)) {
        IEEE_ERR("Failed setting IEEE8021.15.4 addresses in header\n");
        return -1;
    } else {
        if ((mhr_size = ieee_mac_hdr_size() < 0)) {
            IEEE_ERR("Failed calculating IEEE8021.15.4 MAC header size\n");
            return -1;
        }
    }

    return (int)((int)IEEE802154_SIZE_FCS + mhr_size);
} /* Static path count: 3 */

static int
ieee802154_ll_out(struct pico_device *dev, struct pico_ip6 src, struct pico_ip6 dst)
{
    struct pico_ieee802154_addr llsrc;
    struct pico_ieee802154_addr lldst;
    uint16_t src_pan = 0, dst_pan = 0;

    pico_err = PICO_ERR_NOERR;

    llsrc = ieee802154_ll_src(dev, src);
    if (PICO_ERR_EHOSTUNREACH == pico_err)
        return -1;

    lldst = ieee802154_ll_dst(dev, dst);
    if (PICO_ERR_EHOSTUNREACH == pico_err)
        return -1;

    ieee802154_ll_get_pan(dev, &src_pan, &dst_pan);

    return ieee_mac_hdr_init(llsrc, lldst, src_pan, dst_pan);
}

//===----------------------------------------------------------------------===//
//  API Functions
//===----------------------------------------------------------------------===//

/**
 *  Receives a frame from the device and prepares it for higher layers.
 */
void
pico_ieee802154_receive(struct pico_frame *f)
{
    (void)f;
}

/**
 *  Sends a buffer through IEEE802.15.4 encapsulation to the device.
 *  Return -1 when an error occured, 0 when the frame was transmitted
 *  successfully or 'ret > 0' to indicate that the provided buffer was to large
 *  to fit inside the IEEE802.15.4 frame after providing the MAC header with
 *  addresses and possibly a security header. Calls dev->send() finally.
 */
int
pico_ieee802154_send(struct pico_device *dev,
                     struct pico_ip6 src,
                     struct pico_ip6 dst,
                     uint8_t *payload,
                     uint8_t len)
{
    int available = IEEE802154_MAC_MTU, ret = 0;

    ieee_frame_init();

    /* First, do everything regarding the IEEE802.15.4-frame, that is setting
     * the header, filling the addresses, etc.
     */
    ret = ieee802154_ll_out(dev, src, dst);
    if (ret < 0) {
        IEEE_ERR("Could not initialise IEEE802.15.4 header\n");
        return ret;
    } else {
        /* Do not update payload_offset, can be calculated */
        available -= ret;

        /* TODO: Now would be a good time to provide an auxiliary security
         * header in the payload section, after which the available bytes
         * have to be decreased */
#ifdef PICO_SUPPORT_LL_SECURITY
        ret = pico_ll_security_out(ieee_frame_payload(), dev);
        if (ret < 0) {
            IEEE_ERR("Link Layer Security failed prepping frame for tx.\n");
            return ret;
        } else {
            available -= ret;
            payload_offset = (uint8_t)(payload_offset + ret);
        }
#endif

        /* TODO: Now has the time come to prepend DISPATCH_MESH and/or
         * DISPATCH_BC0 header but to do so we pass the frame to our link-layer
         * mesh-protocols module. */
#ifdef PICO_SUPPORT_LL_MESH
        ret = pico_ll_mesh_out(ieee_frame_payload(), llsrc, lldst);
        if (ret < 0) {
            IEEE_ERR("Link Layer Mesh failed prepping frame for tx.\n");
            return ret;
        } else {
            available -= ret;
            payload_offset = (uint8_t)(payload_offset + ret);
        }
#endif

        /* Check if the payload would fit if we copied it in, if it doesn't
         * don't bother continue transmitting the frame and return available
         * bytes so 6LoWPAN knows how many bytes it has available for
         * fragmentation */
        if (available < len)
            return available;

        /* Copy in payload data provided by 6LoWPAN */
        memcpy((uint8_t *)ieee_frame_payload(), payload, len);
        buf[0] = (uint8_t)(buf[0] + ieee_mac_hdr_size() + len);
    }

    /* Return 0 when transmission was succesfull, that is send() > 0 */
    return (dev->send(dev, buf, (int)buf[0]) <= 0);
} /* Static path count: 9 */

/**
 *  Compares 2 IEEE802.15.4 addresses. Takes extended and short addresses into
 *  account.
 */
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
        return ieee_addr_short_cmp(&(a->addr._short), &(b->addr._short));
    } else if (IEEE802154_AM_EXTENDED == a->mode) {
        /* Compare extended addresses if both are */
        return ieee_addr_ext_cmp(&(a->addr._ext), &(b->addr._ext));
    }

    return 0;
} /* Static path count: 4 */

#endif /* PICO_SUPPORT_IEEE802154 */
