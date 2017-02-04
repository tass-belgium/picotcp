/*********************************************************************
 PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_802154.h"
#include "pico_6lowpan.h"
#include "pico_protocol.h"
#include "pico_addressing.h"
#include "pico_6lowpan_ll.h"

#ifdef PICO_SUPPORT_802154

/*******************************************************************************
 * Macros
 ******************************************************************************/

#define PICO_802154_VALID(am)  ((am) == 2 || (am) == 3 ? 1 : 0)

/*******************************************************************************
 * Constants
 ******************************************************************************/

/* Frame type definitions */
#define FCF_TYPE_BEACON       (short_be(0x0000u))
#define FCF_TYPE_DATA         (short_be(0x0001u))
#define FCF_TYPE_ACK          (short_be(0x0002u))
#define FCF_TYPE_CMD          (short_be(0x0003u))

/* Frame version definitions */
#define FCF_VER_2003          (short_be(0x0000u))
#define FCF_VER_2006          (short_be(0x1000u))
#define FCF_SEC               (short_be(0x0008u))
#define FCF_NO_SEC            (short_be(0x0000u))
#define FCF_PENDING           (short_be(0x0010u))
#define FCF_NO_PENDING        (short_be(0x0000u))
#define FCF_ACK_REQ           (short_be(0x0020u))
#define FCF_NO_ACK_REQ        (short_be(0x0000u))
#define FCF_INTRA_PAN         (short_be(0x0040u))
#define FCF_INTER_PAN         (short_be(0x0000u))

/* Commonly used addresses */
#define ADDR_802154_BCAST     (short_be(0xFFFFu))
#define ADDR_802154_UNSPEC    (short_be(0xFFFEu))

#ifndef PICO_6LOWPAN_NOMAC

/*******************************************************************************
 *  ENDIANNESS
 ******************************************************************************/

/* Swaps the two 8-bit values, the pointer A and B point at */
static void pico_swap(uint8_t *a, uint8_t *b)
{
    *a = *a ^ *b;
    *b = *a ^ *b;
    *a = *a ^ *b;
}

/* Converts an IEEE802.15.4 address, which is little endian by standard, to
 * IETF-endianness, which is big endian. */
static void
addr_802154_to_ietf(struct pico_802154 *addr)
{
    int32_t i = 0;
    int32_t end = SIZE_6LOWPAN(addr->mode) - 1;
    for (i = 0; i < (int32_t)((uint8_t)SIZE_6LOWPAN(addr->mode) >> 1); i++) {
        pico_swap(&addr->addr.data[i], &addr->addr.data[end - i]);
    }
}

/* Converts an IEE802.15.4 address in IETF format, which is used to form the IID
 * of the host's IPv6 addresses, back to IEEE-endianess, which is little
 * endian. */
static void
addr_802154_to_ieee(struct pico_802154 *addr)
{
    addr_802154_to_ietf(addr);
}

/*******************************************************************************
 *  FRAME
 ******************************************************************************/

/* Retrieves the addressing mode of the destination address from the MHR's frame
 * control field. */
static uint8_t
dst_am(struct pico_802154_hdr *hdr)
{
    return (uint8_t)((hdr->fcf >> 10) & 0x3);
}

/* Retrieves the addressing mode of the source address from the MHR's frame
 * control field */
static uint8_t
src_am(struct pico_802154_hdr *hdr)
{
    return (uint8_t)((hdr->fcf >> 14) & 0x3);
}

/* Determines the size of an IEEE802.15.4-header, based on the addressing
 * modes */
static uint8_t
frame_802154_hdr_len(struct pico_802154_hdr *hdr)
{
    return (uint8_t)(SIZE_802154_MHR_MIN + SIZE_6LOWPAN(src_am(hdr)) + SIZE_6LOWPAN(dst_am(hdr)));
}

/* Gets the source address out of a mapped IEEE802.15.4-frame, converts it
 * to host endianess */
static struct pico_802154
frame_802154_src(struct pico_802154_hdr *hdr)
{
    struct pico_802154 src = { .addr.data = { 0 }, .mode = src_am(hdr) };
    uint8_t *addresses = (uint8_t *)hdr + sizeof(struct pico_802154_hdr);
    uint16_t len = SIZE_6LOWPAN(src.mode);
    memcpy(src.addr.data, addresses + SIZE_6LOWPAN(dst_am(hdr)), len);
    addr_802154_to_ietf(&src);
    return src;
}

/* Gets the destination address out of a mapped IEEE802.15.4-frame, converts
 * it to host endianess */
static struct pico_802154
frame_802154_dst(struct pico_802154_hdr *hdr)
{
    struct pico_802154 dst = { .addr.data = { 0 }, .mode = dst_am(hdr) };
    uint8_t *addresses = (uint8_t *)hdr + sizeof(struct pico_802154_hdr);
    uint16_t len = SIZE_6LOWPAN(dst.mode);
    memcpy(dst.addr.data, addresses, len);
    addr_802154_to_ietf(&dst);
    return dst;
}

/* Maps a 802.15.4 frame structure onto a flat buffer, fills in the entire
 * header and set the payload pointer right after the MHR. */
static void
frame_802154_format(uint8_t *buf, uint8_t seq, uint16_t intra_pan, uint16_t ack,
                    uint16_t sec, struct pico_6lowpan_short pan, struct pico_802154 src,
                    struct pico_802154 dst)
{
    uint8_t *addresses = (uint8_t *)(buf + sizeof(struct pico_802154_hdr));
    struct pico_802154_hdr *hdr = (struct pico_802154_hdr *)buf;
    uint16_t sam = 0, dam = 0;

    hdr->fcf = 0; /* Clear out control field */
    intra_pan = (uint16_t)(intra_pan & FCF_INTRA_PAN);
    ack = (uint16_t)(ack & FCF_ACK_REQ);
    sec = (uint16_t)(sec & FCF_SEC);
    dam = short_be((uint16_t)(dst.mode << 10));
    sam = short_be((uint16_t)(src.mode << 14));

    /* Fill in frame control field */
    hdr->fcf |= (uint16_t)(FCF_TYPE_DATA | sec );
    hdr->fcf |= (uint16_t)(FCF_NO_PENDING | ack);
    hdr->fcf |= (uint16_t)(intra_pan | dam | FCF_VER_2003);
    hdr->fcf |= (uint16_t)(sam);
    hdr->fcf = short_be(hdr->fcf); // Convert to IEEE endianness

    hdr->seq = seq; // Sequence number

    /* Convert addresses to IEEE-endianness */
    pan.addr = short_be(pan.addr);
    addr_802154_to_ieee(&src);
    addr_802154_to_ieee(&dst);

    /* Fill in the addresses */
    memcpy(&hdr->pan_id, &pan.addr, SIZE_6LOWPAN_SHORT);
    memcpy(addresses, dst.addr.data, SIZE_6LOWPAN(dst.mode));
    memcpy(addresses + SIZE_6LOWPAN(dst.mode), src.addr.data,SIZE_6LOWPAN(src.mode));
}

#endif /* PICO_6LOWPAN_NOMAC */

/* Removes the IEEE802.15.4 MAC header before the frame */
static int32_t
pico_802154_process_in(struct pico_frame *f)
{
#ifndef PICO_6LOWPAN_NOMAC
    struct pico_802154_hdr *hdr = (struct pico_802154_hdr *)f->net_hdr;
    uint16_t fcf = short_be(hdr->fcf);
    uint8_t hlen = 0;
    f->src.pan = frame_802154_src(hdr);
    f->dst.pan = frame_802154_dst(hdr);

    /* I claim the datalink header */
    f->datalink_hdr = f->net_hdr;

    if (fcf & FCF_SEC) {
        f->flags |= PICO_FRAME_FLAG_LL_SEC;
    }

    hlen = frame_802154_hdr_len(hdr);

    /* XXX: Generic procedure to move forward in incoming processing function
     * is updating the net_hdr-pointer */
    f->net_hdr = f->datalink_hdr + (int32_t)hlen;

    return (int32_t)hlen;
#else
    IGNORE_PARAMETER(f);
    return 0;
#endif
}

/* Prepends the IEEE802.15.4 MAC header before the frame */
static int32_t
pico_802154_process_out(struct pico_frame *f)
{
#ifndef PICO_6LOWPAN_NOMAC
    int32_t len = (int32_t)(SIZE_802154_MHR_MIN + SIZE_6LOWPAN(f->dst.pan.mode) + SIZE_6LOWPAN(f->src.pan.mode));
    uint8_t sec = (uint8_t)((f->flags & PICO_FRAME_FLAG_LL_SEC) ? (FCF_SEC) : (FCF_NO_SEC));
    struct pico_6lowpan_info *info = (struct pico_6lowpan_info *)f->dev->eth;
    uint16_t headroom = (uint16_t)(f->net_hdr - f->buffer);
    static uint8_t seq = 0;
    uint32_t grow = 0;
    int32_t ret = 0;

    if (headroom < (uint16_t)len) { /* Check if there's enough headroom to prepend 802.15.4 header */
        grow = (uint32_t)(len - headroom);
        ret = pico_frame_grow_head(f, (uint32_t)(f->buffer_len + grow));
        if (ret) {
            pico_frame_discard(f);
            return -1;
        }
    }

    /* XXX: General procedure to seek backward in an outgoing processing function
     * is to update the datalink_hdr */
    f->datalink_hdr = f->datalink_hdr - len;

    /* Format the IEEE802.15.4 header */
    frame_802154_format(f->datalink_hdr, seq++, FCF_INTRA_PAN, FCF_NO_ACK_REQ, sec, info->pan_id, f->src.pan, f->dst.pan);
    return len;
#else
    IGNORE_PARAMETER(f);
    return 0;
#endif
}

/* Get the EUI-64 of the device in a structured form */
static struct pico_802154
addr_802154_ext_dev(struct pico_6lowpan_info *info)
{
    struct pico_802154 addr;
    memcpy(addr.addr.data, info->addr_ext.addr, SIZE_6LOWPAN_EXT);
    addr.mode = AM_6LOWPAN_EXT;
    return addr;
}

/* Get the short address of the device in a structured form */
static struct pico_802154
addr_802154_short_dev(struct pico_6lowpan_info *info)
{
    struct pico_802154 addr;
    memcpy(addr.addr.data, (uint8_t *)&(info->addr_short.addr), SIZE_6LOWPAN_SHORT);
    addr.mode = AM_6LOWPAN_SHORT;
    return addr;
}

/* Based on the source IPv6-address, this function derives the link layer source
 * address */
static struct pico_802154
addr_802154_ll_src(struct pico_frame *f)
{
    struct pico_ip6 src = ((struct pico_ipv6_hdr *)f->net_hdr)->src;
    if (IID_16(&src.addr[8])) {
        /* IPv6 source is derived from the device's short address, use that
         * short address so decompressor can derive the IPv6 source from
         * the encapsulating header */
        return addr_802154_short_dev((struct pico_6lowpan_info *)f->dev->eth);
    } else {
        /* IPv6 source is derived from the device's extended address, use
         * the device's extended address so */
        return addr_802154_ext_dev((struct pico_6lowpan_info *)f->dev->eth);
    }
}

/* Based on the destination IPv6-address, this function derives the link layer
 * destination address */
static struct pico_802154
addr_802154_ll_dst(struct pico_frame *f)
{
    struct pico_ip6 dst = ((struct pico_ipv6_hdr *)f->net_hdr)->dst;
    struct pico_802154 addr = { .addr.data = { 0 }, .mode = 0 };
    addr.mode = AM_6LOWPAN_NONE;

    /* If the address is multicast use 802.15.4 BCAST address 0xFFFF */
    if (pico_ipv6_is_multicast(dst.addr)) {
        addr.addr._short.addr = short_be(ADDR_802154_BCAST);
        addr.mode = AM_6LOWPAN_SHORT;
    }
    /* If the address is link local derive the link layer address from the IID */
    else { // if (pico_ipv6_is_linklocal(dst.addr)) {
        if (IID_16(&dst.addr[8])) {
            addr.addr.data[0] = dst.addr[14];
            addr.addr.data[1] = dst.addr[15];
            addr.mode = AM_6LOWPAN_SHORT;
        } else {
            memcpy(addr.addr.data, &dst.addr[8], SIZE_6LOWPAN_EXT);
            addr.addr.data[0] = (uint8_t)(addr.addr.data[0] ^ 0x02);
            addr.mode = AM_6LOWPAN_EXT;
        }
    }
/*
    else {
        struct pico_802154 *n = (struct pico_802154 *)pico_ipv6_get_neighbor(f);
        if (n) {
            memcpy(addr.addr.data, n->addr.data, SIZE_6LOWPAN(n->mode));
            addr.mode = n->mode;
        } else {
            pico_ipv6_nd_postpone(f);
        }
    }
*/
    return addr;
}

/* Estimates the size the MAC header would be based on the source and destination
 * link layer address */
static int32_t
pico_802154_estimator(struct pico_frame *f)
{
    return (int32_t)(SIZE_802154_MHR_MIN + SIZE_6LOWPAN(f->src.pan.mode) + SIZE_6LOWPAN(f->dst.pan.mode) + f->dev->overhead);
}

/* Retrieve address from temporarily flat buffer */
static int32_t
addr_802154_from_buf(union pico_ll_addr *addr, uint8_t *buf)
{
    uint8_t len = (uint8_t)*buf++;

    if (len > 8) // OOB check
        return -1;

    memcpy(addr->pan.addr.data, buf, len);
    if (SIZE_6LOWPAN_EXT == len)
        addr->pan.mode = AM_6LOWPAN_EXT;
    else if (SIZE_6LOWPAN_SHORT == len)
        addr->pan.mode = AM_6LOWPAN_SHORT;
    else
        addr->pan.mode = AM_6LOWPAN_NONE;

    return 0;
}

/* If 'dest' is not set, this function will get the link layer address for a
 * certain source IPv6 address, if 'dest' is set it will get it for the a
 * destination address */
static int32_t
addr_802154_from_net(union pico_ll_addr *addr, struct pico_frame *f, int32_t dest)
{
    if (dest) {
        addr->pan = addr_802154_ll_dst(f);
    } else {
        addr->pan = addr_802154_ll_src(f);
    }
    return 0;
}

/* Determines the length of an IEEE802.15.4 address */
static int32_t
addr_802154_len(union pico_ll_addr *addr)
{
    return SIZE_6LOWPAN(addr->pan.mode);
}

/* Compares 2 IEE802.15.4 addresses */
static int32_t
addr_802154_cmp(union pico_ll_addr *a, union pico_ll_addr *b)
{
    if (a->pan.mode != b->pan.mode) {
        return (int32_t)((int32_t)a->pan.mode - (int32_t)b->pan.mode);
    } else {
        return memcmp(a->pan.addr.data, b->pan.addr.data, SIZE_6LOWPAN(b->pan.mode));
    }
}

/* Derive an IPv6 IID from an IEEE802.15.4 address */
static int32_t
addr_802154_iid(uint8_t iid[8], union pico_ll_addr *addr)
{
    uint8_t buf[8] = {0,0,0,0xff,0xfe,0,0,0};
    struct pico_802154 pan = addr->pan;

    if (AM_6LOWPAN_SHORT == pan.mode) {
        buf[6] = (uint8_t)(pan.addr._short.addr);
        buf[7] = (uint8_t)(pan.addr._short.addr >> 8);
    } else if (AM_6LOWPAN_EXT == pan.mode) {
        memcpy(buf, pan.addr.data, SIZE_6LOWPAN_EXT);
        buf[0] ^= (uint8_t)0x02;
    } else {
        return -1;
    }

    memcpy(iid, buf, 8);
    return 0;
}

/*
 *  Allocates a pico_frame but makes sure the network-buffer starts on an 4-byte aligned address,
 *  this is required by upper layer of the stack. IEEE802.15.4's header isn't necessarily 4/8-byte
 *  aligned since the minimum size of an IEEE802.15.4 header is '5'. The datalink header therefore
 *  might not (and most probably isn't) aligned on an aligned address. The datalink header will of
 *  the size passed in 'headroom'
 *
 *  @param size         Size of the actual frame provided for network-layer and above
 *  @param headroom     Size of the headroom for datalink-buffer
 *  @param overhead     Size of the overhead to keep for the device driver
 *
 *  @return struct pico_frame *, returns the allocated frame upon success, 'NULL' otherwise.
 */
static struct pico_frame *
pico_frame_alloc_with_headroom(uint16_t size, uint16_t headroom, uint16_t overhead)
{
    int network_offset = (((headroom + overhead) >> 2) + 1) << 2; // Sufficient headroom for alignment
    struct pico_frame *f = pico_frame_alloc((uint32_t)(size + network_offset));

    if (!f)
        return NULL;

    f->net_hdr = f->buffer + network_offset;
    f->datalink_hdr = f->net_hdr - headroom;
    return f;
}

/* Allocates a frame with the maximum MAC header size + device's overhead-parameter since this is
 * the lowest level of the frame allocation chain */
static struct pico_frame *
pico_802154_frame_alloc(struct pico_device *dev, uint16_t size)
{
    struct pico_frame *f = pico_frame_alloc_with_headroom(size, SIZE_802154_MHR_MAX, (uint16_t)dev->overhead);
    if (!f)
        return NULL;

    f->dev = dev;
    return f;
}

const struct pico_6lowpan_ll_protocol pico_6lowpan_ll_802154 = {
    .process_in     = pico_802154_process_in,
    .process_out    = pico_802154_process_out,
    .estimate       = pico_802154_estimator,
    .addr_from_buf  = addr_802154_from_buf,
    .addr_from_net  = addr_802154_from_net,
    .addr_len       = addr_802154_len,
    .addr_cmp       = addr_802154_cmp,
    .addr_iid       = addr_802154_iid,
    .alloc          = pico_802154_frame_alloc,
};

#endif /* PICO_SUPPORT_802154 */
