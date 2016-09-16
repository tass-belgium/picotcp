/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_802154.h"
#include "pico_6lowpan.h"
#include "pico_protocol.h"
#include "pico_addressing.h"

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

/*******************************************************************************
 *  ADDRESSES
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
    int i = 0;
    int end = SIZE_6LOWPAN(addr->mode) - 1;
    for (i = 0; i < (int)((uint8_t)SIZE_6LOWPAN(addr->mode) >> 1); i++) {
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
addr_802154_ll_src(struct pico_ip6 *src, struct pico_device *dev)
{
    if (IID_16(&src->addr[8])) {
        /* IPv6 source is derived from the device's short address, use that
         * short address so decompressor can derive the IPv6 source from
         * the encapsulating header */
        return addr_802154_short_dev((struct pico_6lowpan_info *)dev->eth);
    } else {
        /* IPv6 source is derived from the device's extended address, use
         * the device's extended address so */
        return addr_802154_ext_dev((struct pico_6lowpan_info *)dev->eth);
    }
}

/* Based on the destination IPv6-address, this function derives the link layer
 * destination address */
static struct pico_802154
addr_802154_ll_dst(struct pico_ip6 *src, struct pico_ip6 *dst, struct pico_device *dev)
{
    struct pico_802154 addr = { .addr.data = { 0 }, .mode = 0 };
    addr.mode = AM_6LOWPAN_NONE;

    if (dst) {
        if (pico_ipv6_is_multicast(dst->addr)) {
            addr.addr._short.addr = short_be(ADDR_802154_BCAST);
            addr.mode = AM_6LOWPAN_SHORT;
        }
        /* If the address is link local derive the link layer address from the IID
        * TODO: THIS IS FOR TESTING PURPOSES, HAS TO BE REMOVED WHEN LOWPAN_ND IS
        * IMPLEMENTED */
        else if (pico_ipv6_is_linklocal(dst->addr)) {
            if (IID_16(&dst->addr[8])) {
                addr.addr.data[0] = dst->addr[14];
                addr.addr.data[1] = dst->addr[15];
                addr.mode = AM_6LOWPAN_SHORT;
            } else {
                memcpy(addr.addr.data, &dst->addr[8], SIZE_6LOWPAN_EXT);
                addr.addr.data[0] = (uint8_t)(addr.addr.data[0] ^ 0x02);
                addr.mode = AM_6LOWPAN_EXT;
            }
        }
#ifdef LOWPAN_ND
        else {
            struct pico_802154 *n;
            n = pico_ipv6_get_neighbor(src, dst, dev);
            if (n) {
                memcpy(addr.addr.data, n->addr.data, SIZE_6LOWPAN(n->mode));
                addr.mode = n->mode;
            }
        }
#else
        IGNORE_PARAMETER(dev);
        IGNORE_PARAMETER(src);
#endif
    }
    return addr;
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

/* Estimates the size the MAC header would be based on the source and destination
 * link layer address */
uint8_t pico_802154_estimator(struct pico_frame *f, struct pico_802154 *src, struct pico_802154 *dst)
{
    IGNORE_PARAMETER(f);
    return (uint8_t)(SIZE_802154_MHR_MIN + SIZE_6LOWPAN(src->mode) + SIZE_6LOWPAN(dst->mode));
}

/* Prepends the IEEE802.15.4 MAC header before the frame */
int pico_802154_process_out(struct pico_frame *f, struct pico_802154 *src, struct pico_802154 *dst)
{
    int len = (int)(SIZE_802154_MHR_MIN + SIZE_6LOWPAN(dst->mode) + SIZE_6LOWPAN(src->mode));
    uint8_t sec = (uint8_t)((f->flags & PICO_FRAME_FLAG_LL_SEC) ? (FCF_SEC) : (FCF_NO_SEC));
    struct pico_6lowpan_info *info = (struct pico_6lowpan_info *)f->dev->eth;
    uint16_t headroom = (uint16_t)(f->net_hdr - f->buffer);
    static uint8_t seq = 0;
    uint32_t grow = 0;
    int ret = 0;

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
    frame_802154_format(f->datalink_hdr, seq++, FCF_INTRA_PAN, FCF_NO_ACK_REQ, sec, info->pan_id, *src, *dst);
    return len;
}

/* Prepends the IEEE802.15.4 MAC header before the frame */
int pico_802154_process_in(struct pico_frame *f, struct pico_802154 *src, struct pico_802154 *dst)
{
    struct pico_802154_hdr *hdr = (struct pico_802154_hdr *)f->net_hdr;
    uint16_t fcf = short_be(hdr->fcf);
    uint8_t hlen = 0;
    *src = frame_802154_src(hdr);
    *dst = frame_802154_dst(hdr);

    /* I claim the datalink header */
    f->datalink_hdr = f->net_hdr;

    if (fcf & FCF_SEC) {
        f->flags |= PICO_FRAME_FLAG_LL_SEC;
    }

    hlen = frame_802154_hdr_len(hdr);
    /* XXX: Generic procedure to move forward in incoming processing function
     * is updating the net_hdr-pointer */
    f->net_hdr = f->datalink_hdr + (int)hlen;

    return (int)hlen;
}

/* Derive an IPv6 IID from an IEEE802.15.4 address */
int
addr_802154_iid(uint8_t iid[8], union pico_ll_addr *addr)
{
    uint8_t buf[8] = {0,0,0,0xff,0xfe,0,0,0};
    struct pico_802154 pan = addr->pan;

    if (AM_6LOWPAN_SHORT == pan.mode) {
        *(uint16_t *)&buf[6] = pan.addr._short.addr;
    } else if (AM_6LOWPAN_EXT == pan.mode) {
        memcpy(buf, pan.addr.data, SIZE_6LOWPAN_EXT);
        buf[0] ^= (uint8_t)0x02;
    } else {
        return -1;
    }

    memcpy(iid, buf, 8);
    return 0;
}

/* Determines the length of an IEEE802.15.4 address */
int
addr_802154_len(union pico_ll_addr *addr)
{
    return SIZE_6LOWPAN(addr->pan.mode);
}

/* If 'dest' is not set, this function will get the link layer address for a
 * certain source IPv6 address, if 'dest' is set it will get it for the a
 * destination address */
union pico_ll_addr
addr_802154(struct pico_ip6 *src, struct pico_ip6 *dst, struct pico_device *dev, int dest)
{
    union pico_ll_addr addr;
    if (dest) {
        addr.pan = addr_802154_ll_dst(src, dst, dev);
    } else {
        addr.pan = addr_802154_ll_src(src, dev);
    }
    return addr;
}

/* Compares 2 IEE802.15.4 addresses */
int
addr_802154_cmp(union pico_ll_addr *a, union pico_ll_addr *b)
{
    if (a->pan.mode != b->pan.mode) {
        return (int)((int)a->pan.mode - (int)b->pan.mode);
    } else {
        return memcmp(a->pan.addr.data, b->pan.addr.data, SIZE_6LOWPAN(b->pan.mode));
    }
}

#endif /* PICO_SUPPORT_IEEE802154 */
