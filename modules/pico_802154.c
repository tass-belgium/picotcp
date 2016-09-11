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

#define NUM_LL_EXTENSIONS 2

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

/* Possible actions to perform on a received frame */
#define FRAME_802154_RELEASE  (-1)
#define FRAME_802154_DISCARD  (-2)

/*******************************************************************************
 * Type definitions
 ******************************************************************************/

typedef uint8_t (*ll_estimator)(struct pico_frame *f, struct pico_802154 src,
                                struct pico_802154 dst);
typedef int (*ll_processor)(struct pico_frame *f, struct pico_802154 *src,
                          struct pico_802154 *dst);
typedef struct extension {
    ll_estimator estimate;
    ll_processor out;
    ll_processor in;
} extension_t;

/*******************************************************************************
 * Global variables
 ******************************************************************************/
static struct pico_queue pico_802154_in = {
    0
};
static struct pico_queue pico_802154_out = {
    0
};

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
    int end = SIZE_802154(addr->mode) - 1;
    for (i = 0; i < (int)((uint8_t)SIZE_802154(addr->mode) >> 1); i++) {
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
addr_802154_ext_dev(struct pico_802154_info *info)
{
    struct pico_802154 addr;
    memcpy(addr.addr.data, info->addr_ext.addr, SIZE_802154_EXT);
    addr.mode = AM_802154_EXT;
    return addr;
}

/* Get the short address of the device in a structured form */
static struct pico_802154
addr_802154_short_dev(struct pico_802154_info *info)
{
    struct pico_802154 addr;
    memcpy(addr.addr.data, (uint8_t *)&(info->addr_short.addr), SIZE_802154_SHORT);
    addr.mode = AM_802154_SHORT;
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
        return addr_802154_short_dev((struct pico_802154_info *)dev->eth);
    } else {
        /* IPv6 source is derived from the device's extended address, use
         * the device's extended address so */
        return addr_802154_ext_dev((struct pico_802154_info *)dev->eth);
    }
}

/* Based on the destination IPv6-address, this function derives the link layer
 * destination address */
static struct pico_802154
addr_802154_ll_dst(struct pico_ip6 *src, struct pico_ip6 *dst, struct pico_device *dev)
{
    struct pico_802154 addr = { .addr.data = { 0 }, .mode = 0 };
    addr.mode = AM_802154_NONE;

    if (dst) {
        if (pico_ipv6_is_multicast(dst->addr)) {
            addr.addr._short.addr = short_be(ADDR_802154_BCAST);
            addr.mode = AM_802154_SHORT;
        }
        /* If the address is link local derive the link layer address from the IID
        * TODO: THIS IS FOR TESTING PURPOSES, HAS TO BE REMOVED WHEN LOWPAN_ND IS
        * IMPLEMENTED */
        else if (pico_ipv6_is_linklocal(dst->addr)) {
            if (IID_16(&dst->addr[8])) {
                addr.addr.data[0] = dst->addr[14];
                addr.addr.data[1] = dst->addr[15];
                addr.mode = AM_802154_SHORT;
            } else {
                memcpy(addr.addr.data, &dst->addr[8], SIZE_802154_EXT);
                addr.addr.data[0] = (uint8_t)(addr.addr.data[0] ^ 0x02);
                addr.mode = AM_802154_EXT;
            }
        }
#ifdef LOWPAN_ND
        else {
            struct pico_802154 *n;
            n = pico_ipv6_get_neighbor(src, dst, dev);
            if (n) {
                memcpy(addr.addr.data, n->addr.data, SIZE_802154(n->mode));
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
    return (uint8_t)(SIZE_802154_MHR_MIN + SIZE_802154(src_am(hdr)) + SIZE_802154(dst_am(hdr)));
}

/* Gets the source address out of a mapped IEEE802.15.4-frame, converts it
 * to host endianess */
static struct pico_802154
frame_802154_src(struct pico_802154_hdr *hdr)
{
    struct pico_802154 src = { .addr.data = { 0 }, .mode = src_am(hdr) };
    uint8_t *addresses = (uint8_t *)hdr + sizeof(struct pico_802154_hdr);
    uint16_t len = SIZE_802154(src.mode);
    memcpy(src.addr.data, addresses + SIZE_802154(dst_am(hdr)), len);
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
    uint16_t len = SIZE_802154(dst.mode);
    memcpy(dst.addr.data, addresses, len);
    addr_802154_to_ietf(&dst);
    return dst;
}

/* Maps a 802.15.4 frame structure onto a flat buffer, fills in the entire
 * header and set the payload pointer right after the MHR. */
static void
frame_802154_format(uint8_t *buf, uint8_t seq, uint16_t intra_pan, uint16_t ack,
                    uint16_t sec, struct pico_802154_short pan, struct pico_802154 src,
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
    memcpy(&hdr->pan_id, &pan.addr, SIZE_802154_SHORT);
    memcpy(addresses, dst.addr.data, SIZE_802154(dst.mode));
    memcpy(addresses + SIZE_802154(dst.mode), src.addr.data,SIZE_802154(src.mode));
}

/* Stores the addresses derived from the network addresses inside the frame
 * so they're available and the same when they are processed further for TX */
static int
frame_802154_store_addr(struct pico_frame *f, struct pico_802154 src,
                        struct pico_802154 dst)
{
    int ssize = SIZE_802154(src.mode), dsize = SIZE_802154(dst.mode);
    uint32_t len = (uint32_t)(SIZE_802154(src.mode) + SIZE_802154(dst.mode) + 2);
    uint32_t datalink_len = (uint32_t)(f->net_hdr - f->buffer);
    uint32_t grow = 0;
    int ret = 0;

    if (len > datalink_len) {
        grow = (uint32_t)(SIZE_802154_MHR_MAX - datalink_len);
        ret = pico_frame_grow_head(f, (uint32_t)(f->buffer_len + grow));
        if (ret)
            return -1;
    }
    /* Move the datalink header before the net_hdr */
    f->datalink_hdr = (uint8_t *)(f->net_hdr - len);

    /* Store the addressing modes and the addresses themself */
    f->datalink_hdr[0] = src.mode;
    f->datalink_hdr[ssize + 1] = dst.mode;
    memcpy(f->datalink_hdr + 1, src.addr.data, (size_t)ssize);
    memcpy(f->datalink_hdr + ssize + 2, dst.addr.data, (size_t)dsize);
    return 0;
}

/* Estimates the size the MAC header would be based on the source and destination
 * link layer address */
static uint8_t
ll_mac_header_estimator(struct pico_frame *f, struct pico_802154 src, struct
                        pico_802154 dst)
{
    IGNORE_PARAMETER(f);
    return (uint8_t)(SIZE_802154_MHR_MIN + SIZE_802154(src.mode) +
        SIZE_802154(dst.mode));
}

/* XXX: Extensible function that estimates the size of the mesh header to be
 * prepended based on the frame, the source and destination link layer address */
static uint8_t
ll_mesh_header_estimator(struct pico_frame *f, struct pico_802154 src, struct
                         pico_802154 dst)
{
    IGNORE_PARAMETER(f);
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);
    return (uint8_t)0;
}

/* Prepends the IEEE802.15.4 MAC header before the frame */
static int
ll_mac_header_process_out(struct pico_frame *f, struct pico_802154 *src,
                          struct pico_802154 *dst)
{
    int len = (int)(SIZE_802154_MHR_MIN + SIZE_802154(dst->mode) + SIZE_802154(src->mode));
    uint8_t sec = (uint8_t)((f->flags & PICO_FRAME_FLAG_LL_SEC) ? (FCF_SEC) : (FCF_NO_SEC));
    struct pico_802154_info *info = (struct pico_802154_info *)f->dev->eth;
    static uint8_t seq = 0;

    /* XXX: General procedure to seek backward in an outgoing processing function
     * is to update the datalink_hdr */
    f->datalink_hdr = f->datalink_hdr - len;

    /* Format the IEEE802.15.4 header */
    frame_802154_format(f->datalink_hdr, seq++, FCF_INTRA_PAN, FCF_NO_ACK_REQ,
                        sec, info->pan_id, *src, *dst);
    return len;
}

/* XXX: Extensible processing function for outgoing frames. Here, the mesh header
 * for a Mesh-Under topology can be prepended and the link layer source and
 * destination addresses can be updated */
static int
ll_mesh_header_process_out(struct pico_frame *f, struct pico_802154 *src,
                           struct pico_802154 *dst)
{
    IGNORE_PARAMETER(f);
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);
    return 0;
}

/* Prepends the IEEE802.15.4 MAC header before the frame */
static int
ll_mac_header_process_in(struct pico_frame *f, struct pico_802154 *src,
                         struct pico_802154 *dst)
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

/* XXX: Extensible processing function for outgoing frames. Here, the mesh header
 * for a Mesh-Under topology can be prepended and the link layer source and
 * destination addresses can be updated */
static int
ll_mesh_header_process_in(struct pico_frame *f, struct pico_802154 *src,
                           struct pico_802154 *dst)
{
    IGNORE_PARAMETER(f);
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);
    return 0;
}

/* Derive an IPv6 IID from an IEEE802.15.4 address */
int
addr_802154_iid(uint8_t iid[8], union pico_ll_addr *addr)
{
    uint8_t buf[8] = {0,0,0,0xff,0xfe,0,0,0};
    struct pico_802154 pan = addr->pan;

    if (AM_802154_SHORT == pan.mode) {
        *(uint16_t *)&buf[6] = pan.addr._short.addr;
    } else if (AM_802154_EXT == pan.mode) {
        memcpy(buf, pan.addr.data, SIZE_802154_EXT);
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
    return SIZE_802154(addr->pan.mode);
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
        return memcmp(a->pan.addr.data, b->pan.addr.data, SIZE_802154(b->pan.mode));
    }
}

const extension_t exts[] = {
    {ll_mac_header_estimator, ll_mac_header_process_out, ll_mac_header_process_in},
    {ll_mesh_header_estimator, ll_mesh_header_process_out, ll_mesh_header_process_in},
};

/* Interface from the 6LoWPAN layer towards the link layer, either enqueues the
 * frame for later processing, or returns the amount of bytes available after
 * prepending the MAC header and additional headers */
int
frame_802154_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    uint16_t frame_size, pl_available = MTU_802154_MAC;
    int i = 0;

    if (!f || !f->dev)
        return -1;
    frame_size = (uint16_t)(f->len);

    /* Call each of the estimator functions of the additional headers to
     * determine if the frame fits inside a single 802.15.4 frame, if it doesn't
     * at some point, return the available bytes */
    for (i = 0; i < NUM_LL_EXTENSIONS; i++) {
        pl_available = (uint16_t)(pl_available - exts[i].estimate(f, src.pan, dst.pan));
        if (frame_size > pl_available)
            return pl_available;
    }

    /* Make sure these addresses are retrievable from the frame on processing */
    if (!frame_802154_store_addr(f, src.pan, dst.pan)) {
        if (pico_enqueue(pico_proto_802154.q_out,f) > 0)
            return 0; // Frame enqueued for later processing
    }
    return -1; // Return ERROR
}

/* General pico_protocol outgoing processing function */
static int
pico_802154_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    uint32_t datalink_len = 0;
    size_t ssize = 0, dsize = 0;
    struct pico_802154 llsrc;
    struct pico_802154 lldst;
    int i = 0, ret = 0;
    IGNORE_PARAMETER(self);

    if (!f || !f->dev)
        return -1;

    /* Retrieve the link layer addresses from the frame */
    ssize = SIZE_802154(f->datalink_hdr[0]);
    dsize = SIZE_802154(f->datalink_hdr[ssize + 1]);
    llsrc.mode = f->datalink_hdr[0];
    lldst.mode = f->datalink_hdr[ssize + 1];
    memcpy(llsrc.addr.data, f->datalink_hdr + 1, ssize);
    memcpy(lldst.addr.data, f->datalink_hdr + ssize + 2, dsize);

    /* Storage of addresses isn't needed anymore, restore link_hdr to former
     * location, so processing functions can easily seek back */
    f->datalink_hdr = f->net_hdr;

    /* Call each of the outgoing processing functions */
    for (i = 0; i < NUM_LL_EXTENSIONS; i++) {
        ret = exts[i].out(f, &llsrc, &lldst);
        if (ret < 0) {
            /* Processing failed, no way to recover, discard frame */
            pico_frame_discard(f);
            return -1;
        }
        datalink_len = (uint32_t)(datalink_len + (uint32_t)ret);
    }

    /* Frame is ready for sending to the device driver */
    f->start = f->datalink_hdr;
    f->len = (uint32_t)(f->len + datalink_len);
    return (int)(pico_sendto_dev(f) <= 0);
}

/* General pico_protocol incoming processing function */
static int
pico_802154_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    int i = 0, ret = 0;
    uint32_t len = 0;
    union pico_ll_addr src;
    union pico_ll_addr dst;
    IGNORE_PARAMETER(self);

    /* net_hdr is the pointer that is dynamically updated by the incoming
     * processing functions to always point to right after a particular
     * header, whether it's MAC, MESH, LL_SEC, ... eventually net_hdr will
     * point to 6LoWPAN header which is exactly what we want */
    f->net_hdr = f->buffer;

    for (i = 0; i < NUM_LL_EXTENSIONS; i++) {
        ret = exts[i].in(f, &src.pan, &dst.pan);
        switch (ret) {
            case FRAME_802154_RELEASE:
                /* Success, frame is somewhere else now.. :( */
                break;
            case FRAME_802154_DISCARD:
                /* Something went wrong, discard the frame */
                pico_frame_discard(f);
                break;
            default:
                /* Success, update link layer header length */
                len = (uint32_t)(len + (uint32_t)ret);
        }
    }

    /* Determine size at network layer */
    f->net_len = (uint16_t)(f->len - len);
    f->len = (uint32_t)(f->len - len);

    return pico_6lowpan_pull(f,src,dst);
}

/* Alloc-function for picoTCP's alloc-chain */
static struct pico_frame *
pico_802154_frame_alloc(struct pico_protocol *self, uint16_t size)
{
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(size);

    /* TODO: Update to extended alloc-function with device as in PR #406 */

    return NULL;
}

struct pico_protocol pico_proto_802154 = {
    .name = "ieee802154",
    .layer = PICO_LAYER_DATALINK,
    .alloc = pico_802154_frame_alloc,
    .process_in = pico_802154_process_in,
    .process_out = pico_802154_process_out,
    .q_in = &pico_802154_in,
    .q_out = &pico_802154_out,
};

#endif /* PICO_SUPPORT_IEEE802154 */
