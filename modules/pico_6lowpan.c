/*********************************************************************
 PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_udp.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_6lowpan.h"
#include "pico_protocol.h"
#include "pico_addressing.h"
#include "pico_6lowpan_ll.h"

#ifdef PICO_SUPPORT_6LOWPAN

/*******************************************************************************
 * Macros
 ******************************************************************************/

#ifdef DEBUG_6LOWPAN
#define GRN  "\x1b[32m"
#define ORG  "\x1b[33m"
#define RST  "\x1b[0m"
#define lp_dbg dbg
#else
#define lp_dbg(...) do {} while(0)
#endif

#define IPV6_MCAST_48(addr) (!addr[8] && !addr[9] && !addr[10] && (addr[11] || addr[12]))
#define IPV6_MCAST_32(addr) (!addr[8] && !addr[9] && !addr[10] && !addr[11] && !addr[12] && (addr[13] || addr[14]))
#define IPV6_MCAST_8(addr)  (addr[1] == 0x02 && !addr[14] && addr[15])
#define PORT_COMP(a, mask, b)   (((a) & (mask)) == (b))

/*******************************************************************************
 * Constants
 ******************************************************************************/

#define NUM_IPV6_FIELDS     (6)
#define NUM_UDP_FIELDS      (4)
#define IPV6_DISPATCH       (0x41)
#define IPHC_DISPATCH       (0x60)
#define UDP_DISPATCH        (0xF0)
#define EXT_DISPATCH        (0xE0)
#define EXT_HOPBYHOP        (0x00)
#define EXT_ROUTING         (0x02)
#define EXT_FRAG            (0x04)
#define EXT_DSTOPT          (0x06)
#define EXT_COMPRESSED_NH   (0x01)
#define UDP_COMPRESSED_DST  (0x01)
#define UDP_COMPRESSED_SRC  (0x02)
#define UDP_COMPRESSED_BOTH (0x03)
#define UDP_COMPRESSED_CHCK (0x04)
#define TF_INLINE           (0x00)
#define TF_ELIDED_DSCP      (0x08)
#define TF_ELIDED_FL        (0x10)
#define TF_ELIDED           (0x18)
#define NH_COMPRESSED       (0x04)
#define HL_COMPRESSED_1     (0x01)
#define HL_COMPRESSED_64    (0x02)
#define HL_COMPRESSED_255   (0x03)
#define CTX_EXTENSION       (0x80)
#define SRC_SHIFT           (0x04)
#define SRC_STATEFUL        (0x40)
#define SRC_COMPRESSED_64   (0x10)
#define SRC_COMPRESSED_16   (0x20)
#define SRC_COMPRESSED      (0x30)
#define DST_STATEFUL        (0x04)
#define DST_COMPRESSED_64   (0x01)
#define DST_COMPRESSED_16   (0x02)
#define DST_COMPRESSED      (0x03)
#define DST_MULTICAST       (0x08)
#define DST_MCAST_48        (0x01)
#define DST_MCAST_32        (0x02)
#define DST_MCAST_8         (0x03)
#define COMP_LINKLOCAL      (0)
#define COMP_STATELESS      (-1)
#define COMP_MULTICAST      (-2)
#define COMP_UNSPECIFIED    (-3)
#define FRAG1_SIZE          (4)
#define FRAGN_SIZE          (5)
#define FRAG1_DISPATCH      (0xC0)
#define FRAGN_DISPATCH      (0xE0)
#define FRAG_TIMEOUT        (5)
/*******************************************************************************
 * Type definitions
 ******************************************************************************/

struct hdr_field
{
    int8_t ori_size;
    int8_t (* compress)(uint8_t *, uint8_t *, uint8_t *, union pico_ll_addr *, union pico_ll_addr *, struct pico_device *);
    int8_t (* decompress)(uint8_t *, uint8_t *, uint8_t *, union pico_ll_addr *, union pico_ll_addr *, struct pico_device *);
};

struct frag_ctx {
    struct pico_frame *f;
    uint16_t dgram_size;
    uint16_t dgram_tag;
    uint8_t dgram_off;
    uint16_t copied;
    uint32_t hash;
    pico_time timestamp;
};

/*******************************************************************************
 *  Global Variables
 ******************************************************************************/

static struct pico_queue pico_6lowpan_in = {
    0
};
static struct pico_queue pico_6lowpan_out = {
    0
};

static uint16_t dgram_tag = 0;

/*******************************************************************************
 *  Private functions
 ******************************************************************************/

/* Copies two memory buffers but also considers overlapping buffers */
static void
buf_move(void *dst, const void *src, size_t len)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (!dst || !src) {
        return;
    } else {
        if (d < s) {
            while (len--)
                *d++ = *s++;
        } else {
            s = s + len - 1;
            d = d + len - 1;
            while (len--)
                *d-- = *s--;
        }
    }
}

/*******************************************************************************
 *  Frags
 ******************************************************************************/

/* Compares two fragmentation cookies based on the hash */
static int32_t
frag_ctx_cmp(void *a, void *b)
{
    struct frag_ctx *fa = (struct frag_ctx *)a;
    struct frag_ctx *fb = (struct frag_ctx *)b;
    return (int32_t)(fa->hash - fb->hash);
}

/* Compares two fragmentation cookies according to RFC4944 5.3 */
static int32_t
frag_cmp(void *a, void *b)
{
    struct frag_ctx *fa = (struct frag_ctx *)a;
    struct frag_ctx *fb = (struct frag_ctx *)b;
    int32_t ret = 0;
    if (fa->dgram_size != fb->dgram_size) {
        return (int32_t)(fa->dgram_size - fb->dgram_size);
    } else if (fa->dgram_tag != fb->dgram_tag) {
        return (int32_t)(fa->dgram_tag - fb->dgram_tag);
    } else {
        if ((ret = pico_6lowpan_lls[fa->f->dev->mode].addr_cmp(&fa->f->src, &fb->f->src))) {
            return ret;
        } else {
            return pico_6lowpan_lls[fa->f->dev->mode].addr_cmp(&fa->f->dst, &fb->f->dst);
        }
    }
}

PICO_TREE_DECLARE(FragTree, &frag_ctx_cmp);
PICO_TREE_DECLARE(ReassemblyTree, &frag_cmp);

/* Find a fragmentation cookie for transmission of subsequent fragments */
static struct frag_ctx *
frag_ctx_find(uint32_t hash)
{
    struct frag_ctx f = { .hash = hash };
    return pico_tree_findKey(&FragTree, &f);
}

/* Reassembly timeout function, deletes */
static void
frag_timeout(pico_time now, void *arg)
{
    struct pico_tree_node *i = NULL, *next = NULL;
    struct frag_ctx *key = NULL;
    IGNORE_PARAMETER(arg);
    pico_tree_foreach_safe(i, &ReassemblyTree, next) {
        if ((key = i->keyValue)) {
            if ((pico_time)(FRAG_TIMEOUT * 1000) <= (now - key->timestamp)) {
                lp_dbg("Timeout for reassembly: %d\n", key->dgram_tag);
                pico_tree_delete(&ReassemblyTree, key);
                pico_frame_discard(key->f);
                PICO_FREE(key);
            }
        }
    }

    /* If adding a timer fails, there's not really an easy way to recover, so abort all ongoing
     * reassemblies
     * TODO: Maybe using a global variable allows recovering from this situation */
    if (0 == pico_timer_add(1000, frag_timeout, NULL)) {
        lp_dbg("6LP: Failed to set reassembly timeout! Aborting all ongoing reassemblies...\n");
        pico_tree_foreach_safe(i, &ReassemblyTree, next) {
            if ((key = i->keyValue)) {
                pico_tree_delete(&ReassemblyTree, key);
                pico_frame_discard(key->f);
                PICO_FREE(key);
            }
        }
    }
}

/* Finds a reassembly cookie in the reassembly-tree */
static struct frag_ctx *
frag_find(uint16_t dgram_size, uint16_t tag, struct pico_frame *frame)
{
    struct frag_ctx f = {.f = frame, .dgram_size = dgram_size, .dgram_tag = tag};
    return pico_tree_findKey(&ReassemblyTree, &f);
}

/* Stores a fragmentation cookie in either the fragmentetion cookie tree or
 * in the reassembly tree */
static int32_t
frag_store(struct pico_frame *f, uint16_t dgram_size, uint16_t tag,
           uint8_t dgram_off, uint16_t copied, struct pico_tree *tree)
{
    struct frag_ctx *fr = PICO_ZALLOC(sizeof(struct frag_ctx));
    if (fr) {
        fr->f = f;
        fr->dgram_size = dgram_size;
        fr->dgram_off = dgram_off;
        fr->dgram_tag = tag;
        fr->copied = copied;
        fr->timestamp = PICO_TIME_MS();
        if (&FragTree == tree) {
            fr->hash = pico_hash((void *)fr, sizeof(struct frag_ctx));
            f->hash = fr->hash; // Also set hash in frame so we can identify it
            lp_dbg("6LP: START: "ORG"fragmentation"RST" with hash '%X' of %u bytes.\n", fr->hash, f->len);
        } else {
            lp_dbg("6LP: START: "GRN"reassembly"RST" with tag '%d' of %u bytes.\n", tag, dgram_size);
        }
        /* Insert the cookie in the appropriate tree (FragTree/ReassemblyTree) */
        if (pico_tree_insert(tree, fr)) {
            PICO_FREE(fr);
            return -1;
        }
    } else {
        return (-1);
    }
    return (1); // Succes for 'proto_loop_out'
}

/*******************************************************************************
 *  IPHC
 ******************************************************************************/

#ifdef PICO_6LOWPAN_IPHC_ENABLED

/* Compresses the VTF-field of an IPv6 header */
static int8_t
compressor_vtf(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
               llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    uint8_t ecn = 0, dscp = 0;
    uint32_t fl = 0;
    *ori &= 0x0F; // Clear version field
    *iphc &= (uint8_t)0x07; // Clear IPHC field
    *iphc |= (uint8_t)IPHC_DISPATCH;
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);

    /* Don't worry... */
    ecn = (uint8_t)((ori[0] << 4) & 0xC0);
    dscp = (uint8_t)(((ori[0] << 4) & 0x30) | ((ori[1] & 0xF0) >> 4));
    fl = long_be((uint32_t)(ori[1] & 0x0F) << 16);
    fl += long_be((uint32_t)(ori[2] & 0xFF) << 8);
    fl += long_be((uint32_t)(ori[3] & 0xFF));

    if (fl) {
        if (!dscp) { // Flow label carried in-line
            *iphc |= TF_ELIDED_DSCP;
            comp[0] = (uint8_t)(ecn | (ori[1] & 0x0F));
            comp[1] = ori[2];
            comp[2] = ori[3];
            return 3;
        } else { // Traffic class and flow label carried in-line
            *iphc |= TF_INLINE;
            *comp = ecn | dscp;
            comp[1] = ori[1] & 0x0F;
            comp[2] = ori[2];
            comp[3] = ori[3];
            return 4;
        }
    } else if (ecn || dscp) { // Traffic class carried in-line
        *iphc |= TF_ELIDED_FL;
        *comp = ecn | dscp;
        return 1;
    } else { // Traffic class and flow label elided
        *iphc |= TF_ELIDED;
        return 0;
    }
}

/* Decompresses the VTF-field of a IPHC-header */
static int8_t
decompressor_vtf(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    uint8_t tf = *iphc & TF_ELIDED;
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    if (TF_INLINE == tf) {
        *ori++ = (0x60 | (*comp >> 4));
        *ori |= (uint8_t)((uint8_t)(*comp++ << 4) & 0xF0);
        *ori++ |= *comp++;
        *ori++ = *comp++;
        *ori++ = *comp++;
        return 4;
    } else if (TF_ELIDED_DSCP == tf) {
        *ori++ = (0x60 | (*comp >> 4)) & 0xFC;
        *ori++ = *comp++ & 0x0F;
        *ori++ = *comp++;
        *ori = *comp;
        return 3;
    } else if (TF_ELIDED_FL == tf) {
        *ori++ = (0x60 | (*comp >> 4));
        *ori = (uint8_t)(*comp << 4) & 0xF0;
        return 1;
    } else {
        *ori = 0x60; // Set version field to IPv6
        return 0;
    }
}

/* Checks whether or not next header is compressible according to NHC scheme */
static int32_t
compressible_nh(uint8_t nh)
{
    switch (nh) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
        case PICO_IPV6_EXTHDR_ROUTING:
        case PICO_IPV6_EXTHDR_FRAG:
        case PICO_IPV6_EXTHDR_DESTOPT:
        case PICO_PROTO_UDP: return 1;
        default: return 0;
    }
}

/* Checks whether or not the next header can be compressed and sets the IPHC
 * bits accordingly, compression of next header itself happens in NHC-compression
 */
static int8_t
compressor_nh(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
               llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    *iphc &= (uint8_t)~NH_COMPRESSED;
    IGNORE_PARAMETER(comp);
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    if (compressible_nh(*ori)) {
        *iphc |= NH_COMPRESSED;
        return 0;
    } else {
        *comp = *ori;
        return 1;
    }
}

/* Check whether or no the next header is NHC-compressed, indicates this for the
 * general decompressor so it knows that it has to decompress the next header
 * and fill in the NH-header field in IPv6 header */
static int8_t
decompressor_nh(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    IGNORE_PARAMETER(comp);
    if (*iphc & NH_COMPRESSED) {
        *ori = 0; // Indicate that next header needs to be decompressed
        return 0;
    } else {
        *ori = *comp;
        return 1;
    }
}

/* Compressed the HL-field if common hop limit values are used, like 1, 64 and
 * 255 */
static int8_t
compressor_hl(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
              llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    *iphc &= (uint8_t)~HL_COMPRESSED_255;
    switch (*ori) {
        case 1: *iphc |= (uint8_t)HL_COMPRESSED_1;
            return 0;
        case 64: *iphc |= (uint8_t)HL_COMPRESSED_64;
            return 0;
        case 255: *iphc |= (uint8_t)HL_COMPRESSED_255;
            return 0;
        default: *comp = *ori;
            return 1;
    }
}

/* Decompresses the HL-field to common hop limit values like 1, 64 and 255 */
static int8_t
decompressor_hl(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)

{
    uint8_t hl = *iphc & HL_COMPRESSED_255;
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    switch(hl) {
        case HL_COMPRESSED_1: *ori = (uint8_t)1;
            return 0;
        case HL_COMPRESSED_64: *ori = (uint8_t)64;
            return 0;
        case HL_COMPRESSED_255: *ori = (uint8_t)255;
            return 0;
        default: *ori = *comp;
            return 1;
    }
}

/* Determines if an address can be statefully or statelessly compressed */
static int8_t
addr_comp_prefix(uint8_t *iphc, struct pico_ip6 *addr, int8_t src)
{
    struct iphc_ctx *ctx = NULL;
    uint8_t state = src ? SRC_STATEFUL : DST_STATEFUL;
    iphc[1] &= (uint8_t)~state; // Clear out compression state for src/dst

    if (pico_ipv6_is_multicast(addr->addr)) {
        /* TODO: Support stateful multicast compression with Unicast-Prefix-Based
         * IPv6 Multicast Addresses as defined in RFC3956 */
        return COMP_MULTICAST; // AC = 0
    } else if (pico_ipv6_is_linklocal(addr->addr)) {
        return COMP_LINKLOCAL; // AC = 0
    } else if ((ctx = ctx_lookup(*addr))) {
        if (ctx->flags & PICO_IPHC_CTX_COMPRESS) {
            iphc[1] |= state; // AC = 1
            iphc[1] |= CTX_EXTENSION; // SRC or DST is stateful, CID = 1
            return (int8_t)ctx->id;
        }
    }
    return COMP_STATELESS; // AC = 0
}

/* Checks whether or not an IPv6 address is derived from a link layer address */
static int8_t
addr_ll_derived(struct pico_ip6 *addr, union pico_ll_addr *lladdr, struct pico_device *dev)
{
    uint8_t iid[8] = {0};
    if (pico_6lowpan_lls[dev->mode].addr_iid) {
        if (!pico_6lowpan_lls[dev->mode].addr_iid(iid, lladdr))
            return (int8_t)(0 == memcmp(iid, &addr->addr[8], 8));
    }
    return -1;
}

/* Sets the compression mode of either the source address or the destination
 * address, based on the shift parameter. Use SRC_SHIFT for source, 0 for dst */
static int8_t
addr_comp_mode(uint8_t *iphc, struct pico_ip6 *addr, union pico_ll_addr lladdr, struct pico_device *dev, int8_t shift)
{
    int8_t mac = addr_ll_derived(addr, &lladdr, dev);
    iphc[1] &= (uint8_t)((uint8_t)~DST_COMPRESSED << shift); // Clear src/dst mode

    if (mac > 0) { // Address is mac derived
        iphc[1] |= (uint8_t)(DST_COMPRESSED << shift);
        return 0;
    } else if (!mac && IID_16(&addr->addr[8])) { // Address is 16-bit deriveable
        iphc[1] |= (uint8_t)(DST_COMPRESSED_16 << shift);
        return 2;
    } else if (!mac) { // Copy the entire IID
        iphc[1] |= (uint8_t)(DST_COMPRESSED_64 << shift);
        return 8;
    } else {
        return -1; // Something went wrong, indicate failure
    }
}

/* Compresses a multicast address statelessly */
static int8_t
addr_comp_mcast(uint8_t *iphc, uint8_t *comp, struct pico_ip6 *mcast)
{
    iphc[1] &= (uint8_t)~DST_MCAST_8; // Clear out addressing mode
    iphc[1] |= (uint8_t)DST_MULTICAST; // Set multicast flag

    if (IPV6_MCAST_48(mcast->addr)) {
        comp[0] = mcast->addr[1]; // Copy flags and scope
        buf_move(&comp[1], &mcast->addr[11], 5); // Copy group identifier
        iphc[1] |= DST_MCAST_48;
        return 6;
    } else if (IPV6_MCAST_32(mcast->addr)) {
        comp[0] = mcast->addr[1]; // Copy flags and scope
        buf_move(&comp[1], &mcast->addr[13], 3); // Copy group identifier
        iphc[1] |= DST_MCAST_32;
        return 4;
    } else if (IPV6_MCAST_8(mcast->addr)) {
        comp[0] = mcast->addr[15]; // Copy group identifier
        iphc[1] |= DST_MCAST_8; // Flags and scope = 0x02
        return 1;
    } else {
        buf_move(comp, mcast->addr, PICO_SIZE_IP6); // Copy entire address
        return PICO_SIZE_IP6;
    }
}

/* Compresses the IID of a IPv6 address into 'comp'. Also has to take link layer
 * address into account and whether it's about source or destination address. */
static int8_t
addr_comp_iid(uint8_t *iphc, uint8_t *comp, int8_t state, struct pico_ip6 *addr, union pico_ll_addr ll, struct pico_device *dev, int8_t shift)
{
    int8_t len = PICO_SIZE_IP6;
    switch (state) {
        case COMP_UNSPECIFIED: // Set stateful bit
            iphc[1] |= SRC_STATEFUL;
        case COMP_STATELESS: // Clear compressed flags
            iphc[1] &= (uint8_t)~SRC_COMPRESSED;
            break;
        case COMP_LINKLOCAL:
            len = addr_comp_mode(iphc, addr, ll, dev, shift);
            break;
        case COMP_MULTICAST: // Multicast, compress statelessly
            return addr_comp_mcast(iphc, comp, addr);
        default: // Context available, extend header, and check for IID
            iphc[2] = (uint8_t)((uint8_t)state << shift);
            len = addr_comp_mode(iphc, addr, ll, dev, shift);
    }

    if (len >= 0)
        buf_move(comp, addr->addr + PICO_SIZE_IP6 - len, (size_t)len);
    return len;
}

/* Compresses the SOURCE address of the IPv6 frame */
static int8_t
compressor_src(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    struct pico_ip6 src = *(struct pico_ip6 *)ori;
    int8_t ret = addr_comp_prefix(iphc, &src, SRC_SHIFT);
    IGNORE_PARAMETER(lldst);

    if (pico_ipv6_is_unspecified(src.addr))
        ret = COMP_UNSPECIFIED;

    return addr_comp_iid(iphc, comp, ret, &src, *llsrc, dev, SRC_SHIFT);
}

/* Copies the appropriate IPv6 prefix in the decompressed address. Based on
 * context, link local address or multicast address */
static int8_t
addr_decomp_prefix(uint8_t *prefix, uint8_t *iphc, int8_t shift)
{
    struct pico_ip6 ll = { .addr = {0xfe,0x80,0,0,0,0,0,0,0,0,0,0xff,0xfe,0,0,0}};
    uint8_t addr_state = (uint8_t)(DST_STATEFUL << shift);
    struct iphc_ctx *ctx = NULL;

   if (iphc[1] & addr_state) {
        if ((ctx = ctx_lookup_id((uint8_t)(iphc[2] >> shift)))) {
            buf_move(prefix, ctx->prefix.addr, PICO_SIZE_IP6);
            buf_move(&prefix[8], &ll.addr[8], 8); // For 16-bit derived addresses
        } else {
            /* No context available while stateful compression is used... */
            return -1;
        }
    } else {
        buf_move(prefix, ll.addr, PICO_SIZE_IP6);
    }
    return 0;
}

/* Decompresses the IID of the IPv6 address based on addressing mode of the IPHC-
 * header */
static int8_t
addr_decomp_iid(struct pico_ip6 *addr, uint8_t *comp, uint8_t am, union pico_ll_addr lladdr, struct pico_device *dev)
{
    if (addr) {
        switch (am) {
            case DST_COMPRESSED_64: buf_move(&addr->addr[8], comp, 8);
                return 8;
            case DST_COMPRESSED_16: buf_move(&addr->addr[14], comp, 2);
                return 2;
            case DST_COMPRESSED:
                if (dev && pico_6lowpan_lls[dev->mode].addr_iid) {
                    pico_6lowpan_lls[dev->mode].addr_iid(&addr->addr[8], &lladdr);
                    return 0;
                } else {
                    return -1;
                }
            default: buf_move(addr->addr, comp, PICO_SIZE_IP6);
                return 16;
        }
    } else {
        return -1;
    }
}

/* Decompress the SOURCE address of the 6LoWPAN frame */
static int8_t
decompressor_src(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    struct pico_ip6 *src = (struct pico_ip6 *)ori;
    uint8_t sam = (uint8_t)((uint8_t)(iphc[1] & SRC_COMPRESSED) >> 4);
    IGNORE_PARAMETER(lldst);

    /* Get the appropriate IPv6 prefix */
    if (addr_decomp_prefix(ori, iphc, SRC_SHIFT))
        return -1;

    return addr_decomp_iid(src, comp, sam, *llsrc, dev);
}

/* Compresses the DESTINATION address of IPv6 frame */
static int8_t
compressor_dst(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
               llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    struct pico_ip6 dst = *(struct pico_ip6 *)ori;
    int8_t ret = addr_comp_prefix(iphc, &dst, 0);
    IGNORE_PARAMETER(llsrc);
    return addr_comp_iid(iphc, comp, ret, &dst, *lldst, dev, 0);
}

/* Decompresses the IPv6 multicast destination address when the IPHC mcast-flag
 * is set */
static int8_t
addr_decomp_mcast(uint8_t *comp, struct pico_ip6 *dst, uint8_t am)
{
    if (dst) {
        memset(dst->addr, 0, PICO_SIZE_IP6);
        dst->addr[0] = 0xff;
        dst->addr[1] = *comp;
        switch (am) {
            case DST_MCAST_48:
                buf_move(dst->addr + 11, comp + 1, 5);
                return 6;
            case DST_MCAST_32:
                buf_move(dst->addr + 13, comp + 1, 3);
                return 4;
            case DST_MCAST_8:
                dst->addr[1] = 0x02;
                dst->addr[15] = *comp;
                return 1;
            default:
                buf_move(dst->addr, comp, PICO_SIZE_IP6);
                return PICO_SIZE_IP6;
        }
    } else {
        return -1;
    }
}

/* Decompresses the DESTINATION address of a 6LoWPAN frame */
static int8_t
decompressor_dst(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    struct pico_ip6 *dst = (struct pico_ip6 *)ori;
    uint8_t dam = iphc[1] & DST_COMPRESSED;
    IGNORE_PARAMETER(llsrc);

    if (addr_decomp_prefix(ori, iphc, SRC_SHIFT))
        return -1;

    if (iphc[1] & DST_MULTICAST) {
        return addr_decomp_mcast(comp, dst, dam);
    } else {
        return addr_decomp_iid(dst, comp, dam, *lldst, dev);
    }
}

static const struct hdr_field ip6_fields[] = {
    {4, compressor_vtf, decompressor_vtf},
    {2, NULL, NULL},
    {1, compressor_nh, decompressor_nh},
    {1, compressor_hl, decompressor_hl},
    {16, compressor_src, decompressor_src},
    {16, compressor_dst, decompressor_dst}
};

/* Compresses the IPv6 frame according to the IPHC-compression scheme */
static uint8_t *
compressor_iphc(struct pico_frame *f, int32_t *compressed_len, uint8_t *nh)
{
    uint8_t *inline_buf = PICO_ZALLOC(PICO_SIZE_IP6HDR + 3);
    uint8_t *comp = inline_buf + 3;
    uint8_t *iphc = inline_buf;
    uint8_t *ori = f->net_hdr;
    int32_t i = 0, ret = 0;
    *compressed_len = 0;
    *nh = ((struct pico_ipv6_hdr *)f->net_hdr)->nxthdr;

    if (!inline_buf) {
        return NULL;
    } else {
        /* Compress fixed IPv6 fields */
        for (i = 0; i < NUM_IPV6_FIELDS; i++) {
            if (ip6_fields[i].compress) {
                ret = ip6_fields[i].compress(ori, comp, iphc, &f->src, &f->dst, f->dev);
                if (ret < 0) { // Something went wrong ...
                    PICO_FREE(inline_buf);
                    return NULL;
                }
                *compressed_len += ret; // Increase compressed length
                comp += ret; // Move forward compressed length
            }
            ori += ip6_fields[i].ori_size; // Move to next field
        }

        /* Rearrange IPHC-header if CTX-extension is included */
        if (iphc[1] & CTX_EXTENSION) {
            *compressed_len += 3;
        } else {
            buf_move(inline_buf + 2, inline_buf + 3, (size_t)*compressed_len);
            *compressed_len += 2;
        }
    }
    return inline_buf;
}

/* Decompresses a frame compressed with the IPHC compression scheme, RFC6282 */
static uint8_t *
decompressor_iphc(struct pico_frame *f, int32_t *compressed_len)
{
    uint8_t *ipv6_hdr = PICO_ZALLOC(PICO_SIZE_IP6HDR);
    uint8_t *iphc = f->net_hdr, *ori = ipv6_hdr, *comp = NULL;
    int32_t i = 0, ret = 0, ctx = f->net_hdr[1] & CTX_EXTENSION;
    *compressed_len = ctx ? 3 : 2;
    comp = f->net_hdr + (ctx ? 3 : 2);

    if (!ipv6_hdr) {
        return NULL;
    } else {
        for (i = 0; i < NUM_IPV6_FIELDS; i++) {
            if (ip6_fields[i].decompress) {
                ret = ip6_fields[i].decompress(ori, comp, iphc, &f->src, &f->dst, f->dev);
                if (ret < 0) { // Something went wrong ...
                    PICO_FREE(ipv6_hdr);
                    return NULL;
                }
                *compressed_len += ret; // Increase compressed size
                comp += ret; // Move to next compressed chunk
            }
            ori += ip6_fields[i].ori_size; // Move to next IPv6 field
        }
    }
    return ipv6_hdr;
}

/* Compresses a UDP header according to the NHC_UDP compression scheme, RFC6282 */
static uint8_t *
compressor_nhc_udp(struct pico_frame *f, int32_t *compressed_len)
{
    uint8_t *inline_buf = PICO_ZALLOC(PICO_UDPHDR_SIZE);
    struct pico_udp_hdr *hdr = (struct pico_udp_hdr *)f->transport_hdr;
    uint16_t sport = hdr->trans.sport, dport = hdr->trans.dport;
    uint16_t xF0B0 = short_be(0xF0B0), xF000 = short_be(0xF000);
    uint16_t xFF00 = short_be(0xFF00), xFFF0 = short_be(0xFFF0);
    *compressed_len = 0;

    if (!inline_buf) {
        return NULL;
    } else {
        /* Dispatch header */
        inline_buf[0] = (uint8_t)UDP_DISPATCH;
        /* Port compression */
        if (PORT_COMP(sport, xFFF0, xF0B0) && PORT_COMP(dport, xFFF0, xF0B0)) {
            inline_buf[0] |= UDP_COMPRESSED_BOTH;
            inline_buf[1] = (uint8_t)(short_be(sport) << 4);
            dport = (uint8_t)(short_be(dport) & (uint16_t)0x000F);
            inline_buf[1] = (uint8_t)(inline_buf[1] | (uint8_t)dport);
            *compressed_len = 2;
        } else if (PORT_COMP(sport, xFF00, xF000)) {
            inline_buf[0] |= UDP_COMPRESSED_SRC;
            inline_buf[1] = (uint8_t)short_be(sport);
            buf_move(inline_buf + 2, (uint8_t *)hdr + 2, 2);
            *compressed_len = 4;
        } else if (PORT_COMP(dport, xFF00, xF000)) {
            inline_buf[0] |= UDP_COMPRESSED_DST;
            inline_buf[3] = (uint8_t)short_be(dport);
            buf_move(inline_buf + 1, (uint8_t *)hdr, 2);
            *compressed_len = 4;
        } else {
            inline_buf[0] &= (uint8_t)~UDP_COMPRESSED_BOTH;
            buf_move(inline_buf + 1, (uint8_t *)hdr, 4);
            *compressed_len = 5;
        }
        /* Length MUST be compressed checksum carried inline.
         * RFC6282: .., a compressor in the source transport endpoint MAY elide
         * the UDP checksum if it is autorized by the upper layer. The compressor
         * MUST NOT set the C bit unless it has received such authorization */
        buf_move(inline_buf + *compressed_len, (uint8_t *)hdr + 6, 2);
        *compressed_len += 2;
        return inline_buf;
    }
}

/* Decompresses a NHC_UDP header according to the NHC_UDP compression scheme */
static uint8_t *
decompressor_nhc_udp(struct pico_frame *f, int32_t processed_len, int32_t *compressed_len)
{
    struct pico_udp_hdr *hdr = NULL;
    uint8_t *buf = f->transport_hdr;
    uint8_t compression = buf[0] & UDP_COMPRESSED_BOTH;
    uint16_t xF0B0 = short_be(0xF0B0);
    uint16_t xF000 = short_be(0xF000);
    int32_t payload_len = 0;
    *compressed_len = 0;

    /* Decompress ports */
    hdr = PICO_ZALLOC(PICO_UDPHDR_SIZE);
    if (hdr) {
        if (UDP_COMPRESSED_BOTH == compression) {
            hdr->trans.sport = xF0B0 | short_be((uint16_t)(buf[1] >> 4));
            hdr->trans.dport = xF0B0 | short_be((uint16_t)(buf[1] & 0xff));
            *compressed_len = 2;
        } else if (UDP_COMPRESSED_SRC == compression) {
            hdr->trans.dport = short_be((uint16_t)(((uint16_t)buf[2] << 8) | (uint16_t)buf[3]));
            hdr->trans.sport = xF000 | short_be((uint16_t)buf[1]);
            *compressed_len = 4;
        } else if (UDP_COMPRESSED_DST == compression) {
            hdr->trans.sport = short_be((uint16_t)(((uint16_t)buf[1] << 8) | (uint16_t)buf[2]));
            hdr->trans.dport = xF000 | short_be((uint16_t)buf[3]);
            *compressed_len = 4;
        } else {
            buf_move((uint8_t *)&hdr->trans, &buf[1], 4);
            *compressed_len = 5;
        }
        if (!(buf[0] & UDP_COMPRESSED_CHCK)) { // Leave empty room for checksum
            buf_move((uint8_t *)&hdr->crc, &buf[*compressed_len],2);
            *compressed_len += 2;
        }
        /* Restore inherently compressed length */
        payload_len = (int32_t)f->len - (processed_len + *compressed_len);
        hdr->len = short_be((uint16_t)(payload_len + PICO_UDPHDR_SIZE));
        return (uint8_t *)hdr;
    }
    return NULL;
}

/* Get's the length of an IPv6 extension header  */
static int32_t
ext_hdr_len(struct pico_ipv6_exthdr *ext, uint8_t hdr, uint8_t *dispatch)
{
    int32_t len = 0;
    /* Get length of extension header */
    switch (hdr) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
            *dispatch |= (uint8_t)EXT_HOPBYHOP;
            len = IPV6_OPTLEN(ext->ext.destopt.len); // Length in bytes
            ext->ext.destopt.len = (uint8_t)(len - 2); // Octets after len-field
            return (int32_t)len;
        case PICO_IPV6_EXTHDR_ROUTING:
            *dispatch |= (uint8_t)EXT_ROUTING;
            len = IPV6_OPTLEN(ext->ext.destopt.len); // Length in bytes
            ext->ext.destopt.len = (uint8_t)(len - 2); // Octets after len-field
            return (int32_t)len;
        case PICO_IPV6_EXTHDR_DESTOPT:
            *dispatch |= (uint8_t)EXT_DSTOPT;
            len = IPV6_OPTLEN(ext->ext.destopt.len); // Length in bytes
            ext->ext.destopt.len = (uint8_t)(len - 2); // Octets after len-field
            return (int32_t)len;
        case PICO_IPV6_EXTHDR_FRAG:
            *dispatch |= (uint8_t)EXT_FRAG;
            return (int32_t)8;
        default: // Somethin went wrong, bail out...
            return -1;
    }
}

/* Compresses an IPv6 extension header according to the NHC_EXT compression
 * scheme */
static uint8_t *
compressor_nhc_ext(struct pico_frame *f, int32_t *compressed_len, uint8_t *nh)
{
    struct pico_ipv6_exthdr *ext = (struct pico_ipv6_exthdr *)f->net_hdr;
    uint8_t dispatch = EXT_DISPATCH;
    int32_t len = 0, lead = 0, ret = 0;
    uint8_t *buf = NULL;
    uint8_t hdr = *nh;

    /* Determine next header */
    *nh = ext->nxthdr;
    if (!compressible_nh(*nh)) {
        len++; // Dispatch header has to be prepended
        lead++; // Copy right after dispatch
    } else {
        dispatch |= (uint8_t)0x01; // Set NH flag
    }

    /* Get length of extension header */
    ret = ext_hdr_len(ext, hdr, &dispatch);
    if (ret < 0) {
        return NULL;
    } else {
        /* Provide inline buffer */
        len += ret;
        buf = PICO_ZALLOC((size_t)len);
        if (!buf) {
            return NULL;
        } else {
            /* Copy extension header */
            buf_move(buf + lead, (uint8_t *)ext, (size_t)(len - lead));
            buf[0] = dispatch; // Set the dispatch header
            *compressed_len = len;
            f->net_hdr += *compressed_len; // Move to next header
            return buf;
        }
    }
}

/* Retrieves the next header from the immediately following header */
static uint8_t
ext_nh_retrieve(uint8_t *buf, int32_t len)
{
    uint8_t eid = 0;
    buf += len;
    if ((buf[0] & 0xF0) == EXT_DISPATCH) {
        eid = buf[0] & 0x0E;
        switch (eid) {
            case EXT_HOPBYHOP:
                return (uint8_t)PICO_IPV6_EXTHDR_HOPBYHOP;
            case EXT_ROUTING:
                return (uint8_t)PICO_IPV6_EXTHDR_ROUTING;
            case EXT_FRAG:
                return (uint8_t)PICO_IPV6_EXTHDR_FRAG;
            case EXT_DSTOPT:
                return (uint8_t)PICO_IPV6_EXTHDR_DESTOPT;
            default:
                return 0;
        }
    } else if ((buf[0] & 0xF8) == UDP_DISPATCH) {
        return PICO_PROTO_UDP;
    }
    return 0;
}

/* RFC6282: A decompressor MUST ensure that the
 * containing header is padded out to a multiple of 8 octets in length,
 * using a Pad1 or PadN option if necessary. */
static int32_t
ext_align(uint8_t *buf, int32_t alloc, int32_t len)
{
    int32_t padlen = alloc - len;
    buf += len; // Move to padding location
    if (padlen == 1) {
        buf[0] = 0; // Pad1
    } else if (padlen > 1) {
        buf[0] = 1; // PadN
        buf[1] = (uint8_t)(padlen - 2);
    } else {
        return -1;
    }
    return 0;
}

/* Determines the compressed length (and some other parameters) from NHC_EXT
 * compressed extension header */
static int32_t
ext_compressed_length(uint8_t *buf, uint8_t eid, int32_t *compressed_len, int32_t *head)
{
    int32_t len = 0;
    switch (eid) {
        case EXT_HOPBYHOP: // Intentional fall-through
        case EXT_ROUTING: // Intentional fall-through
        case EXT_DSTOPT: // Intentional fall-through
            if (!(buf[0] & NH_COMPRESSED)) { // [ DIS | NXT | LEN | ... (len)
                len = 2 + buf[2];
                *compressed_len = len + 1;
            } else {  // [ DIS | LEN | ... (len)
                len = 2 + buf[1];
                *compressed_len = len;
                *head = 1;
            }
            return len;
        case EXT_FRAG: // [ DIS | FRAG ...
            len = 8;
            *compressed_len = len;
            return len;
        default: // Something went wrong, bail out..
            return -1;
    }
}

/* Decompresses an extension header pointed to by 'f->net_hdr', according to the
 * NHC_EXT compression scheme */
static uint8_t *
decompressor_nhc_ext(struct pico_frame *f, int32_t *compressed_len, int32_t *decompressed_len)
{
    struct pico_ipv6_exthdr *ext = NULL;
    int32_t len = 0, head = 0, alloc = 0;
    uint8_t *buf = f->net_hdr;
    uint8_t eid = buf[0] & 0x0E;
    uint8_t nh = 0;

    if ((buf[0] & 0xF0) == EXT_DISPATCH) {
        /* Determine compressed header length */
        len = ext_compressed_length(buf, eid, compressed_len, &head);
        if (len >= 0) {
            /* Retrieve next header from following header */
            nh = ext_nh_retrieve(buf, *compressed_len);

            /* Make sure options are 8 octet aligned */
            alloc = (len % 8) ? (((len / 8) + 1) * 8) : (len);
            ext = (struct pico_ipv6_exthdr *)PICO_ZALLOC((size_t)alloc);
            if (ext) {
                buf_move((uint8_t *)ext + head, buf + 1, (size_t)(len - head));
                ext->nxthdr = nh;
                if (EXT_HOPBYHOP == eid || EXT_DSTOPT == eid || EXT_ROUTING) {
                    ext->ext.destopt.len = (uint8_t)((alloc / 8) - 1);
                    ext_align((uint8_t *)ext, alloc, len);
                }
            }
            *decompressed_len = alloc;
            return (uint8_t *)ext;
        }
    }
    return NULL;
}

/* Free's memory of a all assembled chunks for 'n' amount */
static struct pico_frame *
pico_iphc_bail_out(uint8_t **chunks, int32_t n)
{
    int32_t i = 0;
    for (i = 0; i < n; i++) {
        PICO_FREE(chunks[i]);
    }
    return NULL;
}

/* Performs reassembly after either compression of decompression */
static struct pico_frame *
pico_iphc_reassemble(struct pico_frame *f, uint8_t **chunks, int32_t *chunks_len, int32_t n, int32_t processed_len, int32_t handled_len)
{
    uint32_t grow = f->buffer_len;
    struct pico_frame *new = NULL;
    int32_t payload_len = 0;
    uint8_t *dst = NULL;
    int32_t ret = 0, i = 0;

    /* Calculate buffer size including IPv6 payload */
    payload_len = (int32_t)f->len - handled_len;
    processed_len += payload_len; // Length of frame after processing

    /* Reallocate frame size if there isn't enough room available */
    if (f->len < (uint16_t)processed_len) {
        grow = (uint32_t)(grow + (uint32_t)processed_len - f->len);
        ret = pico_frame_grow(f, grow);
        if (ret)
            return pico_iphc_bail_out(chunks, n);
    }

    chunks[n] = f->net_hdr + handled_len; // Start of payload_available
    chunks_len[n] = payload_len; // Size of payload
    n++; // Payload is another chunk to copy

    /* Provide a new frame */
    if (!(new = pico_frame_deepcopy(f)))
        return pico_iphc_bail_out(chunks, n);

    /* Copy each chunk back in the frame starting at the end of the new
     * frame-buffer so we don't overwrite overlapping memory regions */
    dst = new->buffer + new->buffer_len;
    for (i = n - 1; i >= 0; i--) {
        dst -= chunks_len[i];
        buf_move(dst, chunks[i], (size_t)chunks_len[i]);
    }
    new->net_hdr = dst; // Last destination is net_hdr
    new->start = new->net_hdr; // Start of useful data is at net_hdr
    new->len = (uint32_t)processed_len;
    new->transport_len = 0;
    new->payload_len = 0;
    new->app_len = 0;
    new->transport_hdr = new->net_hdr + new->net_len;
    pico_iphc_bail_out(chunks, n - 1); // Success, discard compressed chunk
    if (new->start < new->buffer) {
        pico_frame_discard(new);
        return NULL;
    }
    return new;
}

/* Compresses a frame according to the IPHC, NHC_EXT and NHC_UDP compression scheme */
static struct pico_frame *
pico_iphc_compress(struct pico_frame *f)
{
    int32_t i = 0, compressed_len = 0, loop = 1, uncompressed = f->net_len;
    uint8_t *old_nethdr = f->net_hdr; // Save net_hdr temporary ...
    uint8_t nh = PICO_PROTO_IPV6;
    uint8_t *chunks[8] = { NULL };
    int32_t chunks_len[8] = { 0 };

    do {
        switch (nh) {
            /* IPV6 HEADER */
            case PICO_PROTO_IPV6:
                chunks[i] = compressor_iphc(f, &chunks_len[i], &nh);
                f->net_hdr += 40; // Move after IPv6 header
                f->net_len = (uint16_t)chunks_len[i];
                break;
            /* IPV6 EXTENSION HEADERS */
            case PICO_IPV6_EXTHDR_HOPBYHOP:
            case PICO_IPV6_EXTHDR_ROUTING:
            case PICO_IPV6_EXTHDR_FRAG:
            case PICO_IPV6_EXTHDR_DESTOPT:
                chunks[i] = compressor_nhc_ext(f, &chunks_len[i], &nh);
                f->net_len = (uint16_t)(f->net_len + chunks_len[i]);
                /* f->net_hdr is updated in compresor_nhc_ext with original size */
                break;
            /* UDP HEADER */
            case PICO_PROTO_UDP:
                chunks[i] = compressor_nhc_udp(f, &chunks_len[i]);
                uncompressed += PICO_UDPHDR_SIZE;
                f->transport_len = (uint16_t)chunks_len[i];
            default: /* Intentional fall-through */
                loop = 0;
        }
        /* Check if an error occured */
        if (!chunks[i])
            return pico_iphc_bail_out(chunks, i);
        /* Increment total compressed_len and increase iterator */
        compressed_len += chunks_len[i++];
    } while (compressible_nh(nh) && loop && i < 8);

    f->net_hdr = old_nethdr; // ... Restore old net_hdr
    return pico_iphc_reassemble(f, chunks, chunks_len, i, compressed_len, uncompressed);
}

/* Restore some IPv6 header fields like next header and payload length */
static struct pico_frame *
pico_ipv6_finalize(struct pico_frame *f, uint8_t nh)
{
    struct pico_ipv6_hdr *hdr = NULL;
    if (!f) {
        return NULL;
    } else {
        hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        if (!hdr->nxthdr)
            hdr->nxthdr = nh;
        hdr->len = short_be((uint16_t)(f->len - PICO_SIZE_IP6HDR));
        return f;
    }
}

/* Decompresses a frame according to the IPHC, NHC_EXT and NHC_UDP compression scheme */
static struct pico_frame *
pico_iphc_decompress(struct pico_frame *f)
{
    int32_t i = 0, compressed = 0, loop = 1, uncompressed = 0, ret = 0;
    uint8_t *old_nethdr = f->net_hdr; // Save net_hdr temporary ...
    uint8_t dispatch = PICO_PROTO_IPV6;
    uint8_t *chunks[8] = { NULL };
    struct pico_frame *n = NULL;
    int32_t chunks_len[8] = { 0 };
    uint8_t nh = 0;

    do {
        switch (dispatch) {
            /* IPV6 HEADER */
            case PICO_PROTO_IPV6:
                chunks[i] = decompressor_iphc(f, &ret);
                chunks_len[i] = PICO_SIZE_IP6HDR;
                f->net_len = PICO_SIZE_IP6HDR;
                nh = ext_nh_retrieve(f->net_hdr, ret);
                break;
            /* IPV6 EXTENSION HEADERS */
            case PICO_IPV6_EXTHDR_HOPBYHOP:
            case PICO_IPV6_EXTHDR_ROUTING:
            case PICO_IPV6_EXTHDR_FRAG:
            case PICO_IPV6_EXTHDR_DESTOPT:
                chunks[i] = decompressor_nhc_ext(f, &ret, &chunks_len[i]);
                f->net_len = (uint16_t)(f->net_len + chunks_len[i]);
                break;
            /* UDP HEADER */
            case PICO_PROTO_UDP:
                f->transport_hdr = f->net_hdr; // Switch to transport header
                chunks[i] = decompressor_nhc_udp(f, compressed, &ret);
                chunks_len[i] = PICO_UDPHDR_SIZE;
            default: /* Intentional fall-through */
                loop = 0;
        }
        /* Check if an error occured */
        if (!chunks[i])
            return pico_iphc_bail_out(chunks, i);

        /* Increase compressed and uncompressed length */
        compressed += ret;
        uncompressed += chunks_len[i++];

        /* Get next dispatch header */
        f->net_hdr += ret;
        dispatch = ext_nh_retrieve(f->net_hdr, 0);
    } while (dispatch && loop && i < 8);
    f->net_hdr = old_nethdr; // ... Restore old net_hdr

    /* Reassemble gathererd decompressed buffers */
    n = pico_iphc_reassemble(f, chunks, chunks_len, i, uncompressed, compressed);
    return pico_ipv6_finalize(n, nh);
}

#endif

/* Prepends an uncompressed IPv6 dispatch header */
static void
pico_iphc_no_comp(struct pico_frame *f)
{
    f->net_hdr--; // Only need one bytes
    f->start--;
    f->len++;
    f->net_len++;
    f->net_hdr[0] = IPV6_DISPATCH;
}

/* Removes an uncompressed IPv6 dispatch header */
static void
pico_iphc_no_comp_dec(struct pico_frame *f)
{
    f->net_hdr++;
    f->start++;
    f->len--;
    f->net_len--;
}

/* Updates the fragmentation cookie with how many bytes there are copied and units
 * of 8-octets that are transmitted, if bytes copied equals the size of the datagram
 * the cookie is removed from the cookie-tree and the datagram is discarded */
static int32_t
frag_update(struct pico_frame *f, struct frag_ctx *frag, uint8_t units, uint16_t copy)
{
    frag->dgram_off = (uint8_t)(frag->dgram_off + units);
    frag->copied = (uint16_t)(frag->copied + copy);
    /* Datagram is completely transmitted */
    if (frag->copied >= f->len) {
        lp_dbg("6LP: FIN: "ORG"fragmentation"RST" with hash '%X', sent %u of %u bytes\n", frag->hash, frag->copied, f->len);
        pico_tree_delete(&FragTree, frag);
        PICO_FREE(frag);
        pico_frame_discard(f);
    } else {
        lp_dbg("6LP: UPDATE: "ORG"fragmentation"RST" with hash '%X', sent %u of %u bytes\n", frag->hash, frag->copied, f->len);
        return pico_datalink_send(f);
    }
    return (int32_t)1; // Success
}

static void
frag_fill(uint8_t *frag, uint8_t dispatch, uint16_t dgram_size, uint16_t tag, uint8_t dgram_off, int32_t offset, uint16_t copy, uint16_t copied, uint8_t *buf)
{
    frag[0] = (uint8_t)(dispatch | ((uint8_t)short_be(dgram_size) & 0x07));
    frag[1] = (uint8_t)(short_be(dgram_size) >> 8);
    frag[2] = (uint8_t)(short_be(tag));
    frag[3] = (uint8_t)(short_be(tag) >> 8);
    frag[4] = (uint8_t)(dgram_off);
    buf_move(frag + offset, buf + copied, copy);
}

/* Looks for a fragmentation cookie and creates an n-th fragment frame that it
 * tries to push to the datalink layer, if the entire datagram is transmitted,
 * the fragment cookie is removed from the tree and the datagram is free'd */
static int32_t
frag_nth(struct pico_frame *f)
{
    struct frag_ctx *frag = frag_ctx_find(f->hash);
    uint16_t left = 0;
    uint16_t copy = 0, alloc = FRAGN_SIZE;
    struct pico_frame *n = NULL;
    uint8_t units = 0;
    int32_t avail = 0, ret = 0;

    if (frag) {
        /* Check how many bytes there are available for n-th fragment */
        avail = pico_6lowpan_ll_push(f);
        if (avail > 0) {
            /* Calculate dgram_off and bytes to copy */
            left = (uint16_t)(f->len - frag->copied);
            if (left <= (uint16_t)(avail - FRAGN_SIZE)) {
                copy = left;
            } else {
                units = (uint8_t)((uint16_t)(avail - FRAGN_SIZE) >> 3);
                copy = (uint16_t)(units << 3);
            }
            alloc = (uint16_t)(alloc + copy);

            n = pico_proto_6lowpan_ll.alloc(&pico_proto_6lowpan_ll, f->dev, alloc);
            if (n) {
                frag_fill(n->net_hdr, FRAGN_DISPATCH, frag->dgram_size,
                          frag->dgram_tag, frag->dgram_off, 5, copy,
                          frag->copied, f->net_hdr);
                n->net_len = alloc;
                n->len = (uint32_t)n->net_len;
                n->src = frag->f->src;
                n->dst = frag->f->dst;

                /* Try to push fragment to link layer */
                ret = pico_6lowpan_ll_push(n);
                if (!ret) { // Update frag cookie
                    return frag_update(f, frag, units, copy);
                }
            }
        }
    }

    pico_frame_discard(f);
    return -1;
}

/* Makes a first fragment from a frame and tries to push it to the datalink layer
 * Also enqueues the frame back in the outgoing frame-queue of the 6LOWPAN
 * layer for subsequent fragments */
static int32_t
frag_1st(struct pico_frame *f, uint16_t dgram_size, uint8_t dgram_off, uint16_t copy)
{
    uint16_t alloc = (uint16_t)(copy + FRAG1_SIZE);
    struct pico_frame *n = NULL;
    int32_t ret = 0;

    n = pico_proto_6lowpan_ll.alloc(&pico_proto_6lowpan_ll, f->dev, alloc);
    if (n) {
        frag_fill(n->net_hdr, FRAG1_DISPATCH, dgram_size, dgram_tag, 0, 4, copy, 0,f->net_hdr);
        n->net_len = alloc;
        n->len = (uint32_t)n->net_len;
        n->src = f->src;
        n->dst = f->dst;

        /* Try to push fragment to link layer */
        ret = pico_6lowpan_ll_push(n);
        if (ret) {
            dgram_tag--;
            return -1;
        }

        /* Enqueue the frame again for subsequent fragments */
        f->flags |= PICO_FRAME_FLAG_SLP_FRAG;
        if (pico_datalink_send(f) <= 0)
            return -1;

        /* Everything was a success store a cookie for subsequent fragments */
        return frag_store(f, dgram_size, dgram_tag++, dgram_off, copy, &FragTree);
    } else {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
}

/* Send the first fragment of a uncompressed IPv6 datagram */
static int32_t
frag_1st_no_comp(struct pico_frame *f, uint16_t dgram_size, int32_t available)
{
    /* Available bytes after inserting FRAG1 dispatch and IPv6 dispatch */
    uint16_t rest_size = (uint16_t)(available - FRAG1_SIZE - 1);
    uint8_t dgram_off = (uint8_t)(rest_size >> 3);
    uint16_t copy_size = (uint16_t)(rest_size + 1);
    return frag_1st(f, dgram_size, dgram_off, copy_size);
}

#ifdef PICO_6LOWPAN_IPHC_ENABLED
/* Determines the length of the compressed header */
static uint16_t
frame_comp_hlen(struct pico_frame *f, int32_t udp)
{
    return (uint16_t)(f->net_len + ((udp) ? (f->transport_len) : (0)));
}

/* Send the first fragment of a compressed datagram */
static int32_t
frag_1st_comp(struct pico_frame *f, uint16_t dgram_size, int32_t available, int32_t udp)
{
    /* Calculate amount of bytes that are elided */
    uint16_t comp_diff = (uint16_t)(dgram_size - f->len);
    uint16_t comp_hlen = frame_comp_hlen(f, udp);
    /* Decompressed header length */
    uint16_t deco_hlen = (uint16_t)(comp_hlen + comp_diff);
    /* Available octects after inserting FRAG1 dispatch and compressed header */
    uint16_t rest_size = (uint16_t)(available - FRAG1_SIZE - comp_hlen);
    /* Offset for subsequent fragments in 8-octect units and in octets */
    uint8_t dgram_off = (uint8_t)((uint16_t)(rest_size + deco_hlen) >> 3);
    uint16_t copy_size = 0;
    /* 8-octet aligned available octets after decompression */
    rest_size = (uint16_t)((uint16_t)(dgram_off << 3) - deco_hlen);
    copy_size = (uint16_t)(rest_size + comp_hlen);
    return frag_1st(f, dgram_size, dgram_off, copy_size);
}
#endif

static int32_t
pico_6lowpan_compress(struct pico_frame *f, int32_t avail)
{
    struct pico_ipv6_hdr *ip = (struct pico_ipv6_hdr *)f->net_hdr;
    uint16_t dgram_size = (uint16_t)(short_be(ip->len) + PICO_SIZE_IP6HDR);

#ifdef PICO_6LOWPAN_IPHC_ENABLED
    int32_t udp = (PICO_PROTO_UDP == ip->nxthdr);
    struct pico_frame *try = pico_iphc_compress(f);
    if (try) {
        /* Try to push frame to link layer */
        avail = pico_6lowpan_ll_push(try);
        if (0 < avail && frame_comp_hlen(try, udp) <= (uint16_t)avail) {
            /* RFC6282: any header that cannot fit within the first fragment
             * MUST NOT be compressed. */
            pico_frame_discard(f);
            return frag_1st_comp(try, dgram_size, avail, udp);
        } else if (!avail) {
            pico_frame_discard(f);
            return (int32_t)try->len; // Success, compression was enough
        } else if (0 > avail) {
            pico_frame_discard(try);
            pico_frame_discard(f);
            return -1; // Error pushing compressed frame
        }
        pico_frame_discard(try);
    }
#endif

    pico_iphc_no_comp(f); // Add uncompressed dispatch header again
    return frag_1st_no_comp(f, dgram_size, avail);
}

/* General compression function that first tries to compress the frame and sends
 * it through to the link layer, if that doesn't work the frame is fragmented */
static int32_t
pico_6lowpan_send(struct pico_frame *f)
{
    int32_t avail = 0;
    pico_iphc_no_comp(f); // Add uncrompressed dispatch header ...

    /* Try to push frame to link layer */
    avail = pico_6lowpan_ll_push(f);
    if (avail > 0) {
        pico_iphc_no_comp_dec(f); // ... remove IPv6 Dispatch Header
        return pico_6lowpan_compress(f, avail);
    } else if (!avail) { // Success
        return (int32_t)f->len;
    } else {
        return -1;
    }
}

static int32_t
pico_6lowpan_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);

    /* Check if it's meant for fragmentation */
    if (f->flags & PICO_FRAME_FLAG_SLP_FRAG) {
        return frag_nth(f);
    } else if ((f->net_hdr[0] & 0xF0) != 0x60) {
        lp_dbg("6lowpan - ERROR: not an IPv6 frame\n");
        goto fin;
    } else if (!f->dev || LL_MODE_ETHERNET == f->dev->mode) {
        lp_dbg("6lowpan - ERROR: link layer mode not supported\n");
        goto fin;
    }

    lp_dbg("6LP: ***NEW***, some stats:  ");
    lp_dbg("len: %d net_len: %d transport_len: %d\n", f->len, f->net_len, f->transport_len);

    /* Retrieve link layer addresses */
    if (pico_6lowpan_lls[f->dev->mode].addr_from_net(&f->src, f, 0) ||
        pico_6lowpan_lls[f->dev->mode].addr_from_net(&f->dst, f, 1)) {
        /* Address mode is unspecified, probably destination ll-address is being resolved */
        return (int32_t)f->len;
    }

    return pico_6lowpan_send(f);
fin:
    pico_frame_discard(f);
    return -1;
}

static struct pico_frame *
pico_6lowpan_decompress(struct pico_frame *f)
{
#ifdef PICO_6LOWPAN_IPHC_ENABLED
    struct pico_frame *dec = NULL;
#endif

    if (0) {}
#ifdef PICO_6LOWPAN_IPHC_ENABLED
    else if ((f->net_hdr[0] & 0xE0) == IPHC_DISPATCH) {
        dec = pico_iphc_decompress(f);
        pico_frame_discard(f);
        return dec;
    }
#endif
    else if (f->net_hdr[0] == IPV6_DISPATCH) {
        pico_iphc_no_comp_dec(f);
        return f;
    } else {
        lp_dbg("6LP: RCVD invalid frame\n");
        pico_frame_discard(f);
        return NULL;
    }
}

static int32_t
defrag_new(struct pico_frame *f, uint16_t dgram_size, uint16_t tag, uint16_t off)
{
    struct pico_frame *r = pico_proto_6lowpan_ll.alloc(&pico_proto_6lowpan_ll, f->dev, dgram_size);
    if (r) {
        r->start = r->buffer + (int32_t)(r->buffer_len - (uint32_t)dgram_size);
        r->len = dgram_size;
        r->net_hdr = r->start;
        r->net_len = f->net_len;
        r->transport_len = (uint16_t)(r->len - r->net_len);
        r->src = f->src;
        r->dst = f->dst;
        buf_move(r->net_hdr + off, f->start, f->len);
        if (frag_store(r, dgram_size, tag, 0, (uint16_t)f->len, &ReassemblyTree) < 0) {
            pico_frame_discard(f);
            pico_frame_discard(r);
            return -1;
        }
    }
    pico_frame_discard(f);
    return 1;
}

static int32_t
defrag_update(struct frag_ctx *frag, uint16_t off, struct pico_frame *f)
{
    struct pico_frame *r = frag->f;
    buf_move(r->start + (int32_t)off, f->start, f->len); // Copy at start
    frag->copied = (uint16_t)(frag->copied + (uint16_t)f->len);
    pico_frame_discard(f);
    if (frag->copied >= frag->dgram_size) { // Datagram completely reassembled
        lp_dbg("6LP: FIN: "GRN"reassembly"RST" with tag '%u', stats:  len: %d net: %d trans: %d\n", frag->dgram_tag, r->len, r->net_len, r->transport_len);
        pico_tree_delete(&ReassemblyTree, frag);
        PICO_FREE(frag);
#ifdef PICO_6LOWPAN_IPHC_ENABLED
        r = pico_ipv6_finalize(r, 0);
#endif
        return pico_network_receive(r);
    } else {
        lp_dbg("6LP: UPDATE: "GRN"reassembly"RST" with tag '%u', %u of %u bytes received\n", frag->dgram_tag, frag->copied, frag->dgram_size);
    }
    return (int32_t)r->len;
}

static struct frag_ctx *
defrag_remove_header(struct pico_frame *f, uint16_t *dgram_size, uint16_t *tag, uint16_t *off, int32_t size)
{
    *dgram_size = (uint16_t)(((uint16_t)(f->net_hdr[0] & 0x07) << 8) | (uint16_t)f->net_hdr[1]);
    *tag = (uint16_t)(((uint16_t)f->net_hdr[2] << 8) | (uint16_t)f->net_hdr[3]);
    *off = (uint16_t)((uint16_t)f->net_hdr[4] << 3);
    f->net_len = (uint16_t)(f->net_len - (uint16_t)size);
    f->len = (uint32_t)(f->len - (uint32_t)size);
    f->net_hdr += size;
    f->start = f->net_hdr;
    return frag_find(*dgram_size, *tag, f);
}

static int32_t
defrag(struct pico_frame *f)
{
    uint16_t size = 0, tag = 0, off = 0;
    struct frag_ctx *frag = NULL;

    if ((f->net_hdr[0] & 0xF8) == FRAG1_DISPATCH) {
        frag = defrag_remove_header(f, &size, &tag, &off, FRAG1_SIZE);
        if (!(f = pico_6lowpan_decompress(f)))
            return -1;
        off = 0;
    } else if ((f->net_hdr[0] & 0xF8) == FRAGN_DISPATCH) {
        frag = defrag_remove_header(f, &size, &tag, &off, FRAGN_SIZE);
    } else {
        lp_dbg("6LP: RCVD invalid frame\n");
        pico_frame_discard(f);
        return -1;
    }

    if (frag) {
        return defrag_update(frag, off, f);
    } else {
        return defrag_new(f, size, tag, off);
    }
}

static int32_t
pico_6lowpan_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);

    if (f->net_hdr[0] & 0x80) {
        return defrag(f);
    } else {
        f = pico_6lowpan_decompress(f);
        if (f) {
            lp_dbg("6LP: Decompression finished, stats:  len: %d net: %d trans: %d\n", f->len, f->net_len, f->transport_len);
            return pico_network_receive(f);
        }
        return -1;
    }
}

int32_t
pico_6lowpan_pull(struct pico_frame *f)
{
    if (pico_enqueue(pico_proto_6lowpan.q_in, f) > 0) {
        return (int32_t)f->len; // Success
    }

    pico_frame_discard(f);
    return -1;
}

struct pico_protocol pico_proto_6lowpan = {
    .name = "6lowpan",
    .layer = PICO_LAYER_DATALINK,
    .process_in = pico_6lowpan_process_in,
    .process_out = pico_6lowpan_process_out,
    .q_in = &pico_6lowpan_in,
    .q_out = &pico_6lowpan_out
};

int pico_6lowpan_init(void)
{
    pico_6lowpan_ll_init();
    if (0 == pico_timer_add(1000, frag_timeout, NULL)) {
        return -1; /* We care if timer fails, results in memory leak if frames don't get reassembled */
    }
    return 0;
}

#endif /* PICO_SUPPORT_6LOWPAN */
