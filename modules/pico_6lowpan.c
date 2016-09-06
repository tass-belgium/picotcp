/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_udp.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_802154.h"
#include "pico_6lowpan.h"
#include "pico_protocol.h"
#include "pico_addressing.h"

#ifdef PICO_SUPPORT_6LOWPAN

#define DEBUG_6LOWPAN

/*******************************************************************************
 * Macros
 ******************************************************************************/

#ifdef DEBUG_6LOWPAN
#define lp_dbg dbg
#else
#define lp_dbg(...) do {} while(0)
#endif

#define IPV6_MCAST_48(addr) (!(*(uint16_t *)&addr[8]) && !addr[10] && (addr[11] || addr[12]))
#define IPV6_MCAST_32(addr) (!(*(uint32_t *)&addr[8]) && !addr[12] && (addr[13] || addr[14]))
#define IPV6_MCAST_8(addr)  (addr[1] == 0x02 && !addr[14] && addr[15])

#define PORT_COMP_0xFO(p)   (((p) & short_be(0xFF00)) == short_be(0xF000))
#define PORT_COMP_0xF0B(p)  (((p) & short_be(0xFFF0)) == short_be(0xF0B0))

/*******************************************************************************
 * Constants
 ******************************************************************************/

#define NUM_IPV6_FIELDS     (6)
#define NUM_UDP_FIELDS      (4)
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

/*******************************************************************************
 * Type definitions
 ******************************************************************************/

typedef int (*compressor_t)(uint8_t *, uint8_t *, uint8_t *, union pico_ll_addr
                            *, union pico_ll_addr *, struct pico_device *);

typedef struct hdr_field
{
    int ori_size;
    compressor_t compress;
    compressor_t decompress;
}
hdr_field_t;

struct iphc_ctx
{
    struct pico_ip6 prefix;
    uint8_t id;
    int size;
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

/*******************************************************************************
 *  Function prototypes
 ******************************************************************************/

static int pico_6lowpan_ll_iid(uint8_t iid[8], union pico_ll_addr *addr, struct pico_device *dev);
static int pico_6lowpan_ll_mac_derived(struct pico_ip6 *addr, union pico_ll_addr *lladdr, struct pico_device *dev);
static int pico_6lowpan_ll_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst);
static int pico_6lowpan_ll_addr(struct pico_frame *f, union pico_ll_addr *addr, int dst);
static struct pico_frame *pico_6lowpan_ll_frame(uint16_t size, struct pico_device *dev);

/*******************************************************************************
 *  CTX
 ******************************************************************************/

/* Compares if the IPv6 prefix of two IPv6 addresses match */
static int
compare_prefix(uint8_t *a, uint8_t *b, int len)
{
    uint8_t bitmask = (uint8_t)(0xff >> (8 - (len % 8)));
    size_t bytes = (size_t)len / 8;
    int ret = 0;
    if ((ret = memcmp(a, b, bytes)))
        return ret;
    return (int)((a[bytes] & bitmask) - (b[bytes] & bitmask));
}

/* Compares 2 IPHC context entries */
static int
compare_ctx(void *a, void *b)
{
    struct iphc_ctx *ca = (struct iphc_ctx *)a;
    struct iphc_ctx *cb = (struct iphc_ctx *)b;
    return compare_prefix(ca->prefix.addr, cb->prefix.addr, ca->size);
}

PICO_TREE_DECLARE(CTXtree, compare_ctx);

/* Searches in the context tree if there's a context entry available with the
 * prefix of the IPv6 address */
static struct iphc_ctx *
ctx_lookup(struct pico_ip6 addr)
{
    struct iphc_ctx test = { addr, 0, 0 };
    return pico_tree_findKey(&CTXtree, &test);
}

/* Looks up the context by ID, for decompression */
static struct iphc_ctx *
ctx_lookup_id(uint8_t id)
{
    struct iphc_ctx *key = NULL;
    struct pico_tree_node *i = NULL;

    pico_tree_foreach(i, &CTXtree) {
        key = i->keyValue;
        if (key && id ==key->id)
            return key;
    }
    return NULL;
}

/* Deletes a context with a certain prefix from the context tree. The ctx is
 * either found and deleted, or not found, don't care. */
static void
ctx_remove(struct pico_ip6 addr)
{
    struct iphc_ctx test = { addr, 0, 0}, *key = NULL;
    if ((key = pico_tree_delete(&CTXtree, &test)))
        PICO_FREE(key);
}

/* Tries to insert a new IPHC-context into the Context-tree */
static int
ctx_insert(struct pico_ip6 addr, uint8_t id, int size)
{
    struct iphc_ctx *new = PICO_ZALLOC(sizeof(struct iphc_ctx));
    if (new) {
        new->prefix = addr;
        new->id = id;
        new->size = size;
        if (pico_tree_insert(&CTXtree, new)) {
            PICO_FREE(new);
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

/*******************************************************************************
 *  IPHC
 ******************************************************************************/

/* Compresses the VTF-field of an IPv6 header */
static int
compressor_vtf(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
               llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    uint8_t ecn = 0, dscp = 0, fl1 = 0, fl2 = 0, fl3 = 0;
    *ori &= 0x0F; // Clear version field
    *iphc &= (uint8_t)0x07; // Clear IPHC field
    *iphc |= (uint8_t)IPHC_DISPATCH;
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);

    /* Don't worry... */
    ecn = (uint8_t)(*ori << 4) & 0xC0;      // hdr: [v|v|v|v|e|e|_|_] << 4
    dscp = (uint8_t)(*ori++ << 4) & 0x30;   //      [_|_|_|_|_|_|d|d] << 4
    dscp |= (*ori & 0xF0) >> 4;             //  ...][d|d|d|d|_|_|_|_] >> 4
    fl1 = *ori++ & 0x0F;                    //  ...][_|_|_|_|f|f|f|f]
    fl2 = *ori++;                           // 2B..][f|f|f|f|f|f|f|f]
    fl3 = *ori;                             // 3B..][f|f|f|f|f|f|f|f]

    lp_dbg("ECN: %02X DSCP: %02X FL1: %02X FL2: %02X FL3: %02X\n", ecn, dscp,
           fl1, fl2, fl3);

    if (!dscp && !fl1 && !fl2 && !fl3 && !ecn) {
        *iphc |= TF_ELIDED;
        return 0;
    } else if (!dscp && (fl3 || fl2 || fl1)) {
        *iphc |= TF_ELIDED_DSCP;
        *comp++ = ecn | fl1;
        *comp++ = fl2;
        *comp = fl3;
        return 3;
    } else if ((ecn || dscp) && !fl3 && !fl2 && !fl1) {
        *iphc |= TF_ELIDED_FL;
        *comp = ecn | dscp;
        return 1;
    } else {
        *iphc |= TF_INLINE;
        *comp++ = ecn | dscp;
        *comp++ = fl1 & 0x0F;
        *comp++ = fl2;
        *comp = fl3;
        return 4;
    }
}

/* Decompresses the VTF-field of a IPHC-header */
static int
decompressor_vtf(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    uint8_t tf = *iphc & TF_ELIDED;
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    if (TF_INLINE == tf) {
        *ori++ = (0x60 | (*comp >> 4));
        *ori |= (uint8_t)((*comp++ << 4) & 0xF0);
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
static int
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
static int
compressor_nh(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
               llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    *iphc &= (uint8_t)~NH_COMPRESSED;
    IGNORE_PARAMETER(comp);
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    if (compressible_nh(*ori))
        *iphc |= NH_COMPRESSED;
    return 0;
}

/* Check whether or no the next header is NHC-compressed, indicates this for the
 * general decompressor so it knows that it has to decompress the next header
 * and fill in the NH-header field in IPv6 header */
static int
decompressor_nh(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    IGNORE_PARAMETER(llsrc);
    IGNORE_PARAMETER(lldst);
    IGNORE_PARAMETER(dev);
    IGNORE_PARAMETER(comp);
    if (*iphc & NH_COMPRESSED) {
        *ori = NH_COMPRESSED; // Indicate that next header needs to be decompressed
    } else {
        *ori = 0;
    }
    return 0;
}

/* Compressed the HL-field if common hop limit values are used, like 1, 64 and
 * 255 */
static int
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
        default:
            *comp = *ori;
            return 1;
    }
}

/* Decompresses the HL-field to common hop limit values like 1, 64 and 255 */
static int
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
        default:
            *ori = *comp;
            return 1;
    }
}

/* Determines if an address can be statefully or statelessly compressed */
static int
addr_comp_prefix(uint8_t *iphc, struct pico_ip6 *addr, int src)
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
        iphc[1] |= state; // AC = 1
        iphc[1] |= CTX_EXTENSION; // SRC or DST is stateful, CID = 1
        return ctx->id;
    } else {
        return COMP_STATELESS; // AC = 0
    }
}

/* Sets the compression mode of either the source address or the destination
 * address, based on the shift parameter. Use SRC_SHIFT for source, 0 for dst */
static int
addr_comp_mode(uint8_t *iphc, struct pico_ip6 *addr, union pico_ll_addr lladdr,
               struct pico_device *dev, int shift)
{
    int mac = pico_6lowpan_ll_mac_derived(addr, &lladdr, dev);
    iphc[1] &= (uint8_t)(~DST_COMPRESSED << shift); // Clear out mode for src/dst

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
static int
addr_comp_mcast(uint8_t *iphc, uint8_t *comp, struct pico_ip6 *mcast)
{
    iphc[1] &= (uint8_t)~DST_MCAST_8; // Clear out addressing mode
    iphc[1] |= (uint8_t)DST_MULTICAST; // Set multicast flag

    if (IPV6_MCAST_48(mcast->addr)) {
        comp[0] = mcast->addr[1]; // Copy flags and scope
        memcpy(&comp[1], &mcast->addr[11], 5); // Copy group identifier
        iphc[1] |= DST_MCAST_48;
        return 6;
    } else if (IPV6_MCAST_32(mcast->addr)) {
        comp[0] = mcast->addr[1]; // Copy flags and scope
        memcpy(&comp[1], &mcast->addr[13], 3); // Copy group identifier
        iphc[1] |= DST_MCAST_32;
        return 4;
    } else if (IPV6_MCAST_8(mcast->addr)) {
        comp[0] = mcast->addr[15]; // Copy group identifier
        iphc[1] |= DST_MCAST_8; // Flags and scope = 0x02
        return 1;
    } else {
        memcpy(comp, mcast->addr, PICO_SIZE_IP6); // Copy entire address
        return PICO_SIZE_IP6;
    }
}

/* Compresses the IID of a IPv6 address into 'comp'. Also has to take link layer
 * address into account and whether it's about source or destination address. */
static int
addr_comp_iid(uint8_t *iphc, uint8_t *comp, int state, struct pico_ip6 *addr,
              union pico_ll_addr ll, struct pico_device *dev, int shift)
{
    int len = 16;
    switch (state) {
        case COMP_UNSPECIFIED: // Unspecified, address
            iphc[1] |= SRC_STATEFUL; // Intentional fall-through
        case COMP_STATELESS: // No context available, carry address inline
            iphc[1] &= (uint8_t)~SRC_COMPRESSED;
            break;
        case COMP_LINKLOCAL: // Link local, elide prefix, check for IID
            len = addr_comp_mode(iphc, addr, ll, dev, shift);
            break;
        case COMP_MULTICAST: // Multicast, compress statelessly
            if (!shift) {
                return addr_comp_mcast(iphc, comp, addr);
            } else { // SOURCE can't be multicast, trigger error
                return -1;
            }
        default: // Context available, extend header, and check for IID
            iphc[2] = (uint8_t)((uint8_t)state << shift);
            len = addr_comp_mode(iphc, addr, ll, dev, shift);
    }

    if (len >= 0)
        memcpy(comp, addr->addr + 16 - len, (size_t)len);
    return len;
}

/* Compresses the SOURCE address of the IPv6 frame */
static int
compressor_src(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
               llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    struct pico_ip6 src = *(struct pico_ip6 *)ori;
    int ret = addr_comp_prefix(iphc, &src, SRC_SHIFT);
    IGNORE_PARAMETER(lldst);

    if (pico_ipv6_is_unspecified(src.addr))
        ret = COMP_UNSPECIFIED;

    return addr_comp_iid(iphc, comp, ret, &src, *llsrc, dev, SRC_SHIFT);
}

/* Copies the appropriate IPv6 prefix in the decompressed address. Based on
 * context, link local address or multicast address */
static int
addr_decomp_prefix(uint8_t *prefix, uint8_t *iphc, int shift)
{
    struct pico_ip6 ll = { .addr = {0xfe,0x80,0,0,0,0,0,0,0,0,0,0xff,0xfe,0,0,0}};
    uint8_t addr_state = (uint8_t)(DST_STATEFUL << shift);
    struct iphc_ctx *ctx = NULL;

   if (iphc[1] & addr_state) {
        if ((ctx = ctx_lookup_id((uint8_t)(iphc[2] >> shift)))) {
            memcpy(prefix, ctx->prefix.addr, PICO_SIZE_IP6);
            memcpy(&prefix[8], &ll.addr[8], 8); // For 16-bit derived addresses
        } else {
            /* No context available while stateful compression is used... */
            return -1;
        }
    } else {
        memcpy(prefix, ll.addr, PICO_SIZE_IP6);
    }
    return 0;
}

/* Decompresses the IID of the IPv6 address based on addressing mode of the IPHC-
 * header */
static int
addr_decomp_iid(struct pico_ip6 *addr, uint8_t *comp, uint8_t am, union
                pico_ll_addr lladdr, struct pico_device *dev)
{
    switch (am) {
        case DST_COMPRESSED_64:
            memcpy(&addr->addr[8], comp, 8);
            return 8;
        case DST_COMPRESSED_16:
            memcpy(&addr->addr[14], comp, 2);
            return 2;
        case DST_COMPRESSED:
            pico_6lowpan_ll_iid(&addr->addr[8], &lladdr, dev);
            return 0;
        default:
            memcpy(addr->addr, comp, PICO_SIZE_IP6);
            return 16;
    }
}

/* Decompress the SOURCE address of the 6LoWPAN frame */
static int
decompressor_src(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    struct pico_ip6 *src = (struct pico_ip6 *)ori;
    uint8_t sam = (uint8_t)((iphc[1] & SRC_COMPRESSED) >> 4);
    IGNORE_PARAMETER(lldst);

    /* Get the appropriate IPv6 prefix */
    if (addr_decomp_prefix(ori, iphc, SRC_SHIFT))
        return -1;

    return addr_decomp_iid(src, comp, sam, *llsrc, dev);
}

/* Compresses the DESTINATION address of IPv6 frame */
static int
compressor_dst(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr *
               llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
{
    struct pico_ip6 dst = *(struct pico_ip6 *)ori;
    int ret = addr_comp_prefix(iphc, &dst, 0);
    IGNORE_PARAMETER(llsrc);
    return addr_comp_iid(iphc, comp, ret, &dst, *lldst, dev, 0);
}

/* Decompresses the IPv6 multicast destination address when the IPHC mcast-flag
 * is set */
static int
addr_decomp_mcast(uint8_t *comp, struct pico_ip6 *dst, uint8_t am)
{
    memset(dst->addr, 0, PICO_SIZE_IP6);
    dst->addr[0] = 0xff;
    dst->addr[1] = *comp;
    switch (am) {
        case DST_MCAST_48:
            memcpy(dst->addr + 11, comp + 1, 5);
            return 6;
        case DST_MCAST_32:
            memcpy(dst->addr + 13, comp + 1, 3);
            return 4;
        case DST_MCAST_8:
            dst->addr[1] = 0x02;
            dst->addr[15] = *comp;
            return 1;
        default:
            memcpy(dst->addr, comp, PICO_SIZE_IP6);
            return PICO_SIZE_IP6;
    }
}

/* Decompresses the DESTINATION address of a 6LoWPAN frame */
static int
decompressor_dst(uint8_t *ori, uint8_t *comp, uint8_t *iphc, union pico_ll_addr
                 *llsrc, union pico_ll_addr *lldst, struct pico_device *dev)
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

static const hdr_field_t ip6_fields[] = {
    {4, compressor_vtf, decompressor_vtf},
    {2, NULL, NULL},
    {1, compressor_nh, decompressor_nh},
    {1, compressor_hl, decompressor_hl},
    {16, compressor_src, decompressor_src},
    {16, compressor_dst, decompressor_dst}
};

/* Pointer to originally allocated inline buffer to compressed IPv6 header into */
static uint8_t *
iphc_original_buffer(uint8_t *iphc)
{
    if (!(iphc[1] & CTX_EXTENSION))
        return (uint8_t *)(iphc - 1);
    return iphc;
}

/* Compresses the IPv6 frame according to the IPHC-compression scheme */
static uint8_t *
compressor_iphc(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr
                dst, int *compressed_len, uint8_t *nh)
{
    uint8_t *inline_buf = PICO_ZALLOC(PICO_SIZE_IP6HDR + 3);
    uint8_t *comp = inline_buf + 3;
    uint8_t *iphc = inline_buf;
    uint8_t *ori = f->net_hdr;
    int i = 0, ret = 0;
    *compressed_len = 0;
    *nh = ((struct pico_ipv6_hdr *)f->net_hdr)->nxthdr;

    if (!inline_buf)
        return NULL;

    /* Compress fixed IPv6 fields */
    for (i = 0; i < NUM_IPV6_FIELDS; i++) {
        if (ip6_fields[i].compress) {
            ret = ip6_fields[i].compress(ori, comp, iphc, &src, &dst, f->dev);
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
        memcpy(inline_buf + 2, inline_buf + 3, *compressed_len);
        *compressed_len += 2;
    }
    return inline_buf;
}

/* Decompresses a frame compressed with the IPHC compression scheme, RFC6282 */
static uint8_t *
decompressor_iphc(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr
                  dst, int *compressed_len)
{
    uint8_t *ipv6_hdr = PICO_ZALLOC(PICO_SIZE_IP6HDR);
    uint8_t *iphc = f->net_hdr;
    uint8_t *ori = ipv6_hdr;
    uint8_t *comp = NULL;
    int i = 0, ret = 0, ctx = f->net_hdr[1] & CTX_EXTENSION;

    *compressed_len = ctx ? 3 : 2;
    comp = f->net_hdr + ((ctx) ? 3 : 2);

    if (!ipv6_hdr)
        return NULL;

    /* Decompress IPHC header */
    for (i = 0; i < NUM_IPV6_FIELDS; i++) {
        if (ip6_fields[i].decompress) {
            ret = ip6_fields[i].decompress(ori, comp, iphc, &src, &dst, f->dev);
            if (ret < 0) { // Something went wrong ...
                PICO_FREE(ipv6_hdr);
                return NULL;
            }
            *compressed_len += ret; // Increase compressed size
            comp += ret; // Move to next compressed chunk
        }
        ori += ip6_fields[i].ori_size; // Move to next IPv6 field
    }

    return ipv6_hdr;
}

/* Compresses a UDP header according to the NHC_UDP compression scheme, RFC6282 */
static uint8_t *
compressor_nhc_udp(struct pico_frame *f, int *compressed_len)
{
    uint8_t *inline_buf = PICO_ZALLOC(PICO_UDPHDR_SIZE + 1);
    struct pico_udp_hdr *hdr = (struct pico_udp_hdr *)f->transport_hdr;
    uint16_t sport = hdr->trans.sport;
    uint16_t dport = hdr->trans.dport;
    *compressed_len = 0;

    if (!inline_buf) {
        return NULL;
    } else {
        /* Dispatch header */
        inline_buf[0] = (uint8_t)UDP_DISPATCH;
        /* Port compression */
        if (PORT_COMP_0xF0B(sport) && PORT_COMP_0xF0B(dport)) {
            inline_buf[0] |= UDP_COMPRESSED_BOTH;
            inline_buf[1] = (uint8_t)(short_be(sport) << 4);
            inline_buf[1] |= (uint8_t)(((uint8_t)short_be(dport)) & 0x0F);
            *compressed_len = 2;
        } else if (PORT_COMP_0xFO(sport)) {
            inline_buf[0] |= UDP_COMPRESSED_SRC;
            inline_buf[1] = (uint8_t)short_be(sport);
            memcpy(inline_buf + 2, (uint8_t *)hdr + 2, 2);
            *compressed_len = 4;
        } else if (PORT_COMP_0xFO(dport)) {
            inline_buf[0] |= UDP_COMPRESSED_DST;
            inline_buf[3] = (uint8_t)short_be(dport);
            memcpy(inline_buf + 1, (uint8_t *)hdr, 2);
            *compressed_len = 4;
        } else {
            inline_buf[0] &= (uint8_t)~UDP_COMPRESSED_BOTH;
            memcpy(inline_buf + 1, (uint8_t *)hdr, 4);
            *compressed_len = 5;
        }
        /* Length and checksum carried inline.
         * RFC6282: .., a compressor in the source transport endpoint MAY elide
         * the UDP checksum if it is autorized by the upper layer. The compressor
         * MUST NOT set the C bit unless it has received such authorization */
        memcpy(inline_buf + *compressed_len, (uint8_t *)hdr + 4, 4);
        *compressed_len += 4;
        return inline_buf;
    }
}

/* Decompresses a NHC_UDP header according to the NHC_UDP compression scheme */
static uint8_t *
decompressor_nhc_udp(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr
                     dst, int *compressed_len)
{
    struct pico_udp_hdr *hdr = PICO_ZALLOC(PICO_UDPHDR_SIZE);
    uint8_t *buf = f->transport_hdr;
    uint8_t compression = buf[0] & UDP_COMPRESSED_BOTH;
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);

    if (hdr && ((buf[0] & 0xF8) == UDP_DISPATCH)) {
        /* Decompress ports */
        if (UDP_COMPRESSED_BOTH == compression) {
            hdr->trans.sport = short_be(0xF0B0) | short_be((uint16_t)(buf[1] >> 4));
            hdr->trans.dport = short_be(0xF0B0) | short_be((uint16_t)(buf[1] & 0xff));
            *compressed_len = 2;
        } else if (UDP_COMPRESSED_SRC == compression) {
            hdr->trans.dport = *(uint16_t *)&buf[2];
            hdr->trans.sport = short_be(0xF000) | short_be((uint16_t)buf[1]);
            *compressed_len = 4;
        } else if (UDP_COMPRESSED_DST == compression) {
            hdr->trans.sport = *(uint16_t *)&buf[1];
            hdr->trans.dport = short_be(0xF000) | short_be((uint16_t)buf[3]);
            *compressed_len = 4;
        } else {
            memcpy((uint8_t *)&hdr->trans, &buf[1], 4);
            *compressed_len = 5;
        }
        /* Restore inline length and checksum */
        if (buf[0] & UDP_COMPRESSED_CHCK) { // Leave empty room for checksum
                memcpy((uint8_t *)&hdr->len, (uint8_t *)(buf + *compressed_len),2);
        } else {
                memcpy((uint8_t *)&hdr->len, (uint8_t *)(buf + *compressed_len),4);
        }
        *compressed_len += 4;
        return (uint8_t *)hdr;
    } else {
        return NULL;
    }
}

/* Get's the length of an IPv6 extension header  */
static int
ext_hdr_len(struct pico_ipv6_exthdr *ext, uint8_t hdr, uint8_t *dispatch)
{
    int len = 0;
    /* Get length of extension header */
    switch (hdr) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
            *dispatch |= (uint8_t)EXT_HOPBYHOP;
            len = IPV6_OPTLEN(ext->ext.destopt.len); // Length in bytes
            ext->ext.destopt.len = (uint8_t)(len - 2); // Octets after len-field
            return (int)len;
        case PICO_IPV6_EXTHDR_ROUTING:
            *dispatch |= (uint8_t)EXT_ROUTING;
            len = IPV6_OPTLEN(ext->ext.destopt.len); // Length in bytes
            ext->ext.destopt.len = (uint8_t)(len - 2); // Octets after len-field
            return (int)len;
        case PICO_IPV6_EXTHDR_DESTOPT:
            *dispatch |= (uint8_t)EXT_DSTOPT;
            len = IPV6_OPTLEN(ext->ext.destopt.len); // Length in bytes
            ext->ext.destopt.len = (uint8_t)(len - 2); // Octets after len-field
            return (int)len;
        case PICO_IPV6_EXTHDR_FRAG:
            *dispatch |= (uint8_t)EXT_FRAG;
            return (int)8;
        default: // Somethin went wrong, bail out...
            return -1;
    }
}

/* Compresses an IPv6 extension header according to the NHC_EXT compression
 * scheme */
static uint8_t *
compressor_nhc_ext(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr
                   dst, int *compressed_len, uint8_t *nh)
{
    struct pico_ipv6_exthdr *ext = (struct pico_ipv6_exthdr *)f->net_hdr;
    uint8_t dispatch = EXT_DISPATCH;
    int len = 0, lead = 0, ret = 0;
    uint8_t *buf = NULL;
    uint8_t hdr = *nh;
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);

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
            memcpy(buf + lead, (uint8_t *)ext, (size_t)(len - lead));
            buf[0] = dispatch; // Set the dispatch header
            *compressed_len = len;
            f->net_hdr += *compressed_len; // Move to next header
            return buf;
        }
    }
}

/* Retrieves the next header from the immediately following header */
static uint8_t
ext_nh_retrieve(uint8_t *buf, int len)
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
}

/* RFC6282: A decompressor MUST ensure that the
 * containing header is padded out to a multiple of 8 octets in length,
 * using a Pad1 or PadN option if necessary. */
static int
ext_align(uint8_t *buf, int alloc, int len)
{
    int padlen = alloc - len;
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
static int
ext_compressed_length(uint8_t *buf, uint8_t eid, int *compressed_len, int *head)
{
    int len = 0;
    switch (eid) {
        case EXT_HOPBYHOP: // Intentional
        case EXT_ROUTING: // Intentional
        case EXT_DSTOPT: // Intentional
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
decompressor_nhc_ext(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr
                     dst, int *compressed_len)
{
    struct pico_ipv6_exthdr *ext = NULL;
    int len = 0, head = 0, alloc = 0;
    uint8_t *buf = f->net_hdr;
    uint8_t eid = buf[0] & 0x0E;
    uint8_t nh = 0;
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);

    if ((buf[0] & 0xF0) == EXT_DISPATCH) {
        /* Determine compressed header length */
        len = ext_compressed_length(buf, eid, compressed_len, &head);
        if (len < 0)
            return NULL;

        /* Retrieve next header from followin header */
        nh = ext_nh_retrieve(buf, *compressed_len);

        /* Make sure options are 8 octet aligned */
        alloc = (len % 8) ? (((len / 8) + 1) * 8) : (len);
        ext = (struct pico_ipv6_exthdr *)PICO_ZALLOC((size_t)alloc);
        if (ext) {
            memcpy((uint8_t *)ext + head, buf + 1, (size_t)(len - head));
            ext->nxthdr = nh;
            if (EXT_HOPBYHOP == eid || EXT_DSTOPT == eid || EXT_ROUTING) {
                ext->ext.destopt.len = (uint8_t)((alloc / 8) - 1);
                ext_align((uint8_t *)ext, alloc, len);
            }
        }
        return (uint8_t *)ext;
    } else {
        return NULL;
    }
}

static int
pico_iphc_bail_out(uint8_t *chunks[], int n)
{
    int i = 0;
    for (i = 0; i < n; i++) {
        PICO_FREE(chunks[i]);
    }
    return -1;
}


static struct pico_frame *
pico_iphc_reassemble(struct pico_frame *f, uint8_t *chunks[], int chunks_len[],
                     int n, int compressed, int uncompressed)
{
    uint32_t grow = f->buffer_len;
    struct pico_frame *new = NULL;
    int payload_len = 0;
    uint8_t *dst = NULL;
    int ret = 0, i = 0;

    /* Is the frame large enough */
    if (f->len < (uint16_t)compressed) {
        grow = (uint32_t)(grow + (uint32_t)(compressed - f->len));
        ret = pico_frame_grow(f, grow);
    }

    /* Calculate buffer size including IPv6 payload */
    payload_len = (int)(f->len - uncompressed);
    compressed += payload_len;

    chunks[n] = f->net_hdr + uncompressed; // Start of payload_available
    chunks_len[n] = payload_len; // Size of payload
    n++; // Payload is another chunk to copy

    /* Provide a new frame */
    new = pico_frame_deepcopy(f);
    if (!ret && new) {
        dst = new->net_hdr;
        lp_dbg("Reassembling %d chunks into 1 compressed frame\n", n);
        for (i = 0; i < n; i++) { // Copy each compressed chunk, including payload
            lp_dbg("Copying chunk of %d bytes...\n", chunks_len[i]);
            memcpy(dst, chunks[i], (size_t)chunks_len[i]);
            dst += chunks_len[i];
        }
        new->start = new->net_hdr;
        new->len = (uint32_t)compressed;
        pico_iphc_bail_out(chunks, n-1); // Success, discard compressed chunks
        pico_frame_discard(f); // Success, safe to discard original frame
        return new;
    } else {
        pico_iphc_bail_out(chunks, n-1); // -1, payload chunk is not alloc'ed
        return NULL;
    }
}

static struct pico_frame *
pico_iphc_compress(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    int i = 0, compressed_len = 0, loop = 1, uncompressed = f->net_len;
    int payload_len = 0;
    uint8_t *old_nethdr = f->net_hdr; // Save net_hdr temporary ... :
    uint8_t nh = PICO_PROTO_IPV6;
    uint8_t *chunks[8] = { NULL };
    int chunks_len[8] = { 0 };

    do {
        switch (nh) {
            case PICO_PROTO_IPV6:
                chunks[i] = compressor_iphc(f, src, dst, &chunks_len[i], &nh);
                f->net_hdr += 40; // Move after IPv6 header
                break;
            case PICO_PROTO_UDP:
                chunks[i] = compressor_nhc_udp(f, &chunks_len[i]);
                uncompressed += PICO_UDPHDR_SIZE;
                loop = 0;
                break;
            case PICO_IPV6_EXTHDR_HOPBYHOP:
            case PICO_IPV6_EXTHDR_ROUTING:
            case PICO_IPV6_EXTHDR_FRAG:
            case PICO_IPV6_EXTHDR_DESTOPT:
                chunks[i] = compressor_nhc_ext(f, src, dst, &chunks_len[i], &nh);
                break;
            default:
                loop = 0;
        }
        /* Check if an error occured */
        if (!chunks[i])
            pico_iphc_bail_out(chunks, i);
        /* Increment total compressed_len and increase iterator */
        compressed_len += chunks_len[i++];
    } while (compressible_nh(nh) && loop && i < 8);

    f->net_hdr = old_nethdr; // ... Restore old net_hdr
    return pico_iphc_reassemble(f, chunks, chunks_len, i, compressed_len, uncompressed);
}

static int
pico_6lowpan_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    union pico_ll_addr llsrc;
    union pico_ll_addr lldst;
    int payload_available = 0;
    IGNORE_PARAMETER(self);

    if (f->flags & PICO_FRAME_FLAG_SLP_FRAG) {
        /* TODO: Send frame straight to subsequent fragmentation function */
    }

    if (pico_6lowpan_ll_addr(f, &llsrc, 0) || pico_6lowpan_ll_addr(f, &lldst, 1)) {
        /* Failure, discard frame, bail out */
        pico_frame_discard(f);
        return -1;
    }

    /* Try to push the frame to the device like everything is gonna be okay :) */
    payload_available = pico_6lowpan_ll_push(f, llsrc, lldst);

    if (payload_available > 0) {
        /* Okay okay, I'll send it through compression */
        /* TODO: Send frame to compression, pass payload_available */
    } else if (payload_available < 0) {
        /* Failure, discard frame, bail out */
        pico_frame_discard(f);
        return -1;
    }

    /* Wow! That did actually work, I have nothing to do here anymore */
    return 0;
}

static int
pico_6lowpan_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(f);

    return 0;
}

static struct pico_frame *
pico_6lowpan_frame_alloc(struct pico_protocol *self, uint16_t size)
{
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(size);

    /* TODO: Update to extended alloc-function with device as in PR #406 */

    return NULL;
}

struct pico_protocol pico_proto_6lowpan = {
    .name = "6lowpan",
    .layer = PICO_LAYER_DATALINK,
    .alloc = pico_6lowpan_frame_alloc,
    .process_in = pico_6lowpan_process_in,
    .process_out = pico_6lowpan_process_out,
    .q_in = &pico_6lowpan_in,
    .q_out = &pico_6lowpan_out
};

/*******************************************************************************
 *  GENERIC 6LOWPAN LINK LAYER
 ******************************************************************************/

static struct pico_frame *pico_6lowpan_ll_frame(uint16_t size, struct pico_device *dev)
{
    struct pico_frame *f;
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        /* TODO: Update to pico_protocol's alloc function */
        f = pico_frame_alloc(size);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        lp_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return NULL;
    }
    return f;
}

static int pico_6lowpan_ll_iid(uint8_t iid[8], union pico_ll_addr *addr, struct pico_device *dev)
{
    if (0) {}

#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        addr_802154_iid(iid, addr);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        lp_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return -1;
    }
    return 0;
}

static int pico_6lowpan_ll_len(union pico_ll_addr *addr, struct pico_device *dev)
{
    if (0) {}

#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        return addr_802154_len(addr);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif

    lp_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
    return -1;
}

static int pico_6lowpan_ll_mac_derived(struct pico_ip6 *addr, union pico_ll_addr *lladdr, struct pico_device *dev)
{
    uint8_t iid[8] = {0};
    if (pico_6lowpan_ll_iid(iid, lladdr, dev))
        return -1;
    return (int)(0 == memcmp(iid, &addr->addr[8], 8));
}

static int pico_6lowpan_ll_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    if (0) {}

#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == f->dev->mode) {
        return frame_802154_push(f, src, dst);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    /* No 6LoWPAN link layer protocols are supported */
    lp_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
    return -1;
}

static int pico_6lowpan_ll_addr(struct pico_frame *f, union pico_ll_addr *addr, int dest)
{
    struct pico_ip6 src = ((struct pico_ipv6_hdr *)f->net_hdr)->src;
    struct pico_ip6 dst = ((struct pico_ipv6_hdr *)f->net_hdr)->dst;

    if (0) {}

#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == f->dev->mode) {
        *addr = addr_802154(&src, &dst, f->dev, dest);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        /* No 6LoWPAN link layer protocols are supported */
        lp_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return -1;
    }
    return 0;
}

#endif /* PICO_SUPPORT_6LOWPAN */
