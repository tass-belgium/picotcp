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
#define FRAG_TIMEOUT        (10)
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

struct frag_ctx {
    struct pico_frame *f;
    uint16_t dgram_size;
    uint16_t dgram_tag;
    uint16_t dgram_off;
    uint16_t copied;
    uint16_t avail;
    union pico_ll_addr src;
    union pico_ll_addr dst;
    uint32_t hash;
    uint32_t timer;
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
 *  Function prototypes
 ******************************************************************************/

static int pico_6lowpan_ll_iid(uint8_t iid[8], union pico_ll_addr *addr, struct pico_device *dev);
static int pico_6lowpan_ll_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst);
static int pico_6lowpan_ll_addr(struct pico_frame *f, union pico_ll_addr *addr, int dst);
static int pico_6lowpan_ll_cmp(union pico_ll_addr *a, union pico_ll_addr *b, struct pico_device *dev);
static struct pico_frame *pico_6lowpan_frame_alloc(uint16_t size, struct pico_device *dev);

/*******************************************************************************
 *  CTX
 ******************************************************************************/

/* Compares two fragmentation cookies based on the hash */
static int
frag_ctx_cmp(void *a, void *b)
{
    struct frag_ctx *fa = (struct frag_ctx *)a;
    struct frag_ctx *fb = (struct frag_ctx *)b;
    return (int)(fa->hash - fb->hash);
}

/* Compares two fragmentation cookies according to RFC4944 5.3 */
static int
frag_cmp(void *a, void *b)
{
    struct frag_ctx *fa = (struct frag_ctx *)a;
    struct frag_ctx *fb = (struct frag_ctx *)b;
    int ret = 0;
    if (fa->dgram_size != fb->dgram_size) {
        return (int)(fa->dgram_size - fb->dgram_size);
    } else if (fa->dgram_tag != fb->dgram_tag) {
        return (int)(fa->dgram_tag - fb->dgram_tag);
    } else {
        ret = pico_6lowpan_ll_cmp(&fa->src, &fb->src, fa->f->dev);
        if (ret)
            return ret;
        else {
            return pico_6lowpan_ll_cmp(&fa->dst, &fb->dst, fa->f->dev);
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
    struct frag_ctx *ctx = (struct frag_ctx *)arg;
    IGNORE_PARAMETER(now);
    pico_tree_delete(&ReassemblyTree, arg);
    pico_frame_discard(ctx->f);
    PICO_FREE(arg);
}

/* Finds a reassembly cookie in the reassembly-tree */
static struct frag_ctx *
frag_find(uint16_t dgram_size, uint16_t tag, union pico_ll_addr src, union pico_ll_addr dst)
{
    struct frag_ctx f= {.dgram_size=dgram_size, .dgram_tag=tag, .src=src, .dst=dst};
    return pico_tree_findKey(&ReassemblyTree, &f);
}

/* Stores a fragmentation cookie in either the fragmentetion cookie tree or
 * in the reassembly tree */
static int
frag_store(struct pico_frame *f, int avail, uint16_t dgram_size, uint16_t dgram_tag,
           uint16_t dgram_off, uint16_t copied, union pico_ll_addr src,
           union pico_ll_addr dst, struct pico_tree *tree)
{
    struct frag_ctx *fr = PICO_ZALLOC(sizeof(struct frag_ctx));
    if (fr) {
        fr->f = f;
        fr->dgram_size = dgram_size;
        fr->dgram_tag = dgram_tag;
        fr->dgram_off = dgram_off;
        fr->copied = copied;
        fr->src = src;
        fr->dst = dst;
        if (tree = &ReassemblyTree) {
            /* Set a reassembly timeout of 10 seconds */
            fr->timer = pico_timer_add(1000*FRAG_TIMEOUT, frag_timeout, fr);
        } else {
            /* Make the cookie retrievable */
            fr->hash = 0;
            fr->timer = 0;
            fr->avail = (uint16_t)avail;
            fr->hash = pico_hash((void *)fr, sizeof(struct frag_ctx));
        }
        if (pico_tree_insert(tree, fr)) {
            PICO_FREE(fr);
            return -1;
        }
        return 1; // Succes for 'proto_loop_out'
    } else {
        return -1;
    }
}

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
static int
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

/* Checks whether or not an IPv6 address is derived from a link layer address */
static int
addr_ll_derived(struct pico_ip6 *addr, union pico_ll_addr *lladdr, struct pico_device *dev)
{
    uint8_t iid[8] = {0};
    if (pico_6lowpan_ll_iid(iid, lladdr, dev))
        return -1;
    return (int)(0 == memcmp(iid, &addr->addr[8], 8));
}

/* Sets the compression mode of either the source address or the destination
 * address, based on the shift parameter. Use SRC_SHIFT for source, 0 for dst */
static int
addr_comp_mode(uint8_t *iphc, struct pico_ip6 *addr, union pico_ll_addr lladdr,
               struct pico_device *dev, int shift)
{
    int mac = addr_ll_derived(addr, &lladdr, dev);
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
        memcpy(inline_buf + 2, inline_buf + 3, (size_t)*compressed_len);
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
    uint8_t *inline_buf = PICO_ZALLOC(PICO_UDPHDR_SIZE);
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
        /* Length MUST be compressed checksum carried inline.
         * RFC6282: .., a compressor in the source transport endpoint MAY elide
         * the UDP checksum if it is autorized by the upper layer. The compressor
         * MUST NOT set the C bit unless it has received such authorization */
        memcpy(inline_buf + *compressed_len, (uint8_t *)hdr + 6, 2);
        *compressed_len += 2;
        return inline_buf;
    }
}

/* Decompresses a NHC_UDP header according to the NHC_UDP compression scheme */
static uint8_t *
decompressor_nhc_udp(struct pico_frame *f, int processed_len, int *compressed_len)
{
    struct pico_udp_hdr *hdr = PICO_ZALLOC(PICO_UDPHDR_SIZE);
    uint8_t *buf = f->transport_hdr;
    uint8_t compression = buf[0] & UDP_COMPRESSED_BOTH;
    int payload_len = 0;
    *compressed_len = 0;

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
        /* Restore checksum if carried inline */
        if (!(buf[0] & UDP_COMPRESSED_CHCK)) { // Leave empty room for checksum
            memcpy((uint8_t *)&hdr->crc, &buf[*compressed_len],2);
            *compressed_len += 2;
        }
        /* Restore inherently compressed length */
        payload_len = (int)f->len - (processed_len + *compressed_len);
        hdr->len = short_be((uint16_t)(payload_len + PICO_UDPHDR_SIZE));
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
                     dst, int *compressed_len, int *decompressed_len)
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
        *decompressed_len = alloc;
        return (uint8_t *)ext;
    } else {
        return NULL;
    }
}

/* Free's memory of a all assembled chunks for 'n' amount */
static struct pico_frame *
pico_iphc_bail_out(uint8_t *chunks[], int n)
{
    int i = 0;
    for (i = 0; i < n; i++) {
        PICO_FREE(chunks[i]);
    }
    return NULL;
}

/* Performs reassembly after either compression of decompression */
static struct pico_frame *
pico_iphc_reassemble(struct pico_frame *f, uint8_t *chunks[], int chunks_len[],
                     int n, int processed_len, int handled_len)
{
    uint32_t grow = f->buffer_len;
    struct pico_frame *new = NULL;
    int payload_len = 0;
    uint8_t *dst = NULL;
    int ret = 0, i = 0;

    /* Calculate buffer size including IPv6 payload */
    payload_len = (int)f->len - handled_len;
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
     * frame-buffer so we don't overwrite preceding buffers */
    dst = new->net_hdr + processed_len;
    for (i = n - 1; i >= 0; i--) {
        dst -= chunks_len[i];
        memcpy(dst, chunks[i], (size_t)chunks_len[i]);
    }
    new->net_hdr = dst; // Last destination is net_hdr
    new->start = new->net_hdr; // Start of useful data is at net_hdr
    new->len = (uint32_t)processed_len;
    new->transport_hdr = new->net_hdr + new->net_len;
    pico_iphc_bail_out(chunks, n - 1); // Success, discard compressed chunk
    return new;
}

/* Compresses a frame according to the IPHC, NHC_EXT and NHC_UDP compression scheme */
static struct pico_frame *
pico_iphc_compress(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    int i = 0, compressed_len = 0, loop = 1, uncompressed = f->net_len;
    uint8_t *old_nethdr = f->net_hdr; // Save net_hdr temporary ...
    uint8_t nh = PICO_PROTO_IPV6;
    uint8_t *chunks[8] = { NULL };
    int chunks_len[8] = { 0 };

    do {
        switch (nh) {
            /* IPV6 HEADER */
            case PICO_PROTO_IPV6:
                chunks[i] = compressor_iphc(f, src, dst, &chunks_len[i], &nh);
                f->net_hdr += 40; // Move after IPv6 header
                f->net_len = (uint16_t)chunks_len[i];
                break;
            /* IPV6 EXTENSION HEADERS */
            case PICO_IPV6_EXTHDR_HOPBYHOP:
            case PICO_IPV6_EXTHDR_ROUTING:
            case PICO_IPV6_EXTHDR_FRAG:
            case PICO_IPV6_EXTHDR_DESTOPT:
                chunks[i] = compressor_nhc_ext(f, src, dst, &chunks_len[i], &nh);
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
pico_iphc_decompress(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    int i = 0, compressed = 0, loop = 1, uncompressed = 0, ret = 0;
    uint8_t *old_nethdr = f->net_hdr; // Save net_hdr temporary ...
    uint8_t dispatch = PICO_PROTO_IPV6;
    uint8_t *chunks[8] = { NULL };
    struct pico_frame *n = NULL;
    int chunks_len[8] = { 0 };
    uint8_t nh = 0;

    do {
        switch (dispatch) {
            /* IPV6 HEADER */
            case PICO_PROTO_IPV6:
                chunks[i] = decompressor_iphc(f, src, dst, &ret);
                chunks_len[i] = PICO_SIZE_IP6HDR;
                f->net_len = PICO_SIZE_IP6HDR;
                nh = ext_nh_retrieve(f->net_hdr, ret);
                break;
            /* IPV6 EXTENSION HEADERS */
            case PICO_IPV6_EXTHDR_HOPBYHOP:
            case PICO_IPV6_EXTHDR_ROUTING:
            case PICO_IPV6_EXTHDR_FRAG:
            case PICO_IPV6_EXTHDR_DESTOPT:
                chunks[i] = decompressor_nhc_ext(f, src, dst, &ret, &chunks_len[i]);
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

static int
frag_nth(struct pico_frame *f)
{
    struct frag_ctx *frag = frag_ctx_find(f->hash);
    uint16_t units = (uint16_t)(frag->avail - FRAGN_SIZE) >> 3;
    uint16_t copy = (uint16_t)(units << 3);
    struct pico_frame *n = pico_6lowpan_frame_alloc(copy + FRAGN_SIZE, f->dev);
    uint8_t *fragn = NULL;
    int ret = 0;
    if (frag && n) {
        n->net_hdr = n->buffer + (int)(n->buffer_len) - (int)(copy + FRAGN_SIZE);
        fragn = n->net_hdr;

        /* Fill in n-th fragment */
        fragn[0] = FRAGN_DISPATCH;
        *(uint16_t *)&frag[0] |= (uint16_t)(short_be(frag->dgram_size) & short_be(0x7FF));
        *(uint16_t *)&frag[2] = (uint16_t)short_be(frag->dgram_tag);
        memcpy(frag + 5, f->net_hdr, copy);

        /* Try to push fragment to link layer */
        ret = pico_6lowpan_ll_push(n, frag->src, frag->dst);
        pico_frame_discard(n);
        if (ret)
            return -1;

        /* Enqueue the frame again for subsequent fragments */
        if (pico_datalink_send(f) <= 0)
            return -1;

        frag->dgram_off = (uint16_t)(frag->dgram_off + units);
        frag->copied = (uint16_t)(frag->copied + copy);
        if (frag->copied == f->len) {
            pico_tree_delete(&FragTree, frag);
            pico_frame_discard(f);
        }
    } else {
        pico_frame_discard(f);
        return -1;
    }
}

static int
frag_1st(struct pico_frame *f, int avail, uint16_t dgram_size, uint16_t dgram_off, uint16_t
         copy, union pico_ll_addr src, union pico_ll_addr dst)
{
    struct pico_frame *n = pico_6lowpan_frame_alloc(copy + FRAG1_SIZE, f->dev);
    uint8_t *frag = NULL;
    int ret = 0;
    if (!n) {
        n->net_hdr = n->buffer + (int)(n->buffer_len) - (int)(copy + FRAG1_SIZE);
        frag = n->net_hdr;

        /* Fill 1st fragment */
        frag[0] = FRAG1_DISPATCH;
        *(uint16_t *)&frag[0] |= (uint16_t)(short_be(dgram_size) & short_be(0x7FF));
        *(uint16_t *)&frag[2] = (uint16_t)short_be(dgram_tag++);
        memcpy(frag + 4, f->net_hdr, copy);

        /* Try to push fragment to link layer */
        ret = pico_6lowpan_ll_push(n, src, dst);
        pico_frame_discard(n);
        if (ret) {
            dgram_tag--;
            return -1;
        }

        /* Enqueue the frame again for subsequent fragments */
        if (pico_datalink_send(f) <= 0)
            return -1;

        /* Everything was a success store a cookie for subsequent fragments */
        return frag_store(f, avail, dgram_size, dgram_tag, dgram_off, copy, src, dst,
                          &FragTree);
    } else {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
}

static int
frag_1st_no_comp(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr
                 dst, uint16_t dgram_size, int available)
{
    /* Available bytes after inserting FRAG1 dispatch and IPv6 dispatch */
    uint16_t rest_size = (uint16_t)(available - FRAG1_SIZE - 1);
    uint16_t dgram_off = (uint16_t)(rest_size >> 3);
    uint16_t copy_size = (uint16_t)(rest_size + 1);
    return frag_1st(f, available, dgram_size, dgram_off, copy_size, src, dst);
}

static int
frag_1st_comp(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst,
              uint16_t dgram_size, int available, int udp)
{
    /* Calculate amount of bytes that are elided */
    uint16_t comp_diff = (uint16_t)(dgram_size - f->len);
    uint16_t comp_hlen = (uint16_t)(f->net_len + (udp ? f->transport_len : 0));
    /* Decompressed header length */
    uint16_t deco_hlen = (uint16_t)(comp_hlen + comp_diff);
    /* Available octects after inserting FRAG1 dispatch and compressed header */
    uint16_t rest_size = (uint16_t)(available - FRAG1_SIZE - comp_hlen);
    /* Offset for subsequent fragments in 8-octect units and in octets */
    uint16_t dgram_off = (uint16_t)((uint16_t)(rest_size + deco_hlen) >> 3);
    uint16_t copy_size = 0;
    /* 8-octet aligned available octets after decompression */
    rest_size = (uint16_t)((uint16_t)(dgram_off << 3) - deco_hlen);
    copy_size = (uint16_t)(rest_size + comp_hlen);
    return frag_1st(f, available, dgram_size, dgram_off, copy_size, src, dst);
}

/* General compression function that first tries to compress the frame and sends
 * it through to the link layer, if that doesn't work the frame is fragmented */
static int
pico_6lowpan_compress(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    struct pico_ipv6_hdr *ip = (struct pico_ipv6_hdr *)f->net_hdr;
    uint16_t dgram_size = (uint16_t)(ip->len + PICO_SIZE_IP6HDR);
    struct pico_frame *try = pico_iphc_compress(f, src, dst);
    int udp = PICO_PROTO_UDP == ip->nxthdr;
    int avail = 0;

    if (try) {
        /* Try to push the compressed frame again */
        avail = pico_6lowpan_ll_push(try, src, dst);
        if (avail > 0) {
            /* RFC6282: any header that cannot fit within the first fragment
             * MUST NOT be compressed. */
            if ((udp && (try->net_len + try->transport_len) > (uint16_t)avail) ||
                (!udp && (try->net_len > (uint16_t)avail))) {
                pico_frame_discard(try);
                pico_iphc_no_comp(f);
                return frag_1st_no_comp(f, src, dst, dgram_size, avail);
            } else {
                pico_frame_discard(f);
                return frag_1st_comp(f, src, dst, dgram_size, avail, udp);
            }
        } else if (avail < 0) {
            /* Failure, discard frame, bail out */
            pico_frame_discard(f);
            return -1;
        } else {
            /* Frame was compressed enough to fit in 'payload_available' */
            pico_frame_discard(f);
            return 1;
        }
    }
}

static int
pico_6lowpan_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    union pico_ll_addr llsrc;
    union pico_ll_addr lldst;
    int payload_available = 0;
    IGNORE_PARAMETER(self);

    /* Check if it's meant for fragmentation */
    if (f->flags & PICO_FRAME_FLAG_SLP_FRAG) {
        return frag_nth(f);
    }

    /* Retrieve link layer addresses */
    if (pico_6lowpan_ll_addr(f, &llsrc, 0) || pico_6lowpan_ll_addr(f, &lldst, 1)) {
        pico_frame_discard(f);
        return -1;
    }

    return pico_6lowpan_compress(f, llsrc, lldst);
}

static int
pico_6lowpan_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(f);

    return 0;
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

static int pico_6lowpan_ll_cmp(union pico_ll_addr *a, union pico_ll_addr *b, struct pico_device *dev)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        /* TODO: Update to pico_protocol's alloc function */
        return addr_802154_cmp(a, b);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        lp_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return 0;
    }
}

static struct pico_frame *pico_6lowpan_frame_alloc(uint16_t size, struct pico_device *dev)
{
    struct pico_frame *f;
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        /* TODO: Update to pico_protocol's alloc function */
        f = pico_frame_alloc(SIZE_802154_MHR_MAX + size);
        if (f) {
            f->dev = dev;
        }
        return f;
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        lp_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return NULL;
    }
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
