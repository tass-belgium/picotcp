/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.
 
 Authors: Jelle De Vleeschouwer
 *********************************************************************/

/* Custom includes */
#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "pico_udp.h"
/* --------------- */

#ifdef PICO_SUPPORT_SIXLOWPAN

#define DEBUG
#ifdef DEBUG
    #define PAN_DBG(s, ...)         dbg("[6LoWPAN]$ " s, ##__VA_ARGS__)
    #define PAN_ERR(s, ...)         dbg("[6LoWPAN]$ ERROR: %s: %d: " s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define PAN_WARNING(s, ...)     dbg("[6LoWPAN]$ WARNING: %s: %d: " s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define PAN_DBG_C               dbg
#else
    #define PAN_DBG(...)            do {} while(0)
    #define PAN_DBG_C(...)          do {} while(0)
    #define PAN_WARNING(...)        do {} while(0)
    #define PAN_ERR(...)            do {} while(0)
#endif

#define DISPATCH_NALP(i)            ((i) == INFO_VAL ? (0x00u) : ((i) == INFO_SHIFT ? (0x06u) : (0x00u)))
#define DISPATCH_IPV6(i)            ((i) == INFO_VAL ? (0x41u) : ((i) == INFO_SHIFT ? (0x00u) : (0x01u)))
#define DISPATCH_HC1(i)             ((i) == INFO_VAL ? (0x42u) : ((i) == INFO_SHIFT ? (0x00u) : (0x02u)))
#define DISPATCH_BC0(i)             ((i) == INFO_VAL ? (0x50u) : ((i) == INFO_SHIFT ? (0x00u) : (0x02u)))
#define DISPATCH_ESC(i)             ((i) == INFO_VAL ? (0x7Fu) : ((i) == INFO_SHIFT ? (0x00u) : (0xFFu)))
#define DISPATCH_MESH(i)            ((i) == INFO_VAL ? (0x02u) : ((i) == INFO_SHIFT ? (0x06u) : (0x01u)))
#define DISPATCH_FRAG1(i)           ((i) == INFO_VAL ? (0x18u) : ((i) == INFO_SHIFT ? (0x03u) : (0x04u)))
#define DISPATCH_FRAGN(i)           ((i) == INFO_VAL ? (0x1Cu) : ((i) == INFO_SHIFT ? (0x03u) : (0x05u)))
#define DISPATCH_NESC(i)            ((i) == INFO_VAL ? (0x80u) : ((i) == INFO_SHIFT ? (0x00u) : (0xFFu)))
#define DISPATCH_IPHC(i)            ((i) == INFO_VAL ? (0x03u) : ((i) == INFO_SHIFT ? (0x05u) : (0x02u)))
#define DISPATCH_NHC_EXT(i)         ((i) == INFO_VAL ? (0x0Eu) : ((i) == INFO_SHIFT ? (0x04u) : (0x01u)))
#define DISPATCH_NHC_UDP(i)         ((i) == INFO_VAL ? (0x1Eu) : ((i) == INFO_SHIFT ? (0x03u) : (0x01u)))
#define DISPATCH_PING_REQUEST(i)    ((i) == INFO_VAL ? (0x44u) : ((i) == INFO_SHIFT ? (0x00u) : (0x01u)))
#define DISPATCH_PING_REPLY(i)      ((i) == INFO_VAL ? (0x45u) : ((i) == INFO_SHIFT ? (0x00u) : (0x01u)))
#define CHECK_DISPATCH(d, type)     (((d) >> type(INFO_SHIFT)) == type(INFO_VAL))
#define SIXLOWPAN_NALP              DISPATCH_NALP
#define SIXLOWPAN_IPV6              DISPATCH_IPV6
#define SIXLOWPAN_HC1               DISPATCH_HC1
#define SIXLOWPAN_BC0               DISPATCH_BC0
#define SIXLOWPAN_ESC               DISPATCH_ESC
#define SIXLOWPAN_MESH              DISPATCH_MESH
#define SIXLOWPAN_FRAG1             DISPATCH_FRAG1
#define SIXLOWPAN_FRAGN             DISPATCH_FRAGN
#define SIXLOWPAN_NESC              DISPATCH_NESC
#define SIXLOWPAN_IPHC              DISPATCH_IPHC
#define SIXLOWPAN_NHC_EXT           DISPATCH_NHC_EXT
#define SIXLOWPAN_NHC_UDP           DISPATCH_NHC_UDP
#define SIXLOWPAN_PING_REQUEST      DISPATCH_PING_REQUEST
#define SIXLOWPAN_PING_REPLY        DISPATCH_PING_REPLY
#define SIXLOWPAN_PING_TIMEOUT      (3000u)
#define SIXLOWPAN_DEFAULT_TTL       (0xFFu)
#define SIXLOWPAN_PING_TTL          (64u)
#define SIXLOWPAN_FORWARDING        (0x01u)
#define SIXLOWPAN_TRANSMIT          (0x00u)
#define SIXLOWPAN_SRC               (1u)
#define SIXLOWPAN_DST               (0u)
#define INFO_VAL                    (0u)
#define INFO_SHIFT                  (1u)
#define INFO_HDR_LEN                (2u)

#define IEEE_MIN_HDR_LEN            (5u)
#define IEEE_LEN_LEN                (1u)
#define IEEE_ADDR_IS_BCAST(ieee)    ((IEEE_AM_SHORT == (ieee)._mode) && (IEEE_ADDR_BCAST_SHORT == (ieee)._short.addr))
#define IEEE_AM_BOTH_TO_SHORT(am)   ((IEEE_AM_BOTH == (am) || IEEE_AM_SHORT == (am)) ? IEEE_AM_SHORT : IEEE_AM_EXTENDED)

#define IPV6_FIELDS_NUM             (6u)
#define IPV6_SOURCE                 (0u)
#define IPV6_DESTINATION            (1u)
#define IPV6_OFFSET_LEN             (4u)
#define IPV6_OFFSET_NH              (6u)
#define IPV6_OFFSET_HL              (7u)
#define IPV6_OFFSET_SRC             (8u)
#define IPV6_OFFSET_DST             (24u)
#define IPV6_LEN_TF                 (4u)
#define IPV6_LEN_LEN                (2u)
#define IPV6_LEN_NH                 (1u)
#define IPV6_LEN_HL                 (1u)
#define IPV6_LEN_SRC                (16u)
#define IPV6_LEN_DST                (16u)
#define IPV6_EXT_LEN_NXTHDR         (1u)
#define IPV6_ADDR_OFFSET(id)        ((IPV6_SOURCE == (id)) ? (IPV6_OFFSET_SRC) : (IPV6_OFFSET_DST))
#define IPV6_IS_MCAST_8(addr)       ((addr)[1] == 0x02 && (addr)[14] == 0x00)
#define IPV6_IS_MCAST_32(addr)      ((addr)[12] == 0x00)
#define IPV6_IS_MCAST_48(addr)      ((addr)[10] == 0x00)
#define IPV6_VERSION                ((uint32_t)(0x60000000))
#define IPV6_DSCP(vtf)              (((vtf) >> IPHC_SHIFT_DSCP) & IPHC_MASK_DSCP)
#define IPV6_ECN(vtf)               (((vtf) >> IPHC_SHIFT_ECN) & IPHC_MASK_ECN)
#define IPV6_FLS(vtf)               (((vtf) >> IPHC_SHIFT_FL) & IPHC_MASK_FL)
#define IPV6_FL(vtf)                ((vtf) & IPHC_MASK_FL)

#define IPHC_SHIFT_ECN              (10u)
#define IPHC_SHIFT_DSCP             (2u)
#define IPHC_SHIFT_FL               (8u)
#define IPHC_MASK_DSCP              (uint32_t)(0xFC00000)
#define IPHC_MASK_ECN               (uint32_t)(0x300000)
#define IPHC_MASK_FL                (uint32_t)(0xFFFFF)
#define IPHC_SIZE_MCAST_8           (1u)
#define IPHC_SIZE_MCAST_32          (4u)
#define IPHC_SIZE_MCAST_48          (6u)
#define IPHC_DSCP(vtf)              ((long_be((vtf)) << IPHC_SHIFT_DSCP) & IPHC_MASK_DSCP)
#define IPHC_ECN(vtf)               ((long_be((vtf)) << IPHC_SHIFT_ECN) & IPHC_MASK_ECN)
#define IPHC_FLS(vtf)               ((long_be((vtf)) & IPHC_MASK_FL) << IPHC_SHIFT_FL);
#define IPHC_FL(vtf)                (long_be((vtf)) & IPHC_MASK_FL);

#define UDP_IS_PORT_8(p)            ((0xF0) == ((p) >> 8))
#define UDP_IS_PORT_4(p)            ((0xF0B) == ((p) >> 4))
#define UDP_ARE_PORTS_4(src, dst)   (UDP_IS_PORT_4((src)) && UDP_IS_PORT_4((dst)))
#define UINT32_4LSB(lsb)            (((uint32_t)lsb) & 0x000F)
#define UINT32_8LSB(lsb)            (((uint32_t)lsb) & 0x00FF)

#define FRAG_DGRAM_SIZE_MASK        (0x7FF)

#define MESH_HL_ESC                 (0x0F)
#define MESH_DAH_HOP_LIMIT(dah)     (uint8_t)((dah) & 0x0F)

#define RTABLE_ENTRY_TTL            (10u) /* (600u) // 10 minutes */

/* SAFEGUARD MACROS */
#define R_VOID
#define R_NULL                      (NULL)
#define R_ZERO                      (0)
#define R_PLAIN                     (-1)
#define _CHECK_PARAM(a, b)          if(!(a)){ \
                                        pico_err = PICO_ERR_EINVAL; \
                                        PAN_ERR("Invalid argument!\n"); \
                                        return b; \
                                    } do {} while(0)
#define CHECK_PARAM(a)              _CHECK_PARAM((a), R_PLAIN)
#define CHECK_PARAM_NULL(a)         _CHECK_PARAM((a), R_NULL)
#define CHECK_PARAM_ZERO(a)         _CHECK_PARAM((a), R_ZERO)
#define CHECK_PARAM_VOID(a)         _CHECK_PARAM((a), R_VOID)

/* MEMORY MACROS */
#define SIZE_UPDATE(size, edit, del) (uint16_t)((del) ? (uint16_t)(size - edit) : (uint16_t)(size + edit))

/* -------------------------------------------------------------------------------- */
// MARK: 6LoWPAN types
enum sixlowpan_state
{
    SIXLOWPAN_NREADY = -1,
    SIXLOWPAN_READY,
    SIXLOWPAN_PREPARING,
    SIXLOWPAN_TRANSMITTING
};

enum endian_mode
{
    ENDIAN_IEEE = 0,
    ENDIAN_SIXLOWPAN
};

/**
 *  Definition of 6LoWPAN pico_device
 */
struct pico_device_sixlowpan
{
    struct pico_device dev;
    
    /* Interface between pico_device-structure & 802.15.4-device driver */
    struct ieee_radio *radio;
    
    /* Every PAN has to have a routable IPv6 prefix. */
    struct pico_ip6 prefix;
};

/** *******************************
 *  Frame Status definitions
 *  MARK: Frame Status
 */
enum frame_status
{
    FRAME_ERROR = -1,
    FRAME_OK,
    FRAME_FITS,
    FRAME_FITS_COMPRESSED,
    FRAME_COMPRESSED,
    FRAME_COMPRESSIBLE_NH,
    FRAME_FRAGMENTED,
    FRAME_POSTPONED,
    FRAME_PENDING,
    FRAME_SENT,
    FRAME_ACKED,
    /* ------------------- */
    FRAME_COMPRESSED_NHC,
    FRAME_DECOMPRESSED,
    FRAME_DEFRAGMENTED
};

/**
 *  Definition of a 6LoWPAN frame
 */
struct sixlowpan_frame
{
    uint8_t *phy_hdr;
    uint16_t size;
    
    /* Link header buffer */
    struct ieee_hdr *link_hdr;
    uint8_t link_hdr_len;
    
    /* IPv6 header buffer */
    uint8_t *net_hdr;
    uint16_t net_len;
    
    /* Transport layer buffer */
    uint8_t *transport_hdr;
    uint16_t transport_len;
    
    /* Max bytes (a multiple of eight) that fit inside a single frame */
    uint8_t max_bytes;
    
    /* To which IPv6 datagram the frame belongs to */
    uint16_t dgram_tag;
    uint16_t dgram_size;
    
    uint8_t hop_limit;
    
    enum frame_status state;
    
    /* Pointer to 6LoWPAN-device instance */
    struct pico_device *dev;
    
    /**
     *  Link layer address of the nearest hop, either the
     *  next hop address when sending or the last hop
     *  address when receiving.
     */
    struct pico_ieee_addr hop;
    
    /**
     *  Link layer address of the peer, either the
     *  destination address when sending or the source
     *  address when receiving.
     */
    struct pico_ieee_addr peer;
    
    /**
     *  Link layer address of the local host, only
     *  has a meaning when sending frames.
     */
    struct pico_ieee_addr local;
};

/** *******************************
 *  LOWPAN_IPHC Header structure
 *  MARK: LOWPAN_IPHC types
 */
PACKED_STRUCT_DEF sixlowpan_iphc
{
    uint8_t hop_limit: 2;
    uint8_t next_header: 1;
    uint8_t tf: 2;
    uint8_t dispatch: 3;
    uint8_t dam: 2;
    uint8_t dac: 1;
    uint8_t mcast: 1;
    uint8_t sam: 2;
    uint8_t sac: 1;
    uint8_t context_ext: 1;
};

enum iphc_tf
{
    TF_COMPRESSED_NONE = 0,
    TF_COMPRESSED_TC,
    TF_COMPRESSED_FL,
    TF_COMPRESSED_FULL
}; /* Traffic class / Flow label */

enum iphc_nh
{
    NH_COMPRESSED_NONE = 0,
    NH_COMPRESSED
}; /* Next Header */

enum iphc_hl
{
    HL_COMPRESSED_NONE = 0,
    HL_COMPRESSED_1,
    HL_COMPRESSED_64,
    HL_COMPRESSED_255
}; /* Hop Limit */

enum iphc_cid
{
    CID_CONTEXT_NONE = 0,
    CID_CONTEXT_EXTENSION
}; /* Context extension IDentifier present */

enum iphc_ac
{
    AC_COMPRESSION_STATELESS = 0,
    AC_COMPRESSION_STATEFULL
}; /* Address Compression */

enum iphc_am
{
    AM_COMPRESSED_NONE = 0,
    AM_COMPRESSED_64,
    AM_COMPRESSED_16,
    AM_COMPRESSED_FULL
}; /* Addressing compression Mode */

enum iphc_mcast
{
    MCAST_MULTICAST_NONE = 0,
    MCAST_MULTICAST
}; /* Multicast destination */

enum iphc_mcast_dam
{
    MCAST_COMPRESSED_NONE = 0,
    MCAST_COMPRESSED_48,
    MCAST_COMPRESSED_32,
    MCAST_COMPRESSED_8
}; /* Multicast compression */

/** *******************************
 *  LOWPAN_NHC_EXT Header structure
 *  MARK: LOWPAN_NHC types
 */
PACKED_STRUCT_DEF sixlowpan_nhc_ext
{
    uint8_t nh: 1;
    uint8_t eid: 3;
    uint8_t dispatch: 4;
}; /* NHC_EXT Header */

PACKED_STRUCT_DEF sixlowpan_nhc_udp
{
    uint8_t ports: 2;
    uint8_t checksum: 1;
    uint8_t dispatch: 5;
}; /* NHC_UDP Header */

enum nhc_ext_eid
{
    EID_HOPBYHOP = 0,
    EID_ROUTING,
    EID_FRAGMENT,
    EID_DESTOPT,
}; /* IPv6 Extension IDentifier */

enum nhc_udp_ports
{
    PORTS_COMPRESSED_NONE = 0,  /* [ 16 | 16 ] (4) */
    PORTS_COMPRESSED_DST,       /* [ 16 |  8 ] (3) */
    PORTS_COMPRESSED_SRC,       /* [  8 | 16 ] (3) */
    PORTS_COMPRESSED_FULL,      /* [  4 |  4 ] (1) */
}; /* UDP Ports compression mode */

enum nhc_udp_checksum
{
    CHECKSUM_COMPRESSED_NONE = 0,
    CHECKSUM_COMPRESSED
}; /* UDP Checksum compression mode */

union nhc_hdr
{
    struct sixlowpan_nhc_ext ext;
    struct sixlowpan_nhc_udp udp;
};

/** *******************************
 *  MARK: LOWPAN_FRAG types
 */
PACKED_STRUCT_DEF sixlowpan_frag1
{
    uint16_t dispatch_size;
    uint16_t datagram_tag;
}; /* 6LoWPAN first fragmentation header */

PACKED_STRUCT_DEF sixlowpan_fragn
{
    uint16_t dispatch_size;
    uint16_t datagram_tag;
    uint8_t offset;
}; /* 6LoWPAN following fragmentation header */

/** *******************************
 *  MARK: LOWPAN_BC0 types
 */
PACKED_STRUCT_DEF sixlowpan_bc0
{
    uint8_t dispatch;
    uint8_t seq;
};

/** *******************************
 *  MARK: LOWPAN_MESH types
 */
PACKED_STRUCT_DEF sixlowpan_mesh
{
    uint8_t dah;
    uint8_t addresses[0];
}; /* Plain 6LowPAN mesh header */

PACKED_STRUCT_DEF sixlowpan_mesh_esc
{
    uint8_t dah;
    uint8_t hl;
    uint8_t addresses[0];
}; /* Escaped hop limit 6LowPAN mesh header */

/** *******************************
 *  MARK: Routing table & Ping types
 */
PACKED_STRUCT_DEF sixlowpan_ping
{
    uint8_t dispatch;
    uint16_t id;
}; /* 6LoWPAN custom ping header */

struct sixlowpan_rtable_entry
{
    struct pico_ieee_addr dst;
    struct pico_ieee_addr via;
    uint32_t timestamp;
    uint8_t hops;
}; /* Entry of routing table */

struct ping_cookie
{
    struct pico_ieee_addr dst;
    uint16_t id;
}; /* Cookie for ping-session to store */

/** *******************************
 *  Express a range
 *  MARK: Generic types
 */
struct range
{
    uint16_t offset;
    uint16_t length;
};

/* -------------------------------------------------------------------------------- */
// MARK: GLOBALS
static volatile enum sixlowpan_state sixlowpan_state = SIXLOWPAN_READY;
static struct sixlowpan_frame *tx = NULL;
static struct sixlowpan_frame *rtx = NULL;
static uint16_t sixlowpan_devnum = 0;

/* Fragmentation globals */
static uint16_t dtag = 0;

/* Broadcast globals */
static struct pico_ieee_addr_ext last_bcast_ext = {{0, 0, 0, 0, 0, 0, 0, 0}};
static struct pico_ieee_addr_short last_bcast_short = {0xFFFF};
static uint8_t bcast_seq = 0;

/* -------------------------------------------------------------------------------- */
// MARK: FUNCTION PROTOTYPES
static struct pico_ieee_addr sixlowpan_determine_next_hop(struct sixlowpan_frame *f);
static int sixlowpan_ping(struct pico_ieee_addr dst, struct pico_ieee_addr last_hop, struct pico_device *dev, uint16_t id, enum ieee_am reply_mode);
static uint8_t *sixlowpan_mesh_out(uint8_t *buf, uint8_t *len, struct sixlowpan_frame *f);
static void sixlowpan_update_addr(struct sixlowpan_frame *f, uint8_t src);
static void sixlowpan_retransmit(struct sixlowpan_frame *f);
static int sixlowpan_prep_tx(void);

/* -------------------------------------------------------------------------------- */
// MARK: MEMORY
static uint16_t buf_delete(void *buf, uint16_t len, struct range r)
{
    uint16_t rend = (uint16_t)(r.offset + r.length);
    uint16_t clr_offset = (uint16_t)(len - r.length);
    uint16_t rest = (uint16_t)((len - rend));
    CHECK_PARAM_ZERO(buf);
    
    /* OOB Check */
    if (!rend || len < rend || len <= r.offset)
        return len;
    
    /* Replace the deleted chunk at the offset by the data after the end of the deleted chunk */
    memmove(buf + r.offset, buf + rend, (size_t)rest);
    memset(buf + clr_offset, 0, r.length);
    
    /* Return the new length */
    return (uint16_t)(len - r.length);
}

static void *buf_insert(void *buf, uint16_t len, struct range r)
{
    void *new = NULL;
    
    /* OOB Check */
    if (r.offset > len)
        return buf;
    
    /* OOM Check */
    if (!(new = PICO_ZALLOC((size_t)(len + r.length))))
        return buf;
    
    /* Assemble buffer again */
    if (buf && new) {
        memmove(new, buf, (size_t)r.offset);
        memmove(new + r.offset + r.length, buf + r.offset, (size_t)(len - r.offset));
        memset(new + r.offset, 0x00, r.length);
        PICO_FREE(buf); /* Give back previous buffer to the system */
    }
    
    return new;
}

static inline void frame_rearrange_ptrs(struct sixlowpan_frame *f)
{
    CHECK_PARAM_VOID(f);
    
    f->link_hdr = (struct ieee_hdr *)(f->phy_hdr + IEEE_LEN_LEN);
    f->net_hdr = ((uint8_t *)f->link_hdr) + f->link_hdr_len;
    f->transport_hdr = f->net_hdr + f->net_len;
}

static uint8_t *frame_buf_edit(struct sixlowpan_frame *f, enum pico_layer l, struct range r, uint16_t offset, uint8_t del)
{
    uint8_t *chunk = NULL;
    
    CHECK_PARAM_NULL(f);
    
    switch (l) {
        case PICO_LAYER_DATALINK: /* Set the new size of the datalink chunk */
            f->link_hdr_len = (uint8_t) SIZE_UPDATE(f->link_hdr_len, r.length, del);
            chunk = (uint8_t *)f->link_hdr;
            break;
        case PICO_LAYER_NETWORK: /* Set the new size of the network chunk */
            f->net_len = (uint16_t) SIZE_UPDATE(f->net_len, r.length, del);
            chunk = (uint8_t *)f->net_hdr;
            break;
        case PICO_LAYER_TRANSPORT: /* Set the new size of the transport chunk */
            f->transport_len = (uint16_t) SIZE_UPDATE(f->transport_len, r.length, del);
            chunk = (uint8_t *)f->transport_hdr;
            break;
        default:
            pico_err = PICO_ERR_EINVAL;
            return NULL;
    }
    
    r.offset = (uint16_t)((uint16_t)(chunk - f->phy_hdr) + r.offset + offset);
    
    if (del) {
        f->size = buf_delete(f->phy_hdr, f->size, r);
    } else {
        if (!(f->phy_hdr = buf_insert(f->phy_hdr, f->size, r)))
            return NULL;
        
        /* Set the new buffer size */
        f->size = SIZE_UPDATE(f->size, r.length, 0);
    }
    /* Rearrange chunk-ptrs */
    frame_rearrange_ptrs(f);
    return (uint8_t *)(f->phy_hdr + r.offset);
}

static uint8_t *frame_buf_insert(struct sixlowpan_frame *f, enum pico_layer l, struct range r)
{
    return frame_buf_edit(f, l, r, 0, 0);
}

static uint8_t *frame_buf_prepend(struct sixlowpan_frame *f, enum pico_layer l, uint16_t len)
{
    struct range r = {.offset = 0, .length = len};
    return frame_buf_insert(f, l, r);
}

static uint8_t *frame_buf_delete(struct sixlowpan_frame *f,  enum pico_layer l, struct range r, uint16_t offset)
{
    return frame_buf_edit(f, l, r, offset, 1);
}

/* -------------------------------------------------------------------------------- */
// MARK: IEEE802.15.4
static int ieee_addr_cmp(void *va, void *vb)
{
    struct pico_ieee_addr *a = (struct pico_ieee_addr *)va;
    struct pico_ieee_addr *b = (struct pico_ieee_addr *)vb;
    enum ieee_am aam = IEEE_AM_NONE, bam = IEEE_AM_NONE;
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
}

static inline void ieee_short_to_le(uint8_t s[PICO_SIZE_IEEE_SHORT])
{
    uint8_t temp = 0;
    CHECK_PARAM_VOID(s);
    temp = s[0];
    s[0] = s[1];
    s[1] = temp;
}

static inline void ieee_ext_to_le(uint8_t ext[PICO_SIZE_IEEE_EXT])
{
    uint8_t i = 0, temp = 0;
    CHECK_PARAM_VOID(ext);
    
    for (i = 0; i < 4; i++) {
        temp = ext[i];
        ext[i] = ext[8 - (i + 1)];
        ext[8 - (i + 1)] = temp;
    }
}

static int pico_ieee_addr_modes_to_hdr(struct ieee_hdr *hdr, enum ieee_am sam, enum ieee_am dam)
{
    uint8_t *modes = NULL;
    CHECK_PARAM(hdr);
    
    sam = IEEE_AM_BOTH_TO_SHORT(sam);
    dam = IEEE_AM_BOTH_TO_SHORT(dam);
    
    /* |S|S|V|V|D|D|R|R| */
    modes = (uint8_t *)(((uint8_t *)&hdr->fcf) + 1u);
    *modes |= (uint8_t)(((uint8_t)sam << 6) | ((uint8_t)dam << 2));
    
    /* TODO: Check addresing modes in Wireshark */
    
    return 0;
}

static int pico_ieee_addr_to_flat(uint8_t *buf, struct pico_ieee_addr addr, uint8_t ieee)
{
    if (IEEE_AM_EXTENDED == addr._mode) {
        memcpy(buf, addr._ext.addr, PICO_SIZE_IEEE_EXT);
        if (ieee)
            ieee_ext_to_le(buf);
    } else if (IEEE_AM_BOTH == addr._mode || IEEE_AM_SHORT == addr._mode) {
        memcpy(buf, &addr._short.addr, PICO_SIZE_IEEE_SHORT);
#ifdef PICO_BIG_ENDIAN
        /* If Big Endian, only rearrange if it is a IEEE-buffer */
        if (ieee)
            ieee_short_to_le(buf);
#else
        /* If Little Endian, only rearrange if it's not a IEEE-buffer */
        if (!ieee)
            ieee_short_to_le(buf);
#endif
    } else {
        PAN_ERR("Address Mode (%d) is not supported\n", addr._mode);
        return (-1);
    }
    return 0;
}

static struct pico_ieee_addr_ext pico_ieee_addr_ext_from_flat(uint8_t *buf, uint8_t ieee)
{
    struct pico_ieee_addr_ext ext;
    memcpy(ext.addr, buf, PICO_SIZE_IEEE_EXT);
    if (ieee)
        ieee_ext_to_le(ext.addr);
    return ext;
}

static struct pico_ieee_addr_short pico_ieee_addr_short_from_flat(uint8_t *buf, uint8_t ieee)
{
    uint8_t temp[PICO_SIZE_IEEE_SHORT];
    struct pico_ieee_addr_short _short;
    
    /* Copy in the address from the buffer */
    memcpy(temp, buf, PICO_SIZE_IEEE_SHORT);
#ifdef PICO_BIG_ENDIAN
    if (ieee)
        ieee_short_to_le(temp);
#else
    if (!ieee)
        ieee_short_to_le(temp);
#endif
    memcpy(&_short.addr, temp, PICO_SIZE_IEEE_SHORT);
    
    return _short;
}

static struct pico_ieee_addr pico_ieee_addr_from_flat(uint8_t *buf, enum ieee_am am, uint8_t ieee)
{
    struct pico_ieee_addr addr;
    
    _CHECK_PARAM(buf, addr);
    
    /* Copy in the actual address from buffer */
    if (IEEE_AM_EXTENDED == am) {
        /* Set the addressing mode to extended */
        addr._mode = IEEE_AM_EXTENDED;
        addr._ext = pico_ieee_addr_ext_from_flat(buf, ieee);
        addr._short.addr = IEEE_ADDR_BCAST_SHORT;
    } else if (IEEE_AM_SHORT == am) {
        /* Set the addressing mode to the addressing mode from the buffer */
        addr._mode = IEEE_AM_SHORT;
        addr._short = pico_ieee_addr_short_from_flat(buf, ieee);
        memset(addr._ext.addr, 0, PICO_SIZE_IEEE_EXT);
    } else {
        /* Set the addressing mode to none, do nothing */
        addr._mode = IEEE_AM_NONE;
    }
    
    return addr;
}

static inline uint8_t ieee_hdr_len(struct sixlowpan_frame *f)
{
    CHECK_PARAM_ZERO(f);
    f->link_hdr_len = (uint8_t)(IEEE_MIN_HDR_LEN + pico_ieee_addr_len(f->peer._mode) + pico_ieee_addr_len(f->local._mode));
    
    /* Add Auxiliary Security Header in the future */
    return f->link_hdr_len;
}

static inline uint16_t ieee_len(struct sixlowpan_frame *f)
{
    CHECK_PARAM_ZERO(f);
    f->size = (uint16_t)((uint16_t)((uint16_t)ieee_hdr_len(f) + f->net_len + f->transport_len) + IEEE_PHY_OVERHEAD);
    return (uint16_t)(f->size);
}

static inline uint8_t ieee_hdr_buf_len(struct ieee_hdr *hdr)
{
    return (uint8_t)(IEEE_MIN_HDR_LEN + (uint8_t)(pico_ieee_addr_len(hdr->fcf.sam) + pico_ieee_addr_len(hdr->fcf.dam)));
}

static int ieee_provide_hdr(struct sixlowpan_frame *f)
{
    struct ieee_radio *radio = NULL;
    struct ieee_fcf *fcf = NULL;
    struct ieee_hdr *hdr = NULL;
    static uint8_t seq = 0; /* STATIC SEQUENCE NUMBER */
    
    CHECK_PARAM(f);
    
    radio = ((struct pico_device_sixlowpan *)f->dev)->radio;
    
    /* Set some shortcuts */
    hdr = f->link_hdr;
    fcf = &(hdr->fcf);
    
    /* Set Frame Control Field flags. */
    fcf->frame_type = IEEE_FRAME_TYPE_DATA;
    fcf->security_enabled = IEEE_FALSE;
    fcf->frame_pending = IEEE_FALSE;
    fcf->ack_required = IEEE_FALSE;
    fcf->intra_pan = IEEE_TRUE;
    fcf->frame_version = IEEE_FRAME_VERSION_2003;
    
    /* Set the addressing modes */
    if (IEEE_AM_BOTH == f->peer._mode)
        fcf->dam = IEEE_AM_SHORT;
    else
        fcf->dam = f->peer._mode;
    if (IEEE_AM_BOTH == f->local._mode)
        fcf->sam = IEEE_AM_SHORT;
    else
        fcf->sam = f->local._mode;
    
    /* Set sequence number and PAN ID */
    hdr->seq = seq;
    hdr->pan = radio->get_pan_id(radio);
    
    pico_ieee_addr_to_hdr(hdr, f->local, f->peer);
    
    seq++; /* Increment sequence number for the next time */
    return 0;
}

/* -------------------------------------------------------------------------------- */
// MARK: SIXLOWPAN FRAMES

static uint8_t sixlowpan_overhead(struct sixlowpan_frame *f)
{
    /* Returns overhead needed in byte for 6LoWPAN Mesh addressing and */
    uint8_t overhead = DISPATCH_MESH(INFO_HDR_LEN);
    CHECK_PARAM_ZERO(f);
    
    if (IEEE_AM_SHORT == f->peer._mode && IEEE_ADDR_BCAST_SHORT == f->peer._short.addr) {
        overhead = (uint8_t)(overhead + DISPATCH_BC0(INFO_HDR_LEN));
    }
    
    overhead = (uint8_t)(overhead + pico_ieee_addr_len(f->peer._mode));
    overhead = (uint8_t)(overhead + pico_ieee_addr_len(f->local._mode));
    return overhead;
}

static void sixlowpan_frame_destroy(struct sixlowpan_frame *f)
{
    if (!f)
        return;
    
    if (f->phy_hdr)
        PICO_FREE(f->phy_hdr);
    
    PICO_FREE(f);
}

static struct sixlowpan_frame *sixlowpan_frame_create(struct pico_ieee_addr local,
                                                      struct pico_ieee_addr peer,
                                                      uint16_t net_len,
                                                      uint16_t transport_len,
                                                      uint8_t hop_limit,
                                                      struct pico_device *dev)
{
    struct sixlowpan_frame *f = NULL;
    
    CHECK_PARAM_NULL(dev);
    if (!(f = PICO_ZALLOC(sizeof(struct sixlowpan_frame)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Set some of the fixed-sized fields */
    f->hop_limit = hop_limit;
    f->local = local;
    f->peer = peer;
    f->dev = dev;
    
    /* Calculate the lengths of the buffer-chunks */
    ieee_hdr_len(f);
    f->net_len = net_len;
    f->transport_len = transport_len;
    f->dgram_size = (uint16_t)(f->net_len + f->transport_len);
    ieee_len(f);
    
    if (!(f->phy_hdr = PICO_ZALLOC(f->size))) {
        pico_err = PICO_ERR_ENOMEM;
        PICO_FREE(f);
        return NULL;
    }
    frame_rearrange_ptrs(f);
    
    /* Fill in IEEE802.15.4 MAC header */
    ieee_provide_hdr(f);
    return f;
}

static uint8_t *sixlowpan_frame_to_buf(struct sixlowpan_frame *f, uint8_t *len)
{
    uint8_t *buf = NULL;
    CHECK_PARAM_NULL(f);
    if (!(buf = PICO_ZALLOC(f->size))) {
        f->state = FRAME_ERROR;
        return NULL;
    }
    memcpy(buf, f->phy_hdr, f->size);
    *len = (uint8_t)f->size;
    return buf;
}

static struct sixlowpan_frame *sixlowpan_buf_to_frame(uint8_t *buf, uint8_t len, struct pico_device *dev)
{
    struct pico_ieee_addr peer = IEEE_ADDR_ZERO, local = IEEE_ADDR_ZERO;
    struct sixlowpan_frame *f = NULL;
    struct ieee_hdr *link_hdr = NULL;
    uint8_t link_hdr_len = 0;
    uint16_t net_len = 0;
    CHECK_PARAM_NULL(buf);
    
    link_hdr = (struct ieee_hdr *)(buf + IEEE_LEN_LEN);
    link_hdr_len = ieee_hdr_buf_len(link_hdr);
    local = pico_ieee_addr_from_hdr(link_hdr, 0);
    peer = pico_ieee_addr_from_hdr(link_hdr, 1);
    
    /* Provide space for the sixlowpan_frame */
    net_len = (uint16_t)((uint16_t)(len - IEEE_PHY_OVERHEAD) + 1 - link_hdr_len);
    if (!(f = sixlowpan_frame_create(local, peer, net_len, 0, 0, dev)))
        return NULL;
    
    /* Copy in payload */
    memcpy(f->phy_hdr + IEEE_LEN_LEN, link_hdr, len - IEEE_PHY_OVERHEAD + 1);
    
    f->state = FRAME_COMPRESSED;
    return f;
}

static inline int sixlowpan_frame_postpone(struct sixlowpan_frame *f, uint8_t retrans)
{
    f->state = FRAME_POSTPONED;
    if (retrans) {
        rtx = f;
    }
    return f->size;
}

static inline int sixlowpan_frame_ready(struct sixlowpan_frame *f)
{
    /* Check if next hop is found, otherwise a ping is going on */
    return (IEEE_AM_NONE == f->hop._mode ? (0) : (1));
}

/* -------------------------------------------------------------------------------- */
// MARK: IIDs (ADDRESSES)
int pico_sixlowpan_iid_is_derived_16(uint8_t iid[8])
{
    /*  IID formed from 16-bit [RFC4944]: 
     *
     *  +------+------+------+------+------+------+------+------+
     *  |  PAN |  PAN | 0x00 | 0xFF | 0xFE | 0x00 | xxxx | xxxx | 
     *  +------+------+------+------+------+------+------+------+
     */
    return ((0x00 == iid[2] && 0xFF == iid[3] && 0xFE == iid[4] && 0x00 == iid[5]) ? 1 : 0);
}

static inline int sixlowpan_iid_from_extended(struct pico_ieee_addr_ext addr, uint8_t out[8])
{
    CHECK_PARAM(out);
    memcpy(out, addr.addr, PICO_SIZE_IEEE_EXT);
    out[0] = (uint8_t)(out[0] ^ (uint8_t)(0x02)); /* Toggle the U/L */
    return 0;
}

static inline int sixlowpan_iid_from_short(struct pico_ieee_addr_short addr, uint8_t out[8])
{
    uint8_t buf[8] = {0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00};
    uint16_t s = addr.addr;
    CHECK_PARAM(out);
    buf[6] = (uint8_t)((s >> 8) & 0xFF);
    buf[7] = (uint8_t)(s & 0xFF);
    memcpy(out, buf, 8);
    return 0;
}

static int ieee_addr_from_iid(struct pico_ieee_addr *addr, uint8_t in[8])
{
    CHECK_PARAM(addr);
    CHECK_PARAM(in);
    if (pico_sixlowpan_iid_is_derived_16(in)) {
        addr->_mode = IEEE_AM_SHORT;
        memcpy(&addr->_short.addr, in + 6, PICO_SIZE_IEEE_SHORT);
        addr->_short.addr = short_be(addr->_short.addr);
    } else {
        addr->_mode = IEEE_AM_EXTENDED;
        memcpy(addr->_ext.addr, in, PICO_SIZE_IEEE_EXT);
        addr->_ext.addr[0] = (uint8_t)(addr->_ext.addr[0] ^ 0x02); /* Set the U/L to unique */
    }
    return 0;
}

/* -------------------------------------------------------------------------------- */
// MARK: 6LoWPAN to IPv6 (ADDRESSES)
static int sixlowpan_ipv6_derive_local(struct pico_ieee_addr *addr, uint8_t ip[PICO_SIZE_IP6])
{
    struct pico_ip6 linklocal = {{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    int ret = 0;
    
    CHECK_PARAM(addr);
    CHECK_PARAM(ip);
    
    if (addr->_mode == IEEE_AM_SHORT || addr->_mode == IEEE_AM_BOTH) {
        ret = sixlowpan_iid_from_short(addr->_short, linklocal.addr + 8);
    } else {
        ret = sixlowpan_iid_from_extended(addr->_ext, linklocal.addr + 8);
    }
    
    if (!ret)
        memcpy(ip, linklocal.addr, PICO_SIZE_IP6);
    
    return ret;
}

static int sixlowpan_ipv6_derive_mcast(enum iphc_mcast_dam am, uint8_t *addr)
{
    struct pico_ip6 mcast = {{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    
    switch (am) {
        case MCAST_COMPRESSED_8:
            mcast.addr[1] = 0x02;
            mcast.addr[15] = addr[15];
            break;
        case MCAST_COMPRESSED_32:
            mcast.addr[1] = addr[0];
            memmove(mcast.addr + 13, addr + 1, 3);
            break;
        case MCAST_COMPRESSED_48:
            mcast.addr[1] = addr[0];
            memmove(mcast.addr + 11, addr + 1, 5);
            break;
        default:
            /* IPv6 is fully carried inline */
            return 0;
    }
    memcpy(addr, mcast.addr, PICO_SIZE_IP6);
    return 0;
}

/* -------------------------------------------------------------------------------- */
// MARK: IPv6 to 6LoWPAN (ADDRESSES)
static int sixlowpan_ping_cmp(void *a, void *b)
{
    struct ping_cookie *pa = a, *pb = b;
    
    if (!a || !b)
        return -1;
    
    /* Then compare the ID's */
    return (int)((int)pa->id - (int)pb->id);
}
PICO_TREE_DECLARE(SixlowpanPings, &sixlowpan_ping_cmp);

static struct ping_cookie *sixlowpan_ping_find_cookie(struct pico_ieee_addr dst)
{
    struct pico_tree_node *node = NULL;
    struct ping_cookie *cookie = NULL;
    
    pico_tree_foreach(node, &SixlowpanPings) {
        if ((cookie = (struct ping_cookie *)node->keyValue)) {
            if (0 == ieee_addr_cmp(&cookie->dst, &dst)) {
                return cookie;
            }
        }
    }
    
    return NULL;
}

static int sixlowpan_derive_local(struct pico_ieee_addr *l, struct pico_ip6 *ip)
{
    CHECK_PARAM(ip);
    CHECK_PARAM(l);
    
    ieee_addr_from_iid(l, ip->addr + 8);
    
    return 0;
}

static inline int sixlowpan_derive_mcast(struct pico_ieee_addr *l, struct pico_ip6 *ip)
{
    /* For now, ignore IP */
    IGNORE_PARAMETER(ip);
    CHECK_PARAM(l);
    
    /*  RFC: IPv6 level multicast packets MUST be carried as link-layer broadcast
     *  frame in IEEE802.15.4 networks. */
    l->_mode = IEEE_AM_SHORT;
    l->_short.addr = IEEE_ADDR_BCAST_SHORT;
    
    return 0;
}

static int sixlowpan_derive_nd(struct pico_frame *f, struct pico_ieee_addr *l)
{
    struct pico_ieee_addr *neighbor = NULL;
    CHECK_PARAM(f);
    CHECK_PARAM(l);
    
    /* Discover neighbor link address using 6LoWPAN ND for dst address */
    if ((neighbor = (struct pico_ieee_addr *)pico_ipv6_get_neighbor(f))) {
        memcpy(l, neighbor, sizeof(struct pico_ieee_addr));
        return 0;
    }
    
    return -1;
}

static int sixlowan_rtable_entry_cmp(void *a, void *b)
{
    struct sixlowpan_rtable_entry *ra = (struct sixlowpan_rtable_entry *)a;
    struct sixlowpan_rtable_entry *rb = (struct sixlowpan_rtable_entry *)b;
    CHECK_PARAM(ra);
    CHECK_PARAM(rb);
    
    /* Only compare on the destination-address */
    return ieee_addr_cmp((void *)&ra->dst, (void *)&rb->dst);
}
PICO_TREE_DECLARE(RTable, &sixlowan_rtable_entry_cmp);

static struct sixlowpan_rtable_entry *sixlowpan_rtable_find_entry(struct pico_ieee_addr dst)
{
    struct sixlowpan_rtable_entry *test = NULL, *entry = NULL;
    
    /* Create a test-entry */
    if (!(test = PICO_ZALLOC(sizeof(struct sixlowpan_rtable_entry)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Set searchable params of the test-entry */
    test->dst = dst;
    
    /* Try to find the entry for the destination address in the routing table */
    entry = (struct sixlowpan_rtable_entry *)pico_tree_findKey(&RTable, test);
    PICO_FREE(test);
    return entry;
}

static struct pico_ieee_addr sixlowpan_rtable_find_via(struct pico_ieee_addr dst, struct pico_device *dev)
{
    struct pico_ieee_addr via = IEEE_ADDR_ZERO, via_zero = IEEE_ADDR_ZERO;
    struct sixlowpan_rtable_entry *entry = NULL;
    struct ping_cookie *cookie = NULL;
    uint32_t now = PICO_TIME();
    
    /* Try to find the entry for the destination address in the routing table */
    if ((entry = sixlowpan_rtable_find_entry(dst))) {
        /* If hops is 0, it means hops isn't known and ping is going on, trigger postponing */
        if (!entry->hops) {
            PAN_DBG("Ping is going on for this destination, postponing...\n");
            return via_zero;
        }
        
        /* Destiniation is multiple hops away, via is gateway */
        via = entry->via;
        
        /* Is the entry stale and outdated? */
        if ((uint32_t)(now - entry->timestamp) > RTABLE_ENTRY_TTL) {
            if (!(cookie = sixlowpan_ping_find_cookie(dst))) {
                /* Only send ping when there's no ping for this dest already going on */
                sixlowpan_ping(entry->dst, via, dev, 0, IEEE_AM_NONE);
            }
            return via_zero;
        }
    } else {
//        PAN_DBG("No routing table entry found, sending via BCAST\n");
        via._short.addr = IEEE_ADDR_BCAST_SHORT;
        via._mode = IEEE_AM_SHORT;
    }
    
    return via;
}

static void sixlowpan_resume_tx(struct pico_ieee_addr final, struct pico_ieee_addr next_hop)
{
    if (tx && !ieee_addr_cmp(&final, &tx->peer)) {
        tx->hop = next_hop;
        sixlowpan_prep_tx();
    }
}

static void sixlowpan_resume_rtx(struct pico_ieee_addr final, struct pico_ieee_addr next_hop)
{
    if (rtx && !ieee_addr_cmp(&final, &rtx->peer)) {
        rtx->hop = next_hop;
        sixlowpan_update_addr(rtx, SIXLOWPAN_DST);
        sixlowpan_update_addr(rtx, SIXLOWPAN_SRC);
        sixlowpan_retransmit(rtx);
        sixlowpan_frame_destroy(rtx);
        rtx = NULL;
    }
}

static void pico_ieee_addr_to_str(char llstring[PICO_SIZE_IEEE_ADDR_STR], struct pico_ieee_addr *addr)
{
    if (IEEE_AM_SHORT == addr->_mode || IEEE_AM_BOTH == addr->_mode) {
        snprintf(llstring, PICO_SIZE_IEEE_ADDR_STR, "0x%04X", short_be(addr->_short.addr));
    } else if (IEEE_AM_EXTENDED == addr->_mode) {
        snprintf(llstring, PICO_SIZE_IEEE_ADDR_STR, "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 addr->_ext.addr[0],
                 addr->_ext.addr[1],
                 addr->_ext.addr[2],
                 addr->_ext.addr[3],
                 addr->_ext.addr[4],
                 addr->_ext.addr[5],
                 addr->_ext.addr[6],
                 addr->_ext.addr[7]);
    } else {
        snprintf(llstring, PICO_SIZE_IEEE_ADDR_STR, "(invalid)");
    }
}

static void sixlowpan_update_routing_table(struct sixlowpan_frame *f, uint16_t id, uint8_t hops_left)
{
    struct ping_cookie test = {.dst = IEEE_ADDR_ZERO, .id = short_be(id)};
    struct sixlowpan_rtable_entry *entry = NULL;
    struct ping_cookie *cookie = NULL;
    char llstring[PICO_SIZE_IEEE_ADDR_STR] = {0};
    CHECK_PARAM_VOID(f);
    
    if ((cookie = pico_tree_findKey(&SixlowpanPings, &test))) {
        /* Ping reply is sollicited, find the entry for the origin */
        if ((entry = sixlowpan_rtable_find_entry(f->peer))) {
            /* Check if for the ping reply, the hops of the entry isn't known yet, or came from a more optimal route */
            if (!entry->hops || (hops_left < entry->hops)) {
                entry->hops = (uint8_t)((uint8_t)SIXLOWPAN_PING_TTL - hops_left);
                entry->timestamp = PICO_TIME();
                entry->via = f->hop;
                pico_ieee_addr_to_str(llstring, &entry->dst);
                PAN_DBG("Routing table entry (%s) updated to hops: (%d)\n", llstring, entry->hops);
            }
            
            /* If the ping was required to send current frame, determine next hop and resume */
            sixlowpan_resume_tx(entry->dst, entry->via);
            sixlowpan_resume_rtx(entry->dst, entry->via);
        }
        
        pico_tree_delete(&SixlowpanPings, cookie);
        PICO_FREE(cookie);
    }
}

static void sixlowpan_rtable_remove(struct pico_ieee_addr dst)
{
    struct sixlowpan_rtable_entry *entry = NULL;
    entry = sixlowpan_rtable_find_entry(dst);
    
    if (entry) {
        pico_tree_delete(&RTable, entry);
        PICO_FREE(entry);
    }
}

static int sixlowpan_rtable_insert(struct pico_ieee_addr dst, struct pico_ieee_addr via, uint8_t hops)
{
    struct sixlowpan_rtable_entry *entry = NULL;
    if (!(entry = PICO_ZALLOC(sizeof(struct sixlowpan_rtable_entry)))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    
    entry->dst = dst;
    entry->via = via;
    entry->hops = hops;
    entry->timestamp = PICO_TIME();
    
    if (pico_tree_insert(&RTable, (void *)entry)) {
        PAN_ERR("Could not insert entry into routing table\n");
        PICO_FREE(entry);
        return -1;
    }
    
    return 0;
}

static void sixlowpan_rtable_hop_by_source(struct pico_ieee_addr last_hop)
{
    struct sixlowpan_rtable_entry *entry = NULL;
    
    if ((entry = sixlowpan_rtable_find_entry(last_hop))) {
        /* If entry for this dst is already in routing table, update to neighbor */
        entry->via = last_hop;
        entry->timestamp = PICO_TIME();
        entry->hops = 1;
    } else {
        if (sixlowpan_rtable_insert(last_hop, last_hop, 1))
            PAN_ERR("Unable to insert last hop into routing table\n");
    }
}

static void sixlowpan_rtable_origin_via_source(struct pico_ieee_addr origin, struct pico_ieee_addr last_hop, struct pico_device *dev)
{
    struct sixlowpan_rtable_entry *entry = NULL;
    
    if (0 == ieee_addr_cmp(&origin, dev->eth)) {
//        PAN_DBG("I'm the origin, I'm not going to add a route to myself, am I?\n");
        return;
    }
    
    /* Find entry in the routing table */
    if ((entry = sixlowpan_rtable_find_entry(origin))) {
        /* Origin is already in routing table with this gateway, not going to send ping when I don't really need it */
        if (0 == ieee_addr_cmp(&entry->via, &last_hop))
            return;
        
        /* Only send ping to update route when origin isn't a neigbor */
        if (1 != entry->hops) {
            /* Send LL-ping to compare the hops of the new route to the hops already in the routing table */
            sixlowpan_ping(origin, last_hop, dev, 0, IEEE_AM_NONE);
        }
    } else {
        /* An entry was not found, add a new entry for this route */
        if (sixlowpan_rtable_insert(origin, last_hop, 0))
            PAN_ERR("Unable to insert last hop into routing table\n");
        
        /* Send ping to determine the hops in between, we can't rely on hops left, since we don't know the original hl */
        sixlowpan_ping(origin, last_hop, dev, 0, IEEE_AM_NONE);
    }
}

static void sixlowpan_build_routing_table(struct pico_ieee_addr origin, struct pico_ieee_addr last_hop, struct pico_device *dev)
{
    sixlowpan_rtable_hop_by_source(last_hop);
    sixlowpan_rtable_origin_via_source(origin, last_hop, dev);
}

static void sixlowpan_ping_timeout(pico_time now, void *arg)
{
    struct pico_ieee_addr bcast = IEEE_ADDR_ZERO;
    struct ping_cookie *cookie = NULL;
    IGNORE_PARAMETER(now);
    
    bcast._mode = IEEE_AM_SHORT;
    bcast._short.addr = IEEE_ADDR_BCAST_SHORT;
    
    if ((cookie = (struct ping_cookie *)pico_tree_delete(&SixlowpanPings, arg))) {
        PAN_ERR("6LoWPAN Ping timeout, routed is being removed from routing table...\n");
        sixlowpan_rtable_remove(cookie->dst);
        sixlowpan_resume_tx(cookie->dst, bcast);
        sixlowpan_resume_rtx(cookie->dst, bcast);
        PICO_FREE(cookie);
    }
}

static int sixlowpan_ping(struct pico_ieee_addr dst, struct pico_ieee_addr last_hop, struct pico_device *dev, uint16_t id, enum ieee_am reply_mode)
{
    struct pico_device_sixlowpan *slp = (struct pico_device_sixlowpan *)dev;
    struct sixlowpan_ping *ping = NULL;
    struct pico_ieee_addr *src = NULL;
    struct ping_cookie *cookie = NULL;
    struct sixlowpan_frame *f = NULL;
    static uint16_t next_id = 0x91c0;
    uint8_t *buf = NULL, len = 0;
    
    CHECK_PARAM(dev);
    
    /* Create a ping frame */
    src = (struct pico_ieee_addr *)dev->eth;
    if (!(f = sixlowpan_frame_create(*src, dst, (uint16_t)sizeof(struct sixlowpan_ping), 0, SIXLOWPAN_PING_TTL, dev))) {
        PAN_ERR("Unable to provide a 6LoWPAN-frame\n");
        return -1;
    }
    
    /* Set the next hop to hop via which we want to ping */
    f->hop = last_hop;
    
    /* Parse in the network section of the frame as ping header */
    ping = (struct sixlowpan_ping *)f->net_hdr;
    if (id) {
        /* Reply with correct address, if the request asked for an extended reply with one and so with short addresses as well */
        f->local._mode = reply_mode;
        ping->dispatch = DISPATCH_PING_REPLY(INFO_VAL) << DISPATCH_PING_REPLY(INFO_SHIFT);
        ping->id = short_be(id);
    } else {
        /* Set the ping fields to that of a ping request */
        ping->dispatch = DISPATCH_PING_REQUEST(INFO_VAL) << DISPATCH_PING_REQUEST(INFO_SHIFT);
        ping->id = short_be(next_id++);
        
        /* Create a ping-cookie for a Ping request */
        if (!(cookie = PICO_ZALLOC(sizeof(struct ping_cookie)))) {
            sixlowpan_frame_destroy(f);
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
        
        /* Set some params of the ping-cookie */
        cookie->dst = dst;
        cookie->id = ping->id;
        
        /* Insert a cookie of the request in the Cookie-tree */
        if (pico_tree_insert(&SixlowpanPings, cookie)) {
            sixlowpan_frame_destroy(f);
            PICO_FREE(cookie);
            return -1;
        }
        
        /* Start a timeout-timer */
        pico_timer_add(SIXLOWPAN_PING_TIMEOUT, sixlowpan_ping_timeout, cookie);
    }
    
    /* Conver the ping-frame to a buffer */
    if (!(buf = sixlowpan_frame_to_buf(f, &len))) {
        PAN_ERR("Could convert ping-frame to buffer\n");
        sixlowpan_frame_destroy(f);
        return -1;
    }
    
    /* Provide the mesh header for the Ping request */
    if (!(buf = sixlowpan_mesh_out(buf, &len, f))) {
        PAN_ERR("During mesh addressing\n");
        sixlowpan_frame_destroy(f);
        /* Don't bother removing cookie from tree when the timer times out it will be removed and destroyed */
        return -1;
    }
    
    /* Transmit the frame on the wire */
    slp->radio->transmit(slp->radio, buf, len);
    
    /* Destroy the Ping-frame and the buffer with the raw packet */
    sixlowpan_frame_destroy(f);
    PICO_FREE(buf);
    return 0;
}

static int sixlowpan_ping_recv(struct sixlowpan_frame *f)
{
    struct sixlowpan_ping *ping = NULL;
    
    ping = (struct sixlowpan_ping *)f->net_hdr;
    if (CHECK_DISPATCH(ping->dispatch, SIXLOWPAN_PING_REQUEST)) {
        sixlowpan_ping(f->peer, f->hop, f->dev, short_be(ping->id), f->local._mode);
        return 1;
    } else if (CHECK_DISPATCH(ping->dispatch, SIXLOWPAN_PING_REPLY)) {
        sixlowpan_update_routing_table(f, short_be(ping->id), f->hop_limit);
        return 1;
    } else {
        /* Dispatch is neither ping-request or ping-reply, continue parsing */
    }
    
    return 0;
}

static int sixlowpan_determine_final_dst(struct pico_frame *f, struct pico_ieee_addr *l)
{
    struct pico_ip6 *dst = NULL;
    
    CHECK_PARAM(f);
    
    dst = &((struct pico_ipv6_hdr *)f->net_hdr)->dst;
    
    if (pico_ipv6_is_multicast(dst->addr)) {
        /* Derive link layer address from IPv6 Multicast address */
        return sixlowpan_derive_mcast(l, dst);
    } else {
        /* For either linklocal as unicast, derive L2-address from IP */
        return sixlowpan_derive_local(l, dst);
    }
    
    return 0;
}

static struct pico_ieee_addr sixlowpan_determine_next_hop(struct sixlowpan_frame *f)
{
    struct pico_ieee_addr hop = IEEE_ADDR_ZERO;
    _CHECK_PARAM(f, hop);
    
    if (IEEE_ADDR_IS_BCAST(f->peer)) {
        /* If final destination is BCAST, next hop is also BCAST */
        hop._mode = IEEE_AM_SHORT;
        hop._short.addr = IEEE_ADDR_BCAST_SHORT;
    } else {
        /* If the final destination isn't broadcast, determine next hop by the routing table */
        hop = sixlowpan_rtable_find_via(f->peer, f->dev);
    }
    
    return hop;
}

/* -------------------------------------------------------------------------------- */
// MARK: LOWPAN_NHC
/* -------------------------------------------------------------------------------- */
// MARK: COMMON COMPRESSION/DECOMPRESSION
static inline int sixlowpan_nh_is_compressible(uint8_t nh)
{
    switch (nh) {
        case PICO_IPV6_EXTHDR_HOPBYHOP: /* Intentional fall through */
        case PICO_IPV6_EXTHDR_ROUTING: /* Intentional fall through */
        case PICO_IPV6_EXTHDR_FRAG: /* Intentional fall through */
        case PICO_IPV6_EXTHDR_DESTOPT: /* Intentional fall through */
        case PICO_PROTO_UDP:
            return 1;
        default:
            return 0;
    }
}

static inline uint8_t sixlowpan_nh_from_eid(enum nhc_ext_eid eid)
{
    switch (eid) {
        case EID_HOPBYHOP:
            return PICO_IPV6_EXTHDR_HOPBYHOP;
        case EID_DESTOPT:
            return PICO_IPV6_EXTHDR_DESTOPT;
        case EID_FRAGMENT:
            return PICO_IPV6_EXTHDR_FRAG;
        case EID_ROUTING:
            return PICO_IPV6_EXTHDR_ROUTING;
        default:
            return PICO_IPV6_EXTHDR_NONE;
    }
}

static enum nhc_udp_ports sixlowpan_nhc_udp_ports(uint16_t src, uint16_t dst, uint32_t *comp)
{
    CHECK_PARAM_ZERO(comp);
    
    src = short_be(src);
    dst = short_be(dst);
    
    if (UDP_ARE_PORTS_4(src, dst)) {
        *comp = long_be(((uint32_t)((uint32_t)(UINT32_4LSB(src) << 4) | UINT32_4LSB(dst))) << 24);
        return PORTS_COMPRESSED_FULL;
    } else if (UDP_IS_PORT_8(dst)) {
        *comp = long_be(((uint32_t)(((uint32_t)src << 8) | UINT32_8LSB(dst))) << 8);
        return PORTS_COMPRESSED_DST;
    } else if (UDP_IS_PORT_8(src)) {
        *comp = long_be(((uint32_t)((UINT32_8LSB(src) << 16) | (uint32_t)dst)) << 8);
        return PORTS_COMPRESSED_SRC;
    } else {
        *comp = (uint32_t)0x0;
        return PORTS_COMPRESSED_NONE;
    }
}

/* -------------------------------------------------------------------------------- */
// MARK: DECOMPRESSION
static void sixlowpan_nhc_udp_ports_undo(enum nhc_udp_ports ports, struct sixlowpan_frame *f)
{
    uint16_t sport = 0xF000, dport = 0xF000;
    struct pico_udp_hdr *hdr = NULL;
    uint8_t *buf = NULL;
    
    CHECK_PARAM_VOID(f);
    
    buf = (uint8_t *)(f->transport_hdr);
    
    switch (ports) {
        case PORTS_COMPRESSED_FULL:
            sport = (uint16_t)(sport | 0x00B0 | (uint16_t)(buf[0] >> 4));
            dport = (uint16_t)(dport | 0x00B0 | (uint16_t)(buf[0] & 0x0F));
            frame_buf_prepend(f, PICO_LAYER_TRANSPORT, 3);
            break;
        case PORTS_COMPRESSED_DST:
            sport = short_be(*(uint16_t *)(buf));
            dport = (uint16_t)(dport | (uint16_t)buf[2]);
            frame_buf_prepend(f, PICO_LAYER_TRANSPORT, 1);
            break;
        case PORTS_COMPRESSED_SRC:
            sport = (uint16_t)(sport | (uint16_t)buf[0]);
            dport = short_be(*(uint16_t *)(buf + 1));
            frame_buf_prepend(f, PICO_LAYER_TRANSPORT, 1);
            break;
        default:
            /* Do nothing */
            return;
    }
    
    hdr = (struct pico_udp_hdr *)f->transport_hdr;
    hdr->trans.sport = short_be(sport);
    hdr->trans.dport = short_be(dport);
}

static uint8_t sixlowpan_nhc_udp_undo(struct sixlowpan_nhc_udp *udp, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_NHC_UDP(INFO_HDR_LEN)};
    enum nhc_udp_ports ports = PORTS_COMPRESSED_NONE;
    
    _CHECK_PARAM(udp, 0xFF);
    _CHECK_PARAM(f, 0xFF);
    
    ports = udp->ports;
    frame_buf_delete(f, PICO_LAYER_TRANSPORT, r, 0);
    
    /* UDP is in the transport layer */
    if (ports)
        sixlowpan_nhc_udp_ports_undo(ports, f);
    
    r.offset = 4;
    r.length = 2;
    frame_buf_insert(f, PICO_LAYER_TRANSPORT, r);
    
    return PICO_PROTO_UDP;
}

static uint8_t sixlowpan_nhc_ext_undo(struct sixlowpan_nhc_ext *ext, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_NHC_EXT(INFO_HDR_LEN)};
    struct pico_ipv6_exthdr *exthdr = NULL;
    uint8_t *nh = NULL;
    uint8_t d = 0;
    
    _CHECK_PARAM(ext, 0xFF);
    
    /* Parse in the dispatch */
    d = *(uint8_t *)ext;
    
    if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_EXT)) {
        if (!ext->nh) {
            /* nxthdr is carried inline, delete the NHC header */
            r.offset = (uint16_t)(((uint8_t *)ext) - f->net_hdr);
            frame_buf_delete(f, PICO_LAYER_NETWORK, r, 0);
        } else {
            /* Access the buffer as a IPv6 extension header */
            exthdr = (struct pico_ipv6_exthdr *)ext;
            
            /* Get the following Next Header location */
            if (EID_FRAGMENT == ext->eid) {
                nh = ((uint8_t *)ext) + 8;
                f->net_len = (uint16_t)(f->net_len + 8);
            } else {
                nh = ((uint8_t *)ext) + IPV6_OPTLEN(exthdr->ext.destopt.len);
                f->net_len = (uint16_t)(f->net_len + IPV6_OPTLEN(exthdr->ext.destopt.len));
            }
            
            /* Get the nxthdr recursively */
            exthdr->nxthdr = sixlowpan_nhc_ext_undo((struct sixlowpan_nhc_ext *)nh, f);
        }
        return sixlowpan_nh_from_eid(ext->eid);
    } else if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_UDP)) {
        frame_rearrange_ptrs(f);
        return sixlowpan_nhc_udp_undo((struct sixlowpan_nhc_udp *)f->transport_hdr, f);
    } else {
        /* Shouldn't be possible */
        return 0xFF;
    }
}

static void sixlowpan_nhc_decompress(struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    union nhc_hdr *nhc = NULL;
    uint8_t d = 0, nxthdr = 0;
    
    /* Set size temporarily of the net_hdr */
    f->transport_len = (uint16_t)(f->net_len - PICO_SIZE_IP6HDR);
    f->net_len = (uint16_t)PICO_SIZE_IP6HDR;
    frame_rearrange_ptrs(f);
    
    nhc = (union nhc_hdr *)(f->net_hdr + PICO_SIZE_IP6HDR);
    d = *(uint8_t *)(nhc);
    
    if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_EXT)) {
        nxthdr = sixlowpan_nhc_ext_undo((struct sixlowpan_nhc_ext *)nhc, f);
    } else if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_UDP)) {
        nxthdr = sixlowpan_nhc_udp_undo((struct sixlowpan_nhc_udp *)f->transport_hdr, f);
    } else {
        f->state = FRAME_ERROR;
        return;
    }
    
    /* Parse in the IPv6 header to set the IPv6-nxthdr */
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    hdr->nxthdr = nxthdr;
    
    f->net_len = (uint16_t)(f->transport_len + PICO_SIZE_IP6HDR);
    f->transport_len = (uint16_t)(0);
    frame_rearrange_ptrs(f);
    f->state = FRAME_DECOMPRESSED;
}

/* -------------------------------------------------------------------------------- */
// MARK: COMPRESSION
static uint8_t sixlowpan_nhc_udp(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    struct sixlowpan_nhc_udp *nhc = NULL;
    struct pico_udp_hdr *udp = NULL;
    
    if (!frame_buf_prepend(f, PICO_LAYER_TRANSPORT, DISPATCH_NHC_UDP(INFO_HDR_LEN))) {
        f->state = FRAME_ERROR;
        return 0;
    }
    
    /* Parse in the UDP header */
    udp = (struct pico_udp_hdr *)(f->transport_hdr + 1);
    nhc = (struct sixlowpan_nhc_udp *)f->transport_hdr;
    
    nhc->dispatch = DISPATCH_NHC_UDP(INFO_VAL);
    nhc->ports = sixlowpan_nhc_udp_ports(udp->trans.sport, udp->trans.dport, (uint32_t *)udp);
    /* For now, don't compress the checksum because we have to have the authority from the upper layers */
    nhc->checksum = CHECKSUM_COMPRESSED_NONE;
    
    if (PORTS_COMPRESSED_FULL == nhc->ports) {
        r.offset = 1u; /* 4-bit src + 4-bit dst */
        r.length = 5; /* Compressed port bytes + length field size */
    } else if (PORTS_COMPRESSED_DST == nhc->ports || PORTS_COMPRESSED_SRC == nhc->ports) {
        r.offset = 3u; /* 8-bit x + 16-bit y */
        r.length = 3; /* Compressed port bytes + length field size */
    } else {
        r.offset = 0u; /* 16-bit src + 16-bit dst*/
        r.length = 2; /* Only the length field size */
    }
    frame_buf_delete(f, PICO_LAYER_TRANSPORT, r, DISPATCH_NHC_UDP(INFO_HDR_LEN));
    
    f->state = FRAME_COMPRESSED_NHC;
    return PICO_PROTO_UDP;
}

static uint8_t sixlowpan_nhc_ext(enum nhc_ext_eid eid, uint8_t **buf, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    struct sixlowpan_nhc_ext *nhc = NULL;
    struct pico_ipv6_exthdr *ext = NULL;
    
    /* *ALWAYS* prepend some space for the LOWPAN_NHC header */
    r.offset = (uint16_t)(*buf - f->net_hdr);
    r.length = DISPATCH_NHC_EXT(INFO_HDR_LEN);
    if (!(*buf = frame_buf_insert(f, PICO_LAYER_NETWORK, r))) {
        f->state = FRAME_ERROR;
        return 0;
    }
    
    /* Rearrange the pointers */
    ext = (struct pico_ipv6_exthdr *)(*buf + DISPATCH_NHC_EXT(INFO_HDR_LEN));
    nhc = (struct sixlowpan_nhc_ext *)*buf;
    
    /* Set the dispatch of the LOWPAN_NHC header */
    nhc->dispatch = DISPATCH_NHC_EXT(INFO_VAL);
    nhc->eid = eid; /* Extension IDentifier */
    
    /* Determine if the next header is compressible */
    if (sixlowpan_nh_is_compressible(ext->nxthdr)) {
        /* Next header is compressible */
        f->state = FRAME_COMPRESSIBLE_NH;
        nhc->nh = NH_COMPRESSED;
        
        /* Next header is compressed, sent as part of the LOWPAN_NHC header so can be elided */
        r.offset = (uint16_t)((uint16_t)(*buf - f->net_hdr) + DISPATCH_NHC_EXT(INFO_HDR_LEN));
        r.length = IPV6_EXT_LEN_NXTHDR;
        if (!frame_buf_delete(f, PICO_LAYER_NETWORK, r, 0)) {
            f->state = FRAME_ERROR;
            return ext->nxthdr;
        }
    } else {
        /* Next header field is transmitted in-line */
        f->state = FRAME_COMPRESSED_NHC;
        nhc->nh = NH_COMPRESSED_NONE;
    }
    
    /* Set the pointer to the next sheader */
    if (EID_FRAGMENT != eid)
        *buf = ((uint8_t *)*buf) + IPV6_OPTLEN(ext->ext.destopt.len);
    else
        *buf = ((uint8_t *)*buf) + 8u;
    
    return ext->nxthdr;
}

static uint8_t sixlowpan_nhc(struct sixlowpan_frame *f, uint8_t **buf, uint8_t nht)
{
    /* Check which type of next header we heave to deal with */
    switch (nht) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
            return sixlowpan_nhc_ext(EID_HOPBYHOP, buf, f);
        case PICO_IPV6_EXTHDR_ROUTING:
            return sixlowpan_nhc_ext(EID_ROUTING, buf, f);
        case PICO_IPV6_EXTHDR_FRAG:
            return sixlowpan_nhc_ext(EID_FRAGMENT, buf, f);
        case PICO_IPV6_EXTHDR_DESTOPT:
            return sixlowpan_nhc_ext(EID_DESTOPT, buf, f);
        case PICO_PROTO_UDP:
            return sixlowpan_nhc_udp(f); /* Will always in the transport layer so we can just pass the frame */
        default:
            f->state = FRAME_ERROR;
            return PICO_PROTO_ICMP6;
    }
}

static void sixlowpan_nhc_compress(struct sixlowpan_frame *f, uint8_t nht)
{
    uint8_t *nh = NULL;
    CHECK_PARAM_VOID(f);
    
    /* First time in this function, next header is right after IPv6 header */
    nh = f->net_hdr + DISPATCH_IPHC(INFO_HDR_LEN) + PICO_SIZE_IP6HDR;
    
    /* Compress header untill it isn't compressible anymore */
    while (FRAME_COMPRESSIBLE_NH == f->state) {
        nht = sixlowpan_nhc(f, &nh, nht);
    }
}

/* -------------------------------------------------------------------------------- */
// MARK: LOWPAN_IPHC
/* -------------------------------------------------------------------------------- */
// MARK: COMMON COMPRESSION/DECOMPRESSION
static inline int sixlowpan_iphc_pl_redo(struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    struct pico_udp_hdr *udp = NULL;
    CHECK_PARAM(f);
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    hdr->len = short_be((uint16_t)(f->net_len - PICO_SIZE_IP6HDR));
    if (PICO_PROTO_UDP == hdr->nxthdr) {
        udp = (struct pico_udp_hdr *)(f->net_hdr + PICO_SIZE_IP6HDR);
        udp->len = hdr->len;
    }
    return 0;
}

static inline struct range sixlowpan_iphc_tf_range(enum iphc_tf tf)
{
    struct range r = {.offset = 0, .length = 0};
    
    switch (tf) {
        case TF_COMPRESSED_TC:
            r.offset = 3;
            r.length = 1;
            break;
        case TF_COMPRESSED_FL:
            r.offset = 1;
            r.length = 3;
            break;
        case TF_COMPRESSED_FULL:
            r.offset = 0;
            r.length = 4;
            break;
        default:
            /* Return default range */
            break;
    }
    
    return r;
}

static inline struct range sixlowpan_iphc_mcast_range(enum iphc_mcast_dam am)
{
    struct range r = {.offset = 0, .length = 0};
    
    switch (am) {
        case MCAST_COMPRESSED_8:
            r.offset = IPV6_OFFSET_DST + IPHC_SIZE_MCAST_8;
            r.length = IPV6_LEN_DST - IPHC_SIZE_MCAST_8;
            break;
        case MCAST_COMPRESSED_32:
            r.offset = IPV6_OFFSET_DST + IPHC_SIZE_MCAST_32;
            r.length = IPV6_LEN_DST - IPHC_SIZE_MCAST_32;
            break;
        case MCAST_COMPRESSED_48:
            r.offset = IPV6_OFFSET_DST + IPHC_SIZE_MCAST_48;
            r.length = IPV6_LEN_DST - IPHC_SIZE_MCAST_48;
            break;
        default:
            /* IPv6 is fully carried inline */
            break;
    }
    
    return r;
}

/* -------------------------------------------------------------------------------- */
// MARK: COMPRESSION
static struct range sixlowpan_iphc_rearrange_mcast(struct sixlowpan_iphc *iphc, uint8_t *addr)
{
    iphc->mcast = MCAST_MULTICAST; /* Set MCAST-flag of IPHC */
    
    if (IPV6_IS_MCAST_8(addr)) {
        /* Set DAM */
        iphc->dam = MCAST_COMPRESSED_8;
        addr[0] = addr[15];
    } else if (IPV6_IS_MCAST_32(addr)) {
        /* Set DAM */
        iphc->dam = MCAST_COMPRESSED_32;
        addr[0] = addr[1];
        memmove(addr + 1, addr + 13, 3);
    } else if (IPV6_IS_MCAST_48(addr)) {
        /* Set DAM */
        iphc->dam = MCAST_COMPRESSED_48;
        addr[0] = addr[1];
        memmove(addr + 1, addr + 11, 5);
    } else {
        /* Full address is carried in-line */
        iphc->dam = MCAST_COMPRESSED_NONE;
    }
    
    return sixlowpan_iphc_mcast_range(iphc->dam);
}

static struct range sixlowpan_iphc_dam(struct sixlowpan_iphc *iphc, uint8_t *addr)
{
    struct range r = {.offset = 0, .length = 0};
    _CHECK_PARAM(iphc, r);
    _CHECK_PARAM(addr, r);
    
    iphc->mcast = MCAST_MULTICAST_NONE; /* Set by default to unicast */
    iphc->dac = AC_COMPRESSION_STATELESS; /* For now, use stateless compression */
    iphc->dam = AM_COMPRESSED_NONE; /* Set by default to no compression */
    
    if (pico_ipv6_is_linklocal(addr)) {
        /* Fully compress IPv6-address when it's Link Local */
        iphc->dam = AM_COMPRESSED_FULL;
        r.offset = IPV6_OFFSET_DST;
        r.length = IPV6_LEN_DST;
    } else if (pico_ipv6_is_multicast(addr)) {
        /* Rearrange IPv6-address when it's multicast */
        r = sixlowpan_iphc_rearrange_mcast(iphc, addr);
    } else {
        /* This will not occur */
    }
    
    return r;
}

static struct range sixlowpan_iphc_sam(struct sixlowpan_iphc *iphc, uint8_t *addr)
{
    struct range r = {.offset = 0, .length = 0};
    if (!iphc || !addr) /* Checking params */
        return r;
    
    iphc->context_ext = CID_CONTEXT_NONE; /* For now */
    iphc->sac = AC_COMPRESSION_STATELESS; /* For now */
    
    if (pico_ipv6_is_linklocal(addr)) {
        r.offset = IPV6_OFFSET_SRC;
        r.length = IPV6_LEN_SRC;
        iphc->sam = AM_COMPRESSED_FULL;
    } else {
        iphc->sam = AM_COMPRESSED_NONE;
    }
    
    return r;
}

static struct range sixlowpan_iphc_hl(struct sixlowpan_iphc *iphc, uint8_t hl)
{
    struct range r = {.offset = 0, .length = 0};
    _CHECK_PARAM(iphc, r);
    
    switch (hl) {
        case 1: iphc->hop_limit = HL_COMPRESSED_1; break;
        case 64: iphc->hop_limit = HL_COMPRESSED_64; break;
        case 255: iphc->hop_limit = HL_COMPRESSED_255; break;
        default:  iphc->hop_limit = HL_COMPRESSED_NONE; break;
    }
    
    if (iphc->hop_limit) {
        r.offset = IPV6_OFFSET_HL;
        r.length = IPV6_LEN_HL;
    }
    return r;
}

static struct range sixlowpan_iphc_nh(struct sixlowpan_iphc *iphc, uint8_t nh, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    
    _CHECK_PARAM(iphc, r);
    _CHECK_PARAM(f, r);
    
    /* See if the next header can be compressed */
    if (sixlowpan_nh_is_compressible(nh)) {
        iphc->next_header = NH_COMPRESSED;
        f->state = FRAME_COMPRESSIBLE_NH;
        r.offset = IPV6_OFFSET_NH;
        r.length = IPV6_LEN_NH;
    } else {
        iphc->next_header = NH_COMPRESSED_NONE;
        f->state = FRAME_COMPRESSED;
    }
    
    return r;
}

static struct range sixlowpan_iphc_pl(void)
{
    struct range r = {.offset = IPV6_OFFSET_LEN, .length = IPV6_LEN_LEN};
    return r;
}

static struct range sixlowpan_iphc_tf(struct sixlowpan_iphc *iphc, uint32_t *vtf)
{
    uint32_t dscp = 0, ecn = 0, fl = 0;
    struct range r = { 0, 0 };
    
    if (!iphc || !vtf) /* Checking params */
        return r;
    
    /* Get seperate values of the vtf-field */
    dscp = IPHC_DSCP(*vtf);
    ecn = IPHC_ECN(*vtf);
    fl = IPHC_FL(*vtf);
    
    if (!dscp && !ecn && !fl) {
        /* | vvvvvvvv | vvvvvvvv | vvvvvvvv | vvvvvvvv | */
        iphc->tf = TF_COMPRESSED_FULL;
    } else if (!dscp && (fl || ecn)) {
        /* [ EExxFFFF | FFFFFFFF | FFFFFFFF ] vvvvvvvv | */
        iphc->tf = TF_COMPRESSED_TC;
        *vtf = IPHC_ECN(*vtf) | IPHC_FLS(*vtf);
    } else if (!fl && (ecn || dscp))  {
        /* [ EEDDDDDD ] vvvvvvvv | vvvvvvvv | vvvvvvvv | */
        iphc->tf = TF_COMPRESSED_FL;
        *vtf = IPHC_ECN(*vtf) | IPHC_DSCP(*vtf);
    } else {
        /* [ EEDDDDDD | xxxxFFFF | FFFFFFFF | FFFFFFFF ] */
        iphc->tf = TF_COMPRESSED_NONE;
        *vtf = IPHC_ECN(*vtf) | IPHC_DSCP(*vtf) | IPHC_FL(*vtf);
    }
    
    return sixlowpan_iphc_tf_range(iphc->tf);
}

static void sixlowpan_iphc_compress(struct sixlowpan_frame *f)
{
    struct range deletions[IPV6_FIELDS_NUM];
    struct sixlowpan_iphc *iphc = NULL;
    struct pico_ipv6_hdr *hdr = NULL;
    uint8_t i = 0, nh = 0;
    CHECK_PARAM_VOID(f);
    
    /* Prepend IPHC header space */
    if (!(frame_buf_prepend(f, PICO_LAYER_NETWORK, DISPATCH_IPHC(INFO_HDR_LEN)))) {
        f->state = FRAME_ERROR;
        return;
    }
    
    /* Fill in IPHC header */
    hdr = (struct pico_ipv6_hdr *)(f->net_hdr + DISPATCH_IPHC(INFO_HDR_LEN));
    iphc = (struct sixlowpan_iphc *)(f->net_hdr);
    
    /* Temporarily store nxthdr for NHC in a moment */
    nh = hdr->nxthdr;
    iphc->dispatch = DISPATCH_IPHC(INFO_VAL);
    deletions[0] = sixlowpan_iphc_tf(iphc, &hdr->vtf);
    deletions[1] = sixlowpan_iphc_pl();
    deletions[2] = sixlowpan_iphc_nh(iphc, nh, f);
    deletions[3] = sixlowpan_iphc_hl(iphc, hdr->hop);
    deletions[4] = sixlowpan_iphc_sam(iphc, hdr->src.addr);
    deletions[5] = sixlowpan_iphc_dam(iphc, hdr->dst.addr);
    
    /* Try to apply Next Header compression */
    sixlowpan_nhc_compress(f, nh);
    
    /* Elide fields in IPv6 header */
    for (i = IPV6_FIELDS_NUM; i > 0; i--) {
        if (!frame_buf_delete(f, PICO_LAYER_NETWORK, deletions[i - 1], DISPATCH_IPHC(INFO_HDR_LEN))) {
            f->state = FRAME_ERROR;
            return;
        }
    }
    
    /* Check whether packet now fits inside the frame */
    if ((ieee_len(f) + sixlowpan_overhead(f) <= IEEE_MAC_MTU)) {
        f->state = FRAME_FITS_COMPRESSED;
    } else {
        f->state = FRAME_COMPRESSED;
    }
}

static void sixlowpan_uncompressed(struct sixlowpan_frame *f)
{
    CHECK_PARAM_VOID(f);
    
    /* Provide space for the dispatch type */
    if (!frame_buf_prepend(f, PICO_LAYER_NETWORK, DISPATCH_IPV6(INFO_HDR_LEN))) {
        f->state = FRAME_ERROR;
    } else {
        /* Insert the uncompressed IPv6 dispatch header */
        f->net_hdr[0] = DISPATCH_IPV6(INFO_VAL);
        f->state = FRAME_FITS;
    }
}

static void sixlowpan_compress(struct sixlowpan_frame *f)
{
    CHECK_PARAM_VOID(f);
    
    /* Check whether or not the frame actually needs compression */
    if ((ieee_len(f) + DISPATCH_IPV6(INFO_HDR_LEN) + sixlowpan_overhead(f)) <= IEEE_MAC_MTU) {
        sixlowpan_uncompressed(f);
    } else {
        sixlowpan_iphc_compress(f);
    }
}
/* -------------------------------------------------------------------------------- */
// MARK: DECOMPRESSION
static int sixlowpan_iphc_am_undo(enum iphc_am am, uint8_t id, struct pico_ieee_addr addr, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_ADDR_OFFSET(id), .length = IPV6_LEN_SRC};
    CHECK_PARAM(f);
    
    /* For now, the src-address is either fully elided or sent inline */
    if (AM_COMPRESSED_FULL == am) {
        /* Insert the Source Address-field again */
        if (!frame_buf_insert(f, PICO_LAYER_NETWORK, r))
            return -1;
        
        /* Derive the IPv6 Link Local source address from the IEEE802.15.4 src-address */
        if (sixlowpan_ipv6_derive_local(&addr, f->net_hdr + IPV6_ADDR_OFFSET(id)))
            return -1;
    } else {
        /* Nothing is needed, IPv6-address is fully carried in-line */
    }
    
    return 0;
}

static int sixlowpan_iphc_dam_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Check for multicast destination */
    if (MCAST_MULTICAST == iphc->mcast) {
        if (!(frame_buf_insert(f, PICO_LAYER_NETWORK, sixlowpan_iphc_mcast_range(iphc->dam))))
            return -1;
        /* Rearrange the mcast-address again to form a proper IPv6-address */
        hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        return sixlowpan_ipv6_derive_mcast(iphc->dam, hdr->dst.addr);
    } else {
        /* If destination address is not multicast it's, either not sent at all or
         * fully carried in-line */
        return sixlowpan_iphc_am_undo(iphc->dam, IPV6_DESTINATION, f->local, f);
    }
    
    return 0;
}

static int sixlowpan_iphc_sam_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    return sixlowpan_iphc_am_undo(iphc->sam, IPV6_SOURCE, f->peer, f);
}

static int sixlowpan_iphc_hl_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_OFFSET_HL, .length = IPV6_LEN_HL};
    struct pico_ipv6_hdr *hdr = NULL;
    
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Check whether or not the Hop Limit is compressed */
    if (iphc->hop_limit) {
        /* Insert the Hop Limit-field again */
        if (!frame_buf_insert(f, PICO_LAYER_NETWORK, r))
            return -1;
        
        /* Fill in the Hop Limit-field */
        hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        if (HL_COMPRESSED_1 == iphc->hop_limit) {
            hdr->hop = (uint8_t)1;
        } else if (HL_COMPRESSED_64 == iphc->hop_limit) {
            hdr->hop = (uint8_t)64;
        } else {
            hdr->hop = (uint8_t)255;
        } /* smt else isn't possible */
    }
    
    return 0;
}

static void sixlowpan_iphc_nh_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_OFFSET_NH, .length = IPV6_LEN_NH};
    
    CHECK_PARAM_VOID(iphc);
    CHECK_PARAM_VOID(f);
    
    /* Check if Next Header is compressed */
    if (iphc->next_header) {
        /* Insert the Next Header-field again */
        if (!frame_buf_insert(f, PICO_LAYER_NETWORK, r)) {
            f->state = FRAME_ERROR;
            return;
        }
        /* Will fill in the Next Header field later on, when the Next Header is actually
         * being decompressed, but indicate that it still needs to happen */
        f->state = FRAME_COMPRESSED_NHC;
    } else {
        f->state = FRAME_DECOMPRESSED;
    }
}

static int sixlowpan_iphc_pl_undo(struct sixlowpan_frame *f)
{
    CHECK_PARAM(f);
    /* Insert the payload-field again */
    if (!frame_buf_insert(f, PICO_LAYER_NETWORK, sixlowpan_iphc_pl()))
        return -1;
    return sixlowpan_iphc_pl_redo(f);
}

static int sixlowpan_iphc_tf_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    uint32_t *vtf = NULL;
    
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Insert the right amount of bytes so that the VTF-field is again 32-bits */
    if (!frame_buf_insert(f, PICO_LAYER_NETWORK, sixlowpan_iphc_tf_range(iphc->tf))) {
        f->state = FRAME_ERROR;
        return -1;
    }
    
    /* Reconstruct the original VTF-field */
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    vtf = &(hdr->vtf);
    switch (iphc->tf) {
        case TF_COMPRESSED_NONE:
            /* [ EEDDDDDD | xxxxFFFF | FFFFFFFF | FFFFFFFF ] */
            *vtf = long_be(IPV6_VERSION | IPV6_DSCP(*vtf) | IPV6_ECN(*vtf) | IPV6_FL(*vtf));
            break;
        case TF_COMPRESSED_TC:
            /* [ EExxFFFF | FFFFFFFF | FFFFFFFF ] vvvvvvvv | */
            *vtf = long_be(IPV6_VERSION | ~IPHC_MASK_DSCP | IPV6_ECN(*vtf) | IPV6_FLS(*vtf));
            break;
        case TF_COMPRESSED_FL:
            /* [ EEDDDDDD ] vvvvvvvv | vvvvvvvv | vvvvvvvv | */
            *vtf = long_be(IPV6_VERSION | IPV6_DSCP(*vtf) | IPV6_ECN(*vtf));
            break;
        case TF_COMPRESSED_FULL:
            /* | vvvvvvvv | vvvvvvvv | vvvvvvvv | vvvvvvvv | */
            *vtf = long_be(IPV6_VERSION);
            break;
        default:
            /* Not possible, bitfield of width: 2 */
            break;
    }
    
    return 0;
}

static void sixlowpan_decompress_iphc(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_IPHC(INFO_HDR_LEN)};
    struct sixlowpan_iphc iphc;
    CHECK_PARAM_VOID(f);
    
    /* Parse in the LOWPAN_IPHC-header and remove it */
    memcpy(&iphc, f->net_hdr, (size_t) DISPATCH_IPHC(INFO_HDR_LEN));
    frame_buf_delete(f, PICO_LAYER_NETWORK, r, 0);
    
    sixlowpan_iphc_tf_undo(&iphc, f);
    sixlowpan_iphc_pl_undo(f);
    sixlowpan_iphc_nh_undo(&iphc, f);
    sixlowpan_iphc_hl_undo(&iphc, f);
    sixlowpan_iphc_sam_undo(&iphc, f);
    sixlowpan_iphc_dam_undo(&iphc, f);
    
    /* If there isn't any Next Header compression we can assume the IPv6 Header is default
     * and therefore 40 bytes in size */
    if (FRAME_COMPRESSED_NHC == f->state) {
        sixlowpan_nhc_decompress(f);
    }
    
    /* The differentation isn't usefull anymore, make it a single buffer */
    f->net_len = (uint16_t)(f->net_len + f->transport_len);
    f->transport_len = (uint16_t)(0);
    
    /* Recalculate the Payload Length again because it changed since ..._pl_undo() */
    sixlowpan_iphc_pl_redo(f);
    
    /* Indicate decompression */
    f->state = FRAME_DECOMPRESSED;
}

static void sixlowpan_decompress_ipv6(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_IPV6(INFO_HDR_LEN)};
    CHECK_PARAM_VOID(f);
    frame_buf_delete(f, PICO_LAYER_NETWORK, r, 0);
    f->state = FRAME_DECOMPRESSED;
}

static void sixlowpan_decompress(struct sixlowpan_frame *f)
{
    uint8_t d = 0;
    CHECK_PARAM_VOID(f);
    
    if (FRAME_ERROR == f->state)
        return;
    
    /* Determine compression */
    d = f->net_hdr[0]; /* dispatch type */
    if (CHECK_DISPATCH(d, SIXLOWPAN_IPV6)) {
        sixlowpan_decompress_ipv6(f);
    } else if (CHECK_DISPATCH(d, SIXLOWPAN_IPHC)) {
        sixlowpan_decompress_iphc(f);
    } else {
        /* Dispatch is unknown, trigger discartion */
        f->state = FRAME_ERROR;
    }
}

/* -------------------------------------------------------------------------------- */
// MARK: FRAGMENTATION
static void sixlowpan_frame_frag(struct sixlowpan_frame *f)
{
    uint8_t max_psize = 0, comp = 0;
    uint16_t decompressed = 0, diff = 0;
    CHECK_PARAM_VOID(f);
    
    /* Determine how many bytes need to be transmitted to send the entire IPv6-payload */
    f->net_len = (uint16_t)(f->net_len + f->transport_len);
    f->transport_len = f->net_len;
    
    /* Determine how many bytes fits inside a single IEEE802.15.4-frame including 802.15.4-header and frag-header */
    max_psize = (uint8_t)(IEEE_MAC_MTU - f->link_hdr_len);
    max_psize = (uint8_t)(max_psize - sizeof(struct sixlowpan_fragn));
    max_psize = (uint8_t)(max_psize - sixlowpan_overhead(f));
    
    comp = (uint8_t)(f->dgram_size - f->net_len);
    decompressed = (uint16_t)(max_psize + comp);
    diff = (uint16_t)((decompressed / 8) * 8);
    f->max_bytes = (uint8_t)(diff - comp);
    
    /* Determine how many multiples of eight bytes fit inside that same amount of bytes determined a line above */
    f->state = FRAME_FRAGMENTED;
}

static int sixlowpan_fill_fragn(struct sixlowpan_fragn *hdr, struct sixlowpan_frame *f)
{
    uint16_t offset_bytes = 0;
    uint8_t diff = 0, offset_mul;
    
    hdr->dispatch_size = short_be(((uint16_t)DISPATCH_FRAGN(INFO_VAL)) << DISPATCH_FRAGN(INFO_SHIFT));
    hdr->dispatch_size = short_be((uint16_t)(hdr->dispatch_size | f->dgram_size));
    hdr->datagram_tag = short_be(dtag);
    
    /* Determine the offset in multiples of 8 bytes */
    diff = (uint8_t)(f->dgram_size - f->transport_len);
    offset_bytes = (uint16_t)((uint16_t)(f->transport_len - f->net_len) + (uint16_t)diff);
    offset_mul = (uint8_t)(offset_bytes / 8);
    hdr->offset = offset_mul;
    return 0;
}

static int sixlowpan_fill_frag1(struct sixlowpan_frag1 *hdr, struct sixlowpan_frame *f)
{
    CHECK_PARAM(hdr);
    CHECK_PARAM(f);
    hdr->dispatch_size = short_be(((uint16_t)DISPATCH_FRAG1(INFO_VAL)) << DISPATCH_FRAG1(INFO_SHIFT));
    hdr->dispatch_size = short_be((uint16_t)(hdr->dispatch_size | f->dgram_size));
    hdr->datagram_tag = short_be(++dtag);
    return 0;
}

static uint8_t *sixlowpan_frame_tx_next(struct sixlowpan_frame *f, uint8_t *len)
{
    struct range r = {.offset = 0, .length = 0};
    uint8_t frag_len = 0, dsize = 0, slp_offset;
    uint8_t *buf = NULL;
    
    CHECK_PARAM_NULL(f);
    CHECK_PARAM_NULL(len);
    
    if (0 == f->net_len)
        return NULL;

    if (f->transport_len == f->net_len) {
        /* First fragments isn't sent yet  */
        dsize = (uint8_t)sizeof(struct sixlowpan_frag1);
        frag_len = (uint8_t)(f->max_bytes + dsize);
    } else if (f->net_len < f->max_bytes) {
        /* Last fragment, the rest */
        dsize = (uint8_t)sizeof(struct sixlowpan_fragn);
        frag_len = (uint8_t)(f->net_len + dsize);
    } else {
        /* Subsequent fragment */
        dsize = (uint8_t)sizeof(struct sixlowpan_fragn);
        frag_len = (uint8_t)(((f->max_bytes / 8) * 8) + dsize);
    }
    
    /* Determine length of buffer */
    *len = (uint8_t)(f->link_hdr_len + (uint8_t)(frag_len + IEEE_PHY_OVERHEAD));
    if (!(buf = PICO_ZALLOC(*(size_t *)len))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    slp_offset = (uint8_t)(f->link_hdr_len + IEEE_LEN_LEN);
    
    /* Fill in the fragmentation header */
    if (f->transport_len == f->net_len) {
        sixlowpan_fill_frag1((struct sixlowpan_frag1 *)(buf + slp_offset), f);
    } else {
        sixlowpan_fill_fragn((struct sixlowpan_fragn *)(buf + slp_offset), f);
    }
    
    memcpy((uint8_t *)(buf + IEEE_LEN_LEN), f->link_hdr, (size_t)(f->link_hdr_len));
    memcpy((uint8_t *)(buf + slp_offset + dsize), f->net_hdr, (size_t)(frag_len - dsize));
    
    /* Remove the fragment from the frame */
    r.length = (uint16_t)(frag_len - dsize);
    frame_buf_delete(f, PICO_LAYER_NETWORK, r, 0);
    
    return buf;
}

// MARK: DEFRAGMENTATION
static int sixlowpan_frag_cmp(void *a, void *b)
{
    struct pico_ieee_addr *aa = NULL, *ab = NULL;
    struct sixlowpan_frame *fa = (struct sixlowpan_frame *)a, *fb = (struct sixlowpan_frame *)b;
    int ret = 0;
    
    if (!a || !b) {
        pico_err = PICO_ERR_EINVAL;
        PAN_ERR("Invalid arguments for comparison!\n");
        return -1;
    }
    
    /* 1.) Compare IEEE802.15.4 addresses of the sender */
    aa = (struct pico_ieee_addr *)&fa->peer;
    ab = (struct pico_ieee_addr *)&fb->peer;
    if ((ret = ieee_addr_cmp((void *)aa, (void *)ab)))
        return ret;
    
    /* 2.) Compare IEEE802.15.4 addresses of the destination */
    aa = (struct pico_ieee_addr *)&fa->local;
    ab = (struct pico_ieee_addr *)&fb->local;
    if ((ret = ieee_addr_cmp((void *)aa, (void *)ab)))
        return ret;
    
    /* 3.) Compare datagram_size */
    if (fa->dgram_size != fb->dgram_size)
        return (int)((int)fa->dgram_size - (int)fb->dgram_size);
    
    /* 4.) Compare datagram_tag */
    if (fa->dgram_tag != fb->dgram_tag)
        return (int)((int)fa->dgram_tag - (int)fb->dgram_tag);
    
    return 0;
}
PICO_TREE_DECLARE(Frags, &sixlowpan_frag_cmp);

static uint16_t sixlowpan_defrag_prep(struct sixlowpan_frame *f)
{
    struct range r = { 0, 0 };
    uint16_t offset = 0; /* frag_offset in bytes */
    int first = 0;
    
    /* Determine the offset of the fragment */
    if (!(first = CHECK_DISPATCH(f->net_hdr[0], SIXLOWPAN_FRAG1)))
        offset = (uint16_t)(((struct sixlowpan_fragn *)f->net_hdr)->offset * 8);
    
    /* Determine the size of the IP-packet before LL compression/fragmentation */
    f->dgram_size = short_be(((struct sixlowpan_frag1 *)f->net_hdr)->dispatch_size) & FRAG_DGRAM_SIZE_MASK;
    f->dgram_tag = short_be((uint16_t)(((struct sixlowpan_frag1 *)f->net_hdr)->datagram_tag));
    
    /* Delete the fragmentation header from the buffer */
    r.length = (first) ? (DISPATCH_FRAG1(INFO_HDR_LEN)) : (DISPATCH_FRAGN(INFO_HDR_LEN));
    if (!frame_buf_delete(f, PICO_LAYER_NETWORK, r, 0)) {
        f->state = FRAME_ERROR;
        return 0;
    }
    
    /* Try to decompress the received frame */
    if (first)
        sixlowpan_decompress(f);
    return offset;
}

static int sixlowpan_defrag_init(struct sixlowpan_frame *f, uint16_t offset)
{
    struct sixlowpan_frame *reassembly = NULL;
    CHECK_PARAM(f);
    
    /* Provide a reassembly-frame */
    if (!(reassembly = (struct sixlowpan_frame *)PICO_ZALLOC(sizeof(struct sixlowpan_frame)))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    
    /* [ PHY | ~~LINK~~ | ~~PAYLOAD~~ | PHY ] <- size */
    reassembly->size = (uint16_t)(IEEE_PHY_OVERHEAD + f->link_hdr_len + f->dgram_size);
    reassembly->link_hdr_len = f->link_hdr_len;
    reassembly->net_len = f->dgram_size;
    reassembly->transport_len = 0;
    reassembly->dgram_size = f->dgram_size;
    reassembly->dgram_tag = f->dgram_tag;
    reassembly->dev = f->dev;
    reassembly->local = f->local;
    reassembly->peer = f->peer;
    reassembly->state = f->state;
    
    /* Provide the buffer in the reassembly-frame */
    if (!(reassembly->phy_hdr = PICO_ZALLOC(reassembly->size))) {
        pico_err = PICO_ERR_ENOMEM;
        PICO_FREE(reassembly);
        return -1;
    }
    frame_rearrange_ptrs(reassembly);
    
    /* Copy in the buffer fields from the received frame */
    memmove(reassembly->phy_hdr, f->phy_hdr, IEEE_LEN_LEN);
    memmove(reassembly->link_hdr, f->link_hdr, f->link_hdr_len);
    memmove(reassembly->net_hdr + offset, f->net_hdr, f->net_len);
    
    /* How many bytes there still need to be puzzled */
    reassembly->transport_len = (uint16_t)(reassembly->dgram_size - f->net_len);
    
    if (pico_tree_insert(&Frags, reassembly)) {
        PAN_ERR("Inserting reassembly-buffer in frag-tree.\n");
        PICO_FREE(reassembly->phy_hdr);
        PICO_FREE(reassembly);
        return -1;
    }
    
    /* TODO: start timeout-timer */
    
    return 0;
}

static struct sixlowpan_frame *sixlowpan_defrag_puzzle(struct sixlowpan_frame *f)
{
    struct sixlowpan_frame *reassembly = NULL, *ret = NULL;
    uint16_t offset = 0;
    
    CHECK_PARAM_NULL(f);
    
    offset = sixlowpan_defrag_prep(f);
    if (FRAME_ERROR == f->state) {
        PAN_ERR("Preparing frame for defragging.\n");
        f->state = FRAME_ERROR;
        return f;
    }
    
    /* Check whether or not there is defragmentation already going on */
    reassembly = pico_tree_findKey(&Frags, f);
    if (!reassembly) {
        if (sixlowpan_defrag_init(f, offset)) {
            PAN_ERR("Defrag initialisation!\n");
            f->state = FRAME_ERROR;
            return f;
        }
    } else {
        /* Copy received frame in place */
        memmove((void *)(reassembly->net_hdr + offset), f->net_hdr, f->net_len);
        reassembly->transport_len = (uint16_t)(reassembly->transport_len - f->net_len);
        
        /* Check if the IPv6 frame is completely defragged */
        if (0 == reassembly->transport_len) {
            ret = reassembly;
            if (!pico_tree_delete(&Frags, reassembly))
                PAN_ERR("Reassembly frame not in the tree, could not delete.\n");
            /* Don't delete reassembly, it will be returned */
            ret->state = FRAME_DEFRAGMENTED;
            sixlowpan_iphc_pl_redo(reassembly);
        }
    }
    
    /* Everything went okay, destroy fragment */
    sixlowpan_frame_destroy(f);
    return ret; /* Returns either NULL, or defragged frame */
}

static struct sixlowpan_frame *sixlowpan_defrag(struct sixlowpan_frame *f)
{
    CHECK_PARAM_NULL(f);
    
    /* Check for LOWPAN_FRAGx dispatch header */
    if (CHECK_DISPATCH(f->net_hdr[0], SIXLOWPAN_FRAG1) || CHECK_DISPATCH(f->net_hdr[0], SIXLOWPAN_FRAGN))
        f = sixlowpan_defrag_puzzle(f);
    
    return f;
}

/* -------------------------------------------------------------------------------- */
// MARK: BROADCASTING
static void sixlowpan_retransmit(struct sixlowpan_frame *f)
{
    struct pico_device_sixlowpan *slp = NULL;
    slp = (struct pico_device_sixlowpan *)f->dev;
    slp->radio->transmit(slp->radio, f->phy_hdr, f->size);
}

static uint8_t *sixlowpan_broadcast_out(uint8_t *buf, uint8_t *len, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_BC0(INFO_HDR_LEN)};
    struct sixlowpan_bc0 *bc = NULL;
    struct ieee_hdr *hdr = NULL;
    uint8_t *old = buf;
    
    r.offset = (uint16_t)(IEEE_LEN_LEN + f->link_hdr_len);
    if (IEEE_ADDR_IS_BCAST(f->hop)) {
        buf = buf_insert(buf, *len, r);
        if (!buf) {
            PICO_FREE(old);
            return NULL;
        }
        /* Make sure the length is updated after a memory-insert */
        *len = (uint8_t)(*len + DISPATCH_BC0(INFO_HDR_LEN));
        
        /* Set some params of the bcast header */
        bc = (struct sixlowpan_bc0 *)(buf + r.offset);
        bc->dispatch = DISPATCH_BC0(INFO_VAL);
        bc->seq = ++bcast_seq;
        
        /* Save broadcast information for duplicate broadcast suppression in the future */
        hdr = (struct ieee_hdr *)(buf + IEEE_LEN_LEN);
        if (IEEE_AM_SHORT == hdr->fcf.sam) {
            last_bcast_short = pico_ieee_addr_short_from_flat((uint8_t *)(hdr->addresses + pico_ieee_addr_len(hdr->fcf.dam)), IEEE_TRUE);
        } else {
            last_bcast_ext = pico_ieee_addr_ext_from_flat((uint8_t *)(hdr->addresses + pico_ieee_addr_len(hdr->fcf.dam)), IEEE_TRUE);
        }
    } else {
        /* Next hop isn't broadcast, no LOWPAN_BC0 header needed */
    }
    
    return buf;
}

/* -------------------------------------------------------------------------------- */
// MARK: MESH ADDRESSING
static inline enum ieee_am sixlowpan_mesh_am_get(uint8_t dah, uint8_t origin)
{
    uint8_t am = 0;
    
    if (origin)
        am = (uint8_t)((dah >> 5) & 0x1);
    else
        am = (uint8_t)((dah >> 4) & 0x1);
        
    if (am)
        return IEEE_AM_SHORT;
    return IEEE_AM_EXTENDED;
}

static inline uint8_t sixlowpan_mesh_am(struct pico_ieee_addr *addr, uint8_t origin)
{
    if (IEEE_AM_EXTENDED == addr->_mode)
        return 0;
    
    return ((origin) ? ((uint8_t)((uint8_t)1 << 5)) : ((uint8_t)((uint8_t)1 << 4)));
}

static void sixlowpan_update_addr(struct sixlowpan_frame *f, uint8_t src)
{
    struct range r = {.offset = IEEE_MIN_HDR_LEN, .length = 0};
    uint8_t len = 0, cur_len = 0, offset = 0, del = 0;
    struct pico_ieee_addr *addr = NULL;
    
    addr = (src) ? (struct pico_ieee_addr *)f->dev->eth : &f->hop;
    
    /* Determine the length of both src addresses */
    len = pico_ieee_addr_len(addr->_mode);
    cur_len = (src) ? pico_ieee_addr_len(f->link_hdr->fcf.sam) : pico_ieee_addr_len(f->link_hdr->fcf.dam);
    
    /* Determine the offset where to insert or copy memory */
    offset = (src) ? pico_ieee_addr_len(f->link_hdr->fcf.dam) : (0u);
    
    if (cur_len > len) {
        r.length = (uint16_t)(cur_len - len);
        del = 1;
    } else if (cur_len < len) {
        r.length = (uint16_t)(len - cur_len);
        del = 0;
    }
    
    if (r.length)
        frame_buf_edit(f, PICO_LAYER_DATALINK, r, offset, del);
    
    if (src)
        f->link_hdr->fcf.sam = IEEE_AM_BOTH_TO_SHORT(addr->_mode);
    else
        f->link_hdr->fcf.dam = IEEE_AM_BOTH_TO_SHORT(addr->_mode);
    
    /* Copy in the SRC-address */
    if (pico_ieee_addr_to_flat(f->link_hdr->addresses + offset, *addr, IEEE_TRUE)) {
        PAN_ERR("Error occured while updating address\n");
    }
}

static uint8_t sixlowpan_mesh_read_hdr_info(uint8_t *buf, struct pico_ieee_addr *origin, struct pico_ieee_addr *final)
{
    struct sixlowpan_mesh_esc *esc = NULL;
    struct sixlowpan_mesh *hdr = NULL;
    enum ieee_am dam = 0, sam = 0;
    uint8_t *addresses = NULL;
    uint8_t hops_left = 0;
    int escaped = 0;
    
    /* Parse in normal MESH header */
    hdr = (struct sixlowpan_mesh *)buf;
    escaped = (MESH_DAH_HOP_LIMIT(hdr->dah) == MESH_HL_ESC);
    
    sam = sixlowpan_mesh_am_get(hdr->dah, 1);
    dam = sixlowpan_mesh_am_get(hdr->dah, 0);
    
    /* If Hop Limit is escaped */
    if (escaped) {
        /* Set the addresses-pointer 1 byte further */
        esc = (struct sixlowpan_mesh_esc *)hdr;
        addresses = (uint8_t *)(esc->addresses);
        hops_left = esc->hl;
    } else {
        /* Set the addresses-pointer normally */
        addresses = (uint8_t *)(hdr->addresses);
        hops_left = MESH_DAH_HOP_LIMIT(hdr->dah);
    }
    
    *origin = pico_ieee_addr_from_flat(addresses, sam, IEEE_FALSE);
    *final = pico_ieee_addr_from_flat(addresses + pico_ieee_addr_len(sam), dam, IEEE_FALSE);
    
    return hops_left;
}

static uint8_t *sixlowpan_update_hl(uint8_t *buf, struct sixlowpan_frame *f)
{
    int escaped = (f->hop_limit >= MESH_HL_ESC);
    struct sixlowpan_mesh_esc *esc = (struct sixlowpan_mesh_esc *)buf;
    struct sixlowpan_mesh *hdr = (struct sixlowpan_mesh *)buf;
    
    if (escaped) {
        /* Escaped hop limit */
        hdr->dah = (uint8_t)(hdr->dah | MESH_HL_ESC);
        esc->hl = f->hop_limit;
        return esc->addresses;
    } else {
        /* Set normal hop limit */
        hdr->dah = (uint8_t)(hdr->dah | f->hop_limit);
        return hdr->addresses;
    }
}

static void sixlowpan_mesh_fill_hdr_info(uint8_t *buf, struct sixlowpan_frame *f)
{
    struct sixlowpan_mesh_esc *hdr = NULL;
    uint8_t *addresses = NULL;
    
    /* Fill in fixed location fields */
    hdr = (struct sixlowpan_mesh_esc *)buf;
    hdr->dah = (uint8_t)(DISPATCH_MESH(INFO_VAL) << DISPATCH_MESH(INFO_SHIFT));
    hdr->dah = (uint8_t)(hdr->dah | sixlowpan_mesh_am(&f->peer, 0));
    hdr->dah = (uint8_t)(hdr->dah | sixlowpan_mesh_am(&f->local, 1));
    
    /* Fill in the Hop Limit and determine addresses offset */
    addresses = sixlowpan_update_hl(buf, f);
    
    /* Set the MESH origin and final address */
    pico_ieee_addr_to_flat(addresses, f->local, IEEE_FALSE);
    pico_ieee_addr_to_flat(addresses + pico_ieee_addr_len(f->local._mode), f->peer, IEEE_FALSE);
}

static int sixlowpan_is_duplicate(struct pico_ieee_addr src)
{
    if (IEEE_AM_SHORT == src._mode && (src._short.addr == last_bcast_short.addr)) {
        return 1;
    } else if (IEEE_AM_EXTENDED == src._mode && (0 == memcmp(last_bcast_ext.addr, src._ext.addr, PICO_SIZE_IEEE_EXT))) {
        return 1;
    } else {
        /* Either the mode is not recognized or the frame is not a duplicate */
        return 0;
    }
}

static int sixlowpan_broadcast_in(struct sixlowpan_frame *f, uint8_t offset)
{
    struct sixlowpan_bc0 *bc = NULL;
    
    /* Check if the same frame isn't broadcasted before */
    bc = (struct sixlowpan_bc0 *)(f->net_hdr + offset);
//    PAN_DBG("SEQ: (%d) ORI: (0x%04X) LAST SEQ: (%d) LAST ORI: (0x%04X)\n", bc->seq, f->peer._short.addr, bcast_seq, last_bcast_src._short.addr);
    if (((bc->seq <= bcast_seq) && sixlowpan_is_duplicate(f->peer))) {
        /* Discard frame at once */
        return 1;
    } else {
        /* Update source address and hop limit for forwarding */
        sixlowpan_update_addr(f, SIXLOWPAN_SRC);
        sixlowpan_update_hl(f->net_hdr, f);
        
        /* Keep the last origin address for duplicate suppression in the future */
        if (f->peer._mode == IEEE_AM_SHORT)
            last_bcast_short = f->peer._short;
        else
            last_bcast_ext = f->peer._ext;
        
        bcast_seq = bc->seq;
    }
    
    /* Frame isn't broadcasted before, rebroadcast it */
    sixlowpan_retransmit(f);
    return 0;
}

static struct sixlowpan_frame *sixlowpan_mesh_discard(struct sixlowpan_frame *f)
{
    sixlowpan_frame_destroy(f);
    return NULL;
}

static struct sixlowpan_frame *sixlowpan_mesh_retransmit(struct sixlowpan_frame *f, uint8_t bcast_offset)
{
    if (!IEEE_ADDR_IS_BCAST(f->hop)) {
        /* I'm last hop, and it needs forwarding, determine Next Hop */
        f->peer = f->local;
        f->hop = sixlowpan_determine_next_hop(f);
        
        /* If frame is not ready for transmission, postpone */
        if (!sixlowpan_frame_ready(f)) {
            sixlowpan_frame_postpone(f, SIXLOWPAN_FORWARDING);
            return NULL;
        }
        
        /* Set the hop of the frame to the next hop */
        sixlowpan_update_addr(f, SIXLOWPAN_DST);
        sixlowpan_update_addr(f, SIXLOWPAN_SRC);
        sixlowpan_update_hl(f->net_hdr, f);
        sixlowpan_retransmit(f);
    } else {
        /* Frame is send to LL-BCAST but not destined for me, apply duplicate BCAST-suppress. */
        sixlowpan_broadcast_in(f, bcast_offset);
    }
    
    sixlowpan_frame_destroy(f);
    return NULL;
}

static struct sixlowpan_frame *sixlowpan_mesh_in(struct sixlowpan_frame *f)
{
    struct pico_ieee_addr origin, final, dst;
    struct range r = {.offset = 0, .length = 0};
    int dead_ttl = 0;
    CHECK_PARAM_NULL(f);
    
    if (CHECK_DISPATCH(f->net_hdr[0], SIXLOWPAN_MESH)) {
        /* Read the information contained in the MESH header and decrement Hops Left at once */
        f->hop_limit = (uint8_t)(sixlowpan_mesh_read_hdr_info(f->net_hdr, &origin, &final) - 1);
        dead_ttl = (!f->hop_limit);
        
        /* Calculate the range in order to delete the MESH header in a moment */
        r.length = f->hop_limit >= MESH_HL_ESC ? (uint16_t)(DISPATCH_MESH(INFO_HDR_LEN) + 1) : DISPATCH_MESH(INFO_HDR_LEN);
        r.length = (uint16_t)(r.length + (uint8_t)(pico_ieee_addr_len(origin._mode) + pico_ieee_addr_len(final._mode)));
        
        /* Add information to L2 routing table with current peer address, since at this moment,
         * it still contains the address of the last hop */
        f->hop = pico_ieee_addr_from_hdr(f->link_hdr, SIXLOWPAN_SRC);
        
        sixlowpan_build_routing_table(origin, f->peer, f->dev);
        
        /* After routing table determination, update the peer-address to the mesh origin and the last hop to LL-src */
        f->peer = origin;
        f->local = final;
        dst = pico_ieee_addr_from_hdr(f->link_hdr, SIXLOWPAN_DST);
        
        if (!ieee_addr_cmp((void *)&final, (void *)f->dev->eth)) {
            /* Frame is destined for me and only for me, consume... */
        } else if (IEEE_ADDR_IS_BCAST(final)) {
            /* Check if the hop limit isn't 0 and then if the broadcasting occured again */
            if (dead_ttl || sixlowpan_broadcast_in(f, (uint8_t)r.length))
                return sixlowpan_mesh_discard(f); /* Let the frame be discarded */
            
            r.length = (uint16_t)(r.length + DISPATCH_BC0(INFO_HDR_LEN));
        } else {
            /* If the TTL is zero or I'm the originator don't bother forwarding, discard at once */
            if (dead_ttl)
                return sixlowpan_mesh_discard(f);
            
            /* Frame is not destined for me, forward onto the network */
            f->hop = dst;
            return sixlowpan_mesh_retransmit(f, (uint8_t)r.length);
        }
    }
    
    if (!frame_buf_delete(f, PICO_LAYER_NETWORK, r, 0)) {
        f->state = FRAME_ERROR;
        return sixlowpan_mesh_discard(f);
    }
    
    if (sixlowpan_ping_recv(f)) {
        return sixlowpan_mesh_discard(f);
    }
    
    /* Indicate that the frame needs further consumation */
    return f;
}

static uint8_t *sixlowpan_mesh_out(uint8_t *buf, uint8_t *len, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    uint8_t *old = buf;
    
    /* Calculate the range to insert into the buffer */
    r.offset = (uint16_t)(IEEE_LEN_LEN + f->link_hdr_len);
    r.length = (f->hop_limit >= MESH_HL_ESC) ? ((uint16_t)DISPATCH_MESH(INFO_HDR_LEN) + 1) : (uint16_t)(DISPATCH_MESH(INFO_HDR_LEN));
    r.length = (uint16_t)(r.length + pico_ieee_addr_len(f->local._mode) + pico_ieee_addr_len(f->peer._mode));
    
    /* Always mesh route */
    buf = buf_insert(buf, (uint16_t)*len, r);
    if (!buf) {
        PICO_FREE(old);
        return NULL;
    }
    *len = (uint8_t)(*len + (uint16_t)r.length);
    
    sixlowpan_mesh_fill_hdr_info(buf + r.offset, f);
    
    /* Set the link destination address */
    if (pico_ieee_addr_to_flat(((struct ieee_hdr *)(buf + IEEE_LEN_LEN))->addresses, f->hop, IEEE_TRUE))
        PAN_ERR("Addr to flat failed in MESH OUT: (%d)\n", *len);
    
    return buf;
}

static int sixlowpan_derive_origin(struct pico_frame *f, struct pico_ieee_addr *origin)
{
    struct pico_ipv6_hdr *hdr = NULL;
    CHECK_PARAM(f);
    CHECK_PARAM(origin);
    
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    
    if (pico_ipv6_is_unspecified(hdr->src.addr)) {
        *origin = *(struct pico_ieee_addr *)f->dev->eth;
        return 0;
    } else {
        return ieee_addr_from_iid(origin, (uint8_t *)(hdr->src.addr + 8));
    }
}

/* -------------------------------------------------------------------------------- */
// MARK: TRANSLATING
/* Translates a pico_frame to 6LoWPAN frame */
static struct sixlowpan_frame *sixlowpan_frame_translate(struct pico_frame *f)
{
    struct sixlowpan_frame *frame = NULL;
    struct pico_ieee_addr origin = IEEE_ADDR_ZERO;
    struct pico_ieee_addr final = IEEE_ADDR_ZERO;
    
    CHECK_PARAM_NULL(f);
    
     /* Determine link layer origin and final addresses */
    if (sixlowpan_derive_origin(f, &origin)) {
        PAN_ERR("Failed deriving origin from IPv6 source address\n");
        return NULL;
    }
    
    if (sixlowpan_determine_final_dst(f, &final) < 0) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        pico_ipv6_nd_postpone(f);
        return NULL;
    }
    
    /* Try to provide a 6LoWPAN-frame instance */
    frame = sixlowpan_frame_create(origin, final, f->net_len, (uint16_t)(f->len - f->net_len), SIXLOWPAN_DEFAULT_TTL, f->dev);
    if (!frame) {
        PAN_ERR("Failed creating 6LoWPAN-frame\n");
        return NULL;
    }
    
    /* Next Hop determination */
    frame->hop = sixlowpan_determine_next_hop(frame);
    
    /* Copy in payload-data from the pico_frame */
    memcpy(frame->net_hdr, f->net_hdr, f->net_len);
    memcpy(frame->transport_hdr, f->transport_hdr, f->transport_len);
    
    return frame;
}

/* -------------------------------------------------------------------------------- */
// MARK: PICO_DEV
static int sixlowpan_send_exit(int ret)
{
    sixlowpan_state = SIXLOWPAN_READY;
    sixlowpan_frame_destroy(tx);
    tx = NULL;
    return ret;
}

static int sixlowpan_send_tx()
{
    struct pico_device_sixlowpan *slp = NULL;
    uint8_t *buf = NULL;
    uint8_t len = 0;
    int ret = 0;
    
    if (SIXLOWPAN_TRANSMITTING != sixlowpan_state)
        return 0;
    
    CHECK_PARAM(tx);
    
    /* Check whether the fragment is fragmented */
    if (FRAME_FRAGMENTED == tx->state)
        buf = sixlowpan_frame_tx_next(tx, &len); /* Next fragment of current frame */
    else
        buf = sixlowpan_frame_to_buf(tx, &len); /* Current frame as a whole */
    
    if (buf) {
        if (!(buf = sixlowpan_broadcast_out(buf, &len, tx))) {
            PAN_ERR("During broadcast out\n");
            return sixlowpan_send_exit(-1);
        }
        
        if (!(buf = sixlowpan_mesh_out(buf, &len, tx))) {
            PAN_ERR("During mesh addressing\n");
            return sixlowpan_send_exit(-1);
        }
        
        slp = (struct pico_device_sixlowpan *)tx->dev;
        ret = slp->radio->transmit(slp->radio, buf, len);
        PICO_FREE(buf);
        if (FRAME_FRAGMENTED == tx->state)
            return ret;
    } else {
        /* Entire frame is either sent or something went wrong, we don't care, in
         * either case, tx can be discarded */
    }
    
    return sixlowpan_send_exit(ret);
}

static int sixlowpan_schedule(void)
{
    sixlowpan_state = SIXLOWPAN_TRANSMITTING;
    return sixlowpan_send_tx();
}

static int sixlowpan_prep_tx_exit(int ret)
{
    sixlowpan_state = SIXLOWPAN_READY;
    sixlowpan_frame_destroy(tx);
    tx = NULL;
    return ret;
}

static int sixlowpan_prep_tx(void)
{
    /* Try to compress the 6LoWPAN-frame */
    sixlowpan_compress(tx);
    if (FRAME_COMPRESSED == tx->state) {
        /* Try to fragment the entire compressed frame */
        sixlowpan_frame_frag(tx);
    } else if (FRAME_FITS == tx->state || FRAME_FITS_COMPRESSED == tx->state) {
        /* Nothing to do, frame is ready for transmitting */
    } else {
        PAN_ERR("Unkown frame state (%d).\n", tx->state);
        return sixlowpan_prep_tx_exit(-1);
    }
    
    if (FRAME_ERROR == tx->state) {
        PAN_ERR("Failed fragmenting 6LoWPAN-frame\n");
        return sixlowpan_prep_tx_exit(-1);
    }
    
    return sixlowpan_schedule();
}

static int sixlowpan_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_frame *f = (struct pico_frame *)buf;
    
    /* While transmitting no frames can be passed to the 6LoWPAN-device */
    if (SIXLOWPAN_TRANSMITTING == sixlowpan_state || SIXLOWPAN_PREPARING == sixlowpan_state)
        return 0;
    
    CHECK_PARAM(dev);
    CHECK_PARAM(buf);
    IGNORE_PARAMETER(len);
    
    /* Translate the pico_frame */
    sixlowpan_state = SIXLOWPAN_PREPARING;
    if (!(tx = sixlowpan_frame_translate(f))) {
        PAN_ERR("Failed translating pico_frame\n");
        sixlowpan_state = SIXLOWPAN_READY;
        tx = NULL;
        return -1;
    }
    
    if (sixlowpan_frame_ready(tx)) {
        return sixlowpan_prep_tx();
    } else {
        return sixlowpan_frame_postpone(tx, SIXLOWPAN_TRANSMIT);
    }
}

static int sixlowpan_defragged_handle(struct sixlowpan_frame *f)
{
    if (FRAME_DEFRAGMENTED == f->state)
        return 0; /* IPv6-datagram is completely defragged, do nothing */
    
    /* Try apply decompression/defragmentation if the frame was not degrafmented */
    sixlowpan_decompress(f);
    if (FRAME_ERROR == f->state) {
        sixlowpan_frame_destroy(f);
        return -1;
    }
    return 0;
}

static int sixlowpan_poll(struct pico_device *dev, int loop_score)
{
    /* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *) dev;
    struct ieee_radio *radio = sixlowpan->radio;
    struct sixlowpan_frame *f = NULL;
    uint8_t buf[IEEE_PHY_MTU];
    uint8_t len = 0;
    
    do {
        len = radio->receive(radio, buf, IEEE_PHY_MTU);
        if (len > 0) {
            /* Decapsulate IEEE802.15.4 MAC frame to 6LoWPAN-frame */
            if (!(f = sixlowpan_buf_to_frame(buf, len, dev)))
                return loop_score;
            
            /* Check for MESH Dispatch header */
            if (!(f = sixlowpan_mesh_in(f))) {
                /* Frame is forwared and destroyed or rtx has it and is postponed */
                continue;
            }
            
            /* Defrag, if NULL, everthing OK, but I'm still waiting for some other packets */
            if (!(f = sixlowpan_defrag(f)))
                continue;
            else if (sixlowpan_defragged_handle(f))
                return -1;
            else { /* Frame is ready to be handled by upper layers */ }
            
            /* Hand over the received frame to pico */
            pico_stack_recv(dev, f->net_hdr, (uint32_t)(f->net_len));
            sixlowpan_frame_destroy(f);
            --loop_score;
        } else
            break;
    } while (loop_score > 0);
    
    /* Can I do something else? */
    sixlowpan_send_tx(); /* Yes you can, send current frame */
    return loop_score;
}

/* -------------------------------------------------------------------------------- */
// MARK: API
int pico_ieee_addr_to_hdr(struct ieee_hdr *hdr, struct pico_ieee_addr src, struct pico_ieee_addr dst)
{
    CHECK_PARAM(hdr);
    
    /* Set the addressing modes */
    if (pico_ieee_addr_modes_to_hdr(hdr, src._mode, dst._mode)) {
        PAN_ERR("Failed filling in the addressing modes in the IEEE802.14.4 Frame Control Field\n");
        return -1;
    }
    
    /* Fill in the destination address */
    if (pico_ieee_addr_to_flat((uint8_t *)hdr->addresses, dst, IEEE_TRUE)) {
        PAN_ERR("Failed filling in destination address in IEEE802.15.4 MAC header\n");
        return -1;
    }
    
    /* fIll in the source address */
    if (pico_ieee_addr_to_flat((uint8_t *)(hdr->addresses + pico_ieee_addr_len(dst._mode)), src, IEEE_TRUE)) {
        PAN_ERR("Failed filling in source address in IEEE802.15.4 MAC header\n");
        return -1;
    }
    
    return 0;
}

struct pico_ieee_addr pico_ieee_addr_from_hdr(struct ieee_hdr *hdr, uint8_t src)
{
    if (src) {
        return pico_ieee_addr_from_flat((uint8_t *)(hdr->addresses + pico_ieee_addr_len(hdr->fcf.dam)), hdr->fcf.sam, IEEE_TRUE);
    } else {
        return pico_ieee_addr_from_flat((uint8_t *)hdr->addresses, hdr->fcf.dam, IEEE_TRUE);
    }
}

int pico_sixlowpan_set_prefix(struct pico_device *dev, struct pico_ip6 prefix)
{
    CHECK_PARAM(dev);
    if (!pico_ipv6_link_add_sixlowpan(dev, prefix))
        return -1;
    return 0;
}

void pico_sixlowpan_short_addr_configured(struct pico_device *dev)
{
    struct pico_ieee_addr *slp_addr = NULL;
    struct pico_device_sixlowpan *slp = NULL;
    
    CHECK_PARAM_VOID(dev);
    
    /* Parse the pico_device structure to the internal sixlowpan-structure */
    slp = (struct pico_device_sixlowpan *) dev;
    slp_addr = (struct pico_ieee_addr *)dev->eth;
    
    if (LL_MODE_SIXLOWPAN == dev->mode) {
        /**
         *  Set the short-address of the device. A check whether or not
         *  the device already had a short-address is not needed. I assume
         *  the device-driver has priority of configuring addresses and assume
         *  it takes this into account.
         */
        slp_addr->_short.addr = slp->radio->get_addr_short(slp->radio);
        
        /* Set the address mode accordingly */
        if (IEEE_ADDR_BCAST_SHORT != slp_addr->_short.addr) {
            if (IEEE_AM_EXTENDED == slp_addr->_mode)
                slp_addr->_mode = IEEE_AM_BOTH;
            else
                slp_addr->_mode = IEEE_AM_SHORT;
        }
    }
}

int pico_sixlowpan_enable_6lbr(struct pico_device *dev, struct pico_ip6 prefix)
{
    struct pico_device_sixlowpan *slp = NULL;
    int ret = 0;
    CHECK_PARAM(dev);

    /* Enable IPv6 routing on the device's interface */
    if (pico_ipv6_dev_routing_enable(dev))
        return -1;
    
    /* Make sure the 6LBR router has short address 0x0000 */
    slp = (struct pico_device_sixlowpan *)dev;
    if (0 != (ret = slp->radio->set_addr_short(slp->radio, 0x0000)))
        return ret;
    
    /* Configure prefix for the device */
    return pico_sixlowpan_set_prefix(dev, prefix);
}

struct pico_device *pico_sixlowpan_create(struct ieee_radio *radio)
{
    struct pico_device_sixlowpan *sixlowpan = NULL;
    char dev_name[MAX_DEVICE_NAME];
    struct pico_ieee_addr slp;
    CHECK_PARAM_NULL(radio);
    
    if (!(sixlowpan = PICO_ZALLOC(sizeof(struct pico_device_sixlowpan))))
        return NULL;
    
    /* Generate pico_ieee_addr for the pico_device, extended address by default */
    radio->get_addr_ext(radio, slp._ext.addr);
    slp._mode = IEEE_AM_EXTENDED;
    
    /* Get the short address if the device already has one */
    slp._short.addr = radio->get_addr_short(radio);
    if (IEEE_ADDR_BCAST_SHORT != slp._short.addr)
        slp._mode = IEEE_AM_BOTH;
    
    /* Try to init & register the device to picoTCP */
    snprintf(dev_name, MAX_DEVICE_NAME, "sixlowpan%04d", sixlowpan_devnum++);
    
    /* Set the mode of the pico_device to 6LoWPAN instead of Ethernet by default */
    sixlowpan->dev.mode = LL_MODE_SIXLOWPAN;
    
    if (0 != pico_device_init((struct pico_device *)sixlowpan, dev_name, (uint8_t *)&slp)) {
        dbg("Device init failed.\n");
        return NULL;
    }
    
    /* Set the device-parameters */
    sixlowpan->dev.overhead = 0;
    sixlowpan->dev.send = sixlowpan_send;
    sixlowpan->dev.poll = sixlowpan_poll;
    
    /* Assign the radio-instance to the pico_device-instance */
    sixlowpan->radio = radio;
    
    /* Cast internal 6LoWPAN-structure to picoTCP-device structure */
    PAN_DBG("Device %s created\n", dev_name);
    return (struct pico_device *)sixlowpan;
}
#endif /* PICO_SUPPORT_SIXLOWPAN */
