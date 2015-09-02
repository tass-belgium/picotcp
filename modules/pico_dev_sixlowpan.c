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
    #define PAN_DBG(s, ...)         dbg("[SIXLOWPAN]$ " s, ##__VA_ARGS__)
    #define PAN_ERR(s, ...)         dbg("[SIXLOWPAN]$ ERROR: %s: %d: " s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define PAN_WARNING(s, ...)     dbg("[SIXLOWPAN]$ WARNING: %s: %d: " s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define PAN_DBG_C               dbg
#else
    #define PAN_DBG(...)            do {} while(0)
    #define PAN_DBG_C(...)          do {} while(0)
    #define PAN_WARNING(...)        do {} while(0)
    #define PAN_ERR(...)            do {} while(0)
#endif

#define UNUSED __attribute__((unused))

#define IEEE802154_MIN_HDR_LEN      (5u)
#define IEEE802154_LEN_LEN          (1u)
#define IEEE802154_BCST_ADDR        (0xFFFFu)

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

#define INFO_VAL        (0u)
#define INFO_SHIFT      (1u)
#define INFO_HDR_LEN    (2u)
#define DISPATCH_NALP(i)            ((i) == INFO_VAL ? (0x00u) : ((i) == INFO_SHIFT ? (0x06u) : (0x00u)))
#define DISPATCH_IPV6(i)            ((i) == INFO_VAL ? (0x41u) : ((i) == INFO_SHIFT ? (0x00u) : (0x01u)))
#define DISPATCH_HC1(i)             ((i) == INFO_VAL ? (0x42u) : ((i) == INFO_SHIFT ? (0x00u) : (0x02u)))
#define DISPATCH_BC0(i)             ((i) == INFO_VAL ? (0x50u) : ((i) == INFO_SHIFT ? (0x00u) : (0x02u)))
#define DISPATCH_ESC(i)             ((i) == INFO_VAL ? (0x7Fu) : ((i) == INFO_SHIFT ? (0x00u) : (0xFFu)))
#define DISPATCH_MESH(i)            ((i) == INFO_VAL ? (0x02u) : ((i) == INFO_SHIFT ? (0x06u) : (0xFFu)))
#define DISPATCH_FRAG1(i)           ((i) == INFO_VAL ? (0x18u) : ((i) == INFO_SHIFT ? (0x03u) : (0x04u)))
#define DISPATCH_FRAGN(i)           ((i) == INFO_VAL ? (0x1Cu) : ((i) == INFO_SHIFT ? (0x03u) : (0x05u)))
#define DISPATCH_NESC(i)            ((i) == INFO_VAL ? (0x80u) : ((i) == INFO_SHIFT ? (0x00u) : (0xFFu)))
#define DISPATCH_IPHC(i)            ((i) == INFO_VAL ? (0x03u) : ((i) == INFO_SHIFT ? (0x05u) : (0x02u)))
#define DISPATCH_NHC_EXT(i)         ((i) == INFO_VAL ? (0x0Eu) : ((i) == INFO_SHIFT ? (0x04u) : (0x01u)))
#define DISPATCH_NHC_UDP(i)         ((i) == INFO_VAL ? (0x1Eu) : ((i) == INFO_SHIFT ? (0x03u) : (0x01u)))
#define SIXLOWPAN_NALP              DISPATCH_NALP
#define SIXLOWPAN_IPV6              DISPATCH_IPV6
#define SIXLOWPAN_HC1               DISPATCH_HC1
#define SIXLOPWAN_BC0               DISPATCH_BC0
#define SIXLOWPAN_ESC               DISPATCH_ESC
#define SIXLOWPAN_MESH              DISPATCH_MESH
#define SIXLOWPAN_FRAG1             DISPATCH_FRAG1
#define SIXLOWPAN_FRAGN             DISPATCH_FRAGN
#define SIXLOWPAN_NESC              DISPATCH_NESC
#define SIXLOWPAN_IPHC              DISPATCH_IPHC
#define SIXLOWPAN_NHC_EXT           DISPATCH_NHC_EXT
#define SIXLOWPAN_NHC_UDP           DISPATCH_NHC_UDP
#define CHECK_DISPATCH(d, type)     (((d) >> type(INFO_SHIFT)) == type(INFO_VAL))

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
#define MEM_INSERT(buf, len, range) (buf) = buf_insert((buf),(uint16_t)(len),(range))
#define MEM_DELETE(buf, len, range) (len) = (uint16_t)buf_delete((buf),(uint16_t)(len),(range))

/* -------------------------------------------------------------------------------- */
// MARK: 6LoWPAN types

enum sixlowpan_state
{
    SIXLOWPAN_NREADY = -1,
    SIXLOWPAN_READY,
    SIXLOWPAN_TRANSMITTING
};

enum endian_mode
{
    ENDIAN_IEEE802154 = 0,
    ENDIAN_SIXLOWPAN
};

/**
 *  Definition of 6LoWPAN pico_device
 */
struct pico_device_sixlowpan
{
	struct pico_device dev;
	
	/* Interface between pico_device-structure & 802.15.4-device driver */
	radio_t *radio;
    
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
    IEEE802154_hdr_t *link_hdr;
    uint8_t link_hdr_len;
    
    /* IPv6 header buffer */
    uint8_t *net_hdr;
    uint16_t net_len;
    
    /* Transport layer buffer */
    uint8_t *transport_hdr;
    uint16_t transport_len;
    
    uint8_t max_bytes;
    uint16_t to_send;
    
    /* To which IPv6 datagram the frame belongs to */
    uint16_t dgram_size;
    uint16_t dgram_tag;
    
    /* Next Header field */
    uint8_t nxthdr;
    
    enum frame_status state;

    /* Pointer to 6LoWPAN-device instance */
    struct pico_device *dev;
    
    /**
     *  Link layer address of the peer, either the
     *  destination address when sending or the source
     *  address when receiving.
     */
    struct pico_sixlowpan_addr peer;
    
    /**
     *  Link layer address of the local host, only
     *  has a meaning when sending frames.
     */
    struct pico_sixlowpan_addr local;
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
}; /* Traffic class / Flow label*/

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
 *  Information-type containing frame and 6LoWPAN-device
 *  MARK: LOWPAN_FRAG types
 */
PACKED_STRUCT_DEF sixlowpan_frag1
{
    uint8_t size0: 3;
    uint8_t dispatch: 5;
    uint8_t size1;
    uint16_t datagram_tag;
}; /* 6LoWPAN first fragmentation header */

PACKED_STRUCT_DEF sixlowpan_fragn
{
    uint8_t size0: 3;
    uint8_t dispatch: 5;
    uint8_t size1;
    uint16_t datagram_tag;
    uint8_t offset;
}; /* 6LoWPAN following fragmentation header */

struct stream_info
{
    struct sixlowpan_frame *f;
    struct pico_device_sixlowpan *dev;
};

#define SET_FRAG_SIZE(frag, size) \
        frag->size0 = (uint8_t)short_be(short_be(size) >> 0x8); \
        frag->size1 = (uint8_t)size

#define GET_FRAG_SIZE(frag_hdr) (uint16_t)((uint16_t)(frag_hdr)->size1 | (((uint16_t)(frag_hdr)->size0) << 0x08));

/**
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
static struct sixlowpan_frame *cur_frame = NULL;
static uint16_t sixlowpan_devnum = 0;

/* -------------------------------------------------------------------------------- */
// MARK: DEBUG
#ifdef DEBUG
static void UNUSED dbg_ipv6(const char *pre, struct pico_ip6 *ip)
{
    uint8_t i = 0;
    
    PAN_DBG("%s", pre);
    for (i = 0; i < 16; i = (uint8_t)(i + 2)) {
        PAN_DBG_C("%02x%02x", ip->addr[i], ip->addr[i + 1]);
        if (i != 14)
            PAN_DBG_C(":");
    }
    PAN_DBG_C("\n");
}

static void UNUSED dbg_mem(const char *pre, void *buf, uint16_t len)
{
    uint16_t i = 0, j = 0;
    
    /* Print in factors of 8 */
    PAN_DBG("%s\n", pre);
    for (i = 0; i < (len / 8); i++) {
        PAN_DBG("%03d. ", i * 8);
        for (j = 0; j < 8; j++) {
            PAN_DBG_C("%02X ", ((uint8_t *)buf)[j + (i * 8)] );
            if (j == 3)
                PAN_DBG_C(" ");
        }
        PAN_DBG_C("\n");
    }
    
    if (!(len % 8))
        return;
    
    /* Print the rest */
    PAN_DBG("%03d. ", i * 8);
    for (j = 0; j < (len % 8); j++) {
        PAN_DBG_C("%02X ", ((uint8_t *)buf)[j + (i * 8)] );
        if (j == 3)
            PAN_DBG_C(" ");
    }
    PAN_DBG_C("\n");
}
#endif

/* -------------------------------------------------------------------------------- */
// MARK: MEMORY
static uint16_t buf_delete(void *buf, uint16_t len, struct range r)
{
    uint16_t rend = (uint16_t)(r.offset + r.length);
    
    CHECK_PARAM_ZERO(buf);
    
    /* OOB Check */
    if (!rend || rend > len || r.offset > len)
        return len;
    
    /* Replace the deleted chunk at the offset by the data after the end of the deleted chunk */
    memmove(buf + r.offset, buf + rend, (size_t)(len - rend));
    
    /* Return the new length */
    return (uint16_t)(len - r.length);
}

static void *buf_insert(void *buf, uint16_t len, struct range r)
{
    uint16_t rend = (uint16_t)(r.offset + r.length);
    void *new = NULL;
    
    CHECK_PARAM_NULL(buf);
    
    /* OOB Check */
    if (!rend || r.offset > len || rend > len)
        return buf;
    
    /* OOM Check */
    if (!(new = PICO_ZALLOC((size_t)(len + r.length))))
        return buf;
    
    /* Assemble buffer again */
    memmove(new, buf, (size_t)r.offset);
    memmove(new + r.offset + r.length, buf + r.offset, (size_t)(len - r.offset));
    memset(new + r.offset, 0x00, r.length);
    
    PICO_FREE(buf); /* Give back previous buffer to the system */
    
    return new;
}

static inline void FRAME_REARRANGE_PTRS(struct sixlowpan_frame *f)
{
    CHECK_PARAM_VOID(f);
    
    f->link_hdr = (IEEE802154_hdr_t *)(f->phy_hdr + IEEE802154_LEN_LEN);
    f->net_hdr = ((uint8_t *)f->link_hdr) + f->link_hdr_len;
    f->transport_hdr = f->net_hdr + f->net_len;
}

static uint8_t *FRAME_BUF_EDIT(struct sixlowpan_frame *f, enum pico_layer l, struct range r, uint16_t offset, uint8_t del)
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
        MEM_DELETE(f->phy_hdr, f->size, r);
    } else {
        if (!(MEM_INSERT(f->phy_hdr, f->size, r)))
            return NULL;
        
        /* Set the new buffer size */
        f->size = (uint16_t)(f->size + r.length);
    }
    /* Rearrange chunk-ptrs */
    FRAME_REARRANGE_PTRS(f);
    return (uint8_t *)(f->phy_hdr + r.offset);
}

static uint8_t *FRAME_BUF_INSERT(struct sixlowpan_frame *f, enum pico_layer l, struct range r)
{
    return FRAME_BUF_EDIT(f, l, r, 0, 0);
}

static uint8_t *FRAME_BUF_PREPEND(struct sixlowpan_frame *f, enum pico_layer l, uint16_t len)
{
    struct range r = {.offset = 0, .length = len};
    return FRAME_BUF_INSERT(f, l, r);
}

static uint8_t *FRAME_BUF_DELETE(struct sixlowpan_frame *f,  enum pico_layer l, struct range r, uint16_t offset)
{
    return FRAME_BUF_EDIT(f, l, r, offset, 1);
}

/* -------------------------------------------------------------------------------- */
// MARK: IEEE802.15.4

inline static void IEEE802154_EUI64_LE(uint8_t EUI64[8])
{
    uint8_t i = 0, temp = 0;
    CHECK_PARAM_VOID(EUI64);
    
    for (i = 0; i < 4; i++) {
        temp = EUI64[i];
        EUI64[i] = EUI64[8 - (i + 1)];
        EUI64[8 - (i + 1)] = temp;
    }
}

inline static uint8_t IEEE802154_ADDR_LEN(IEEE802154_address_mode_t am)
{
    uint8_t len = 0;
    switch (am) {
        case IEEE802154_ADDRESS_MODE_BOTH:
            /* intentional fall through */
        case IEEE802154_ADDRESS_MODE_SHORT:
            len = 2;
            break;
        case IEEE802154_ADDRESS_MODE_EXTENDED:
            len = 8;
            break;
        default:
            len = 0;
            break;
    }
    return len;
}

inline static uint8_t IEEE802154_hdr_len(struct sixlowpan_frame *f)
{
    CHECK_PARAM_ZERO(f);
    
    f->link_hdr_len = (uint8_t)(IEEE802154_MIN_HDR_LEN +
                                IEEE802154_ADDR_LEN(f->peer._mode) +
                                IEEE802154_ADDR_LEN(f->local._mode));
    
    /* Add Auxiliary Security Header in the future */
    
    return f->link_hdr_len;
}

inline static uint8_t IEEE802154_len(struct sixlowpan_frame *f)
{
    CHECK_PARAM_ZERO(f);
    
    f->size = (uint16_t)(IEEE802154_hdr_len(f) + (uint16_t)(f->net_len + (uint16_t)(f->transport_len + 3u)));
    
    return (uint8_t)(f->size);
}

inline static uint8_t IEEE802154_hdr_buf_len(IEEE802154_hdr_t *hdr)
{
    return (uint8_t)(IEEE802154_MIN_HDR_LEN + (uint8_t)(IEEE802154_ADDR_LEN(hdr->fcf.sam) + IEEE802154_ADDR_LEN(hdr->fcf.dam)));
}

static void IEEE802154_process_address(uint8_t *buf, struct pico_sixlowpan_addr *addr, IEEE802154_address_mode_t am)
{
    if (am == IEEE802154_ADDRESS_MODE_SHORT) {
        addr->_short.addr = (uint16_t)((((uint16_t)buf[0]) << 8) | (uint16_t)buf[1]);
        addr->_mode = IEEE802154_ADDRESS_MODE_SHORT;
    } else if (am == IEEE802154_ADDRESS_MODE_EXTENDED) {
        memcpy(addr->_ext.addr, buf, PICO_SIZE_SIXLOWPAN_EXT);
        addr->_mode = IEEE802154_ADDRESS_MODE_EXTENDED;
        IEEE802154_EUI64_LE(addr->_ext.addr);
    } else {
        addr->_mode = IEEE802154_ADDRESS_MODE_NONE;
    }
}

static void IEEE802154_process_addresses(IEEE802154_hdr_t *hdr, struct pico_sixlowpan_addr *dst, struct pico_sixlowpan_addr *src)
{
    CHECK_PARAM_VOID(hdr);
    CHECK_PARAM_VOID(dst);
    CHECK_PARAM_VOID(src);
    
    /* Process SRC and DST adresses seperately*/
    IEEE802154_process_address(hdr->addresses, dst, hdr->fcf.dam);
    IEEE802154_process_address(hdr->addresses + IEEE802154_ADDR_LEN(hdr->fcf.dam), src, hdr->fcf.sam);
}

static struct sixlowpan_frame *IEEE802154_unbuf(struct pico_device *dev, uint8_t *buf, uint8_t len)
{
    struct sixlowpan_frame *f = NULL;
    
    CHECK_PARAM_NULL(buf);
    
    /* Provide space for the sixlowpan_frame */
    if (!(f = PICO_ZALLOC(sizeof(struct sixlowpan_frame)))) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    /* Provide space for the buffer inside the sixlowpan-frame and copy */
    f->size = (uint16_t)(len + 1); /* + 1 to take into account length byte */
    if (!(f->phy_hdr = PICO_ZALLOC((size_t)f->size))) {
        pico_err = PICO_ERR_EINVAL;
        PICO_FREE(f);
        return NULL;
    }
    memcpy(f->phy_hdr, buf, len);
    
    /* Parse in IEEE802.15.4-header */
    f->link_hdr = (IEEE802154_hdr_t *)(f->phy_hdr + IEEE802154_LEN_LEN);
    f->link_hdr_len = IEEE802154_hdr_buf_len(f->link_hdr);
    
    /* Parse in IPv6-header */
    f->net_hdr = (uint8_t *)(((uint8_t *)f->link_hdr) + f->link_hdr_len);
    f->net_len = (uint16_t)(f->size - IEEE802154_PHY_OVERHEAD - f->link_hdr_len);
    
    /* Set the device */
    f->dev = dev;
    
    /* Init state */
    f->state = FRAME_COMPRESSED;
    
    /* Process the addresses-fields seperately */
    IEEE802154_process_addresses(f->link_hdr, &(f->local), &(f->peer));

    return f;
}

/* -------------------------------------------------------------------------------- */
// MARK: SIXLOWPAN

/* -------------------------------------------------------------------------------- */
// MARK: FRAGMENTATION
static int sixlowpan_addr_cmp(struct pico_sixlowpan_addr *a, struct pico_sixlowpan_addr *b)
{
    int ret = 0;
    
    if (!a || !b) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    if (a->_mode || b->_mode)
        return (int)((int)a->_mode - (int)b->_mode);
    
    if (a->_mode == IEEE802154_ADDRESS_MODE_EXTENDED) {
        ret = memcmp(a->_ext.addr, b->_ext.addr, PICO_SIZE_SIXLOWPAN_EXT);
    } else {
        ret = memcmp(&a->_short.addr, &b->_short.addr, PICO_SIZE_SIXLOWPAN_SHORT);
    }
    
    return ret;
}

static int sixlowpan_frag_cmp(void *a, void *b)
{
    struct pico_sixlowpan_addr *aa = NULL, *ab = NULL;
    struct sixlowpan_frame *fa = NULL, *fb = NULL;
    int ret = 0;
    
    if (!a || !b) {
        pico_err = PICO_ERR_EINVAL;
        PAN_ERR("Invalid arguments for comparison!\n");
        return -1;
    }
    
    /* Parse in the frames */
    fa = (struct sixlowpan_frame *)a;
    fb = (struct sixlowpan_frame *)b;
    
    /* 1.) Compare IEEE802.15.4 addresses of the sender */
    aa = (struct pico_sixlowpan_addr *)&fa->peer;
    ab = (struct pico_sixlowpan_addr *)&fb->peer;
    if ((ret = sixlowpan_addr_cmp(aa, ab)))
        return ret;
    
    /* 2.) Compare IEEE802.15.4 addresses of the destination */
    aa = (struct pico_sixlowpan_addr *)&fa->local;
    ab = (struct pico_sixlowpan_addr *)&fb->local;
    if ((ret = sixlowpan_addr_cmp(aa, ab)))
        return ret;
    
    /* 3.) Compare datagram_size */
    if (fa->dgram_size != fb->dgram_size)
        return (int)((int)fa->dgram_size - (int)fb->dgram_size);
    
    /* 4.) Compare datagram_tag */
    if (fa->dgram_tag != fb->dgram_tag)
        return (int)((int)fa->dgram_tag - (int)fb->dgram_tag);
    
    return 0;
}

static uint16_t pico_tree_count(struct pico_tree *t)
{
    struct pico_tree_node *node = NULL;
    uint16_t count = 0;
    
    pico_tree_foreach(node, t) {
        count++;
    }
    return count;
}

PICO_TREE_DECLARE(Frags, &sixlowpan_frag_cmp);

/* -------------------------------------------------------------------------------- */
// MARK: FRAMING
/**
 *  Destroys 6LoWPAN-frame
 *
 *  @param f struct pico_frame, frame instance to destroy
 */
static void sixlowpan_frame_destroy(struct sixlowpan_frame *f)
{
    if (!f)
        return;
    
    if (f->phy_hdr)
        PICO_FREE(f->phy_hdr);
    
    PICO_FREE(f);
}

/* -------------------------------------------------------------------------------- */
// MARK: FLAT (ADDRESSES)
/**
 *  Copies a 6LoWPAN address to a flat buffer space.
 *
 *  @param d      void *, destination-pointer to buffer to copy address to.
 *                Needs to be big enough to store the entire address, defined by
 *                addr.mode. If addr.mode is IEEE802154_ADDRESS_MODE_BOTH, the short-
 *                address will be copied in.
 *  @param addr   struct pico_sixlowpan_addr, address to copy.
 *  @param offset uint8_t, offset to add to 'd' for where to copy the address.
 *  @param mode
 *
 *  @return 0 When copying went OK, smt. else when it didn't.
 */
static int sixlowpan_addr_copy_flat(void *d,
                                    struct pico_sixlowpan_addr addr,
                                    uint8_t offset,
                                    enum endian_mode e)
{
    CHECK_PARAM(d);
    
    if (addr._mode == IEEE802154_ADDRESS_MODE_SHORT ||
        addr._mode == IEEE802154_ADDRESS_MODE_BOTH) {
        memcpy(d + offset, &addr._short.addr, PICO_SIZE_SIXLOWPAN_SHORT);
    } else if (addr._mode == IEEE802154_ADDRESS_MODE_EXTENDED) {
        memcpy(d + offset, addr._ext.addr, PICO_SIZE_SIXLOWPAN_EXT);
        if (ENDIAN_IEEE802154 == e) /* Convert to Small Endian */
            IEEE802154_EUI64_LE(d + offset);
    } else {
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------------- */
// MARK: IIDs (ADDRESSES)
inline static int sixlowpan_iid_is_derived_16(uint8_t in[8])
{
    return ((in[3] == 0xFF && in[4] == 0xFE) ? 1 : 0);
}

inline static int sixlowpan_iid_from_extended(struct pico_sixlowpan_addr_ext addr, uint8_t out[8])
{
    CHECK_PARAM(out);
    memcpy(out, addr.addr, PICO_SIZE_SIXLOWPAN_EXT);
    out[0] = (uint8_t)(out[0] & (uint8_t)(~0x02)); /* Set the U/L to local */
    return 0;
}

inline static int sixlowpan_iid_from_short(struct pico_sixlowpan_addr_short addr, uint8_t out[8])
{
    uint16_t s = short_be(addr.addr);
    uint8_t buf[8] = {0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00};
    CHECK_PARAM(out);
    buf[6] = (uint8_t)((s >> 8) & 0xFF);
    buf[7] = (uint8_t)(s & 0xFF);
    memcpy(out, buf, 8);
    return 0;
}

static int sixlowpan_addr_from_iid(struct pico_sixlowpan_addr *addr, uint8_t in[8])
{
    CHECK_PARAM(addr);
    CHECK_PARAM(in);
    if (sixlowpan_iid_is_derived_16(in)) {
        addr->_mode = IEEE802154_ADDRESS_MODE_SHORT;
        memcpy(&addr->_short.addr, in + 6, PICO_SIZE_SIXLOWPAN_SHORT);
        addr->_short.addr = short_be(addr->_short.addr); /* Memcpy is endian-dependent */
    } else {
        addr->_mode = IEEE802154_ADDRESS_MODE_EXTENDED;
        memcpy(addr->_ext.addr, in, PICO_SIZE_SIXLOWPAN_EXT);
        in[0] = (uint8_t)(in[0] ^ 0x02); /* Set the U/L to unique */
    }
    return 0;
}

/* -------------------------------------------------------------------------------- */
// MARK: 6LoWPAN to IPv6 (ADDRESSES)

static int sixlowpan_ipv6_derive_local(struct pico_sixlowpan_addr *addr,
                                       uint8_t ip[PICO_SIZE_IP6])
{
    struct pico_ip6 linklocal = {{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    int ret = 0;
    
    CHECK_PARAM(addr);
    CHECK_PARAM(ip);
    
    if (addr->_mode == IEEE802154_ADDRESS_MODE_SHORT || addr->_mode == IEEE802154_ADDRESS_MODE_BOTH) {
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

/**
 *  Derive a 6LoWPAN link layer address from an IPv6-address.
 *
 *  @param l  struct pico_sixlowpan_addr *, gets filled with the derived addr.
 *  @param ip struct pico_ip6 *, contains the IPv6-address.
 *
 *  @return 0 on succes, smt. else otherwise.
 */
static int sixlowpan_ll_derive_local(struct pico_sixlowpan_addr *l,
                                     struct pico_ip6 *ip)
{
    CHECK_PARAM(ip);
    CHECK_PARAM(l);
    
    sixlowpan_addr_from_iid(l, ip->addr + 8);
    
    return 0;
}

/**
 *  Derive a 6LoWPAN mcast link layer address from a mcast IPv6 address
 *
 *  @param l  pico_sixlowpan_addr *, gets filled with multicast link addr.
 *  @param ip struct pico_ip6 *, contains the multicast IPv6-address.
 *
 *  @return 0 when derivation was a success, smt. else when it was not.
 */
inline static int sixlowpan_ll_derive_mcast(struct pico_sixlowpan_addr *l,
                                            struct pico_ip6 *ip)
{
    /* For now, ignore IP */
    IGNORE_PARAMETER(ip);
    CHECK_PARAM(l);
    
    /*  RFC: IPv6 level multicast packets MUST be carried as link-layer broadcast
     *  frame in IEEE802.15.4 networks. */
    l->_mode = IEEE802154_ADDRESS_MODE_SHORT;
    l->_short.addr = IEEE802154_BCST_ADDR;
    
    return 0;
}

/**
 *  Use 6LoWPAN Neighbor Discovery to determine the destination's link
 *  layer address.
 *
 *  @param f struct pico_frame *, to send to destination address
 *  @param l struct pico_sixlowpan_addr *, gets filled with discovered link addr.
 *
 *  @return 0 on succes, smt. else otherwise
 */
static int sixlowpan_ll_derive_nd(struct pico_frame *f,
                                  struct pico_sixlowpan_addr *l)
{
    struct pico_sixlowpan_addr *neighbor = NULL;
    CHECK_PARAM(f);
    CHECK_PARAM(l);
    
    /* Discover neighbor link address using 6LoWPAN ND for dst address */
    if ((neighbor = pico_ipv6_get_sixlowpan_neighbor(f))) {
        memcpy(l, neighbor, sizeof(struct pico_sixlowpan_addr));
        return 0;
    }
    
    return -1;
}

/* -------------------------------------------------------------------------------- */
// MARK: COMPRESSION
/* -------------------------------------------------------------------------------- */
// MARK: LOWPAN_NHC
inline static int sixlowpan_nh_is_compressible(uint8_t nh)
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

static void sixlowpan_nhc_udp_ports_undo(enum nhc_udp_ports ports, struct sixlowpan_frame *f)
{
    struct pico_udp_hdr *hdr = NULL;
    uint16_t sport = 0xF000, dport = 0xF000;
    uint8_t *buf = NULL;
    
    CHECK_PARAM_VOID(f);
    
    buf = (uint8_t *)(f->transport_hdr);
    hdr = (struct pico_udp_hdr *)f->transport_hdr;
    
    switch (ports) {
        case PORTS_COMPRESSED_FULL:
            sport = (uint16_t)(sport | 0x00B0 | (uint16_t)(buf[0] >> 4));
            dport = (uint16_t)(dport | 0x00B0 | (uint16_t)(buf[0] & 0x0F));
            FRAME_BUF_PREPEND(f, PICO_LAYER_TRANSPORT, 3);
            break;
        case PORTS_COMPRESSED_DST:
            sport = short_be(*(uint16_t *)(buf));
            dport = (uint16_t)(dport | (uint16_t)buf[2]);
            FRAME_BUF_PREPEND(f, PICO_LAYER_TRANSPORT, 1);
            break;
        case PORTS_COMPRESSED_SRC:
            sport = (uint16_t)(sport | (uint16_t)buf[0]);
            dport = short_be(*(uint16_t *)(buf + 1));
            FRAME_BUF_PREPEND(f, PICO_LAYER_TRANSPORT, 1);
            break;
        default:
            /* Do nothing */
            return;
    }
    hdr->trans.sport = sport;
    hdr->trans.dport = dport;
}

inline static enum nhc_udp_ports sixlowpan_nhc_udp_ports(uint16_t src, uint16_t dst, uint32_t *comp)
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

static uint8_t sixlowpan_nhc_udp_undo(struct sixlowpan_nhc_udp *udp, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_NHC_UDP(INFO_HDR_LEN)};
    struct pico_ipv6_hdr *hdr = NULL;
    uint16_t *len = NULL;
    enum nhc_udp_ports ports = PORTS_COMPRESSED_NONE;
    
    _CHECK_PARAM(udp, 0xFF);
    _CHECK_PARAM(f, 0xFF);
    
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    ports = udp->ports;
    FRAME_BUF_DELETE(f, PICO_LAYER_TRANSPORT, r, 0);
    
    /* UDP is in the transport layer */
    if (ports) {
        sixlowpan_nhc_udp_ports_undo(ports, f);
    }
    
    r.offset = 4;
    r.length = 2;
    len = (uint16_t *)FRAME_BUF_INSERT(f, PICO_LAYER_TRANSPORT , r);
    *len = hdr->len;
    
    return PICO_PROTO_UDP;
}

static void sixlowpan_nhc_udp(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    struct pico_udp_hdr *udp = NULL;
    struct sixlowpan_nhc_udp *nhc = NULL;
    
    CHECK_PARAM_VOID(f);
    
    if (!FRAME_BUF_PREPEND(f, PICO_LAYER_TRANSPORT, DISPATCH_NHC_UDP(INFO_HDR_LEN))) {
        f->state = FRAME_ERROR;
        return;
    }
    
    /* Parse in the UDP header */
    udp = (struct pico_udp_hdr *)(f->transport_hdr + 1);
    nhc = (struct sixlowpan_nhc_udp *)f->transport_hdr;
    
    nhc->dispatch = DISPATCH_NHC_UDP(INFO_VAL);
    nhc->ports = sixlowpan_nhc_udp_ports(udp->trans.sport, udp->trans.dport, (uint32_t *)udp);
    /* For now, don't compress the checksum because we have to have the authority of the upper layers */
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
    FRAME_BUF_DELETE(f, PICO_LAYER_TRANSPORT, r, DISPATCH_NHC_UDP(INFO_HDR_LEN));
    
    f->state = FRAME_COMPRESSED_NHC;
}

inline static uint8_t sixlowpan_nh_from_eid(enum nhc_ext_eid eid)
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
            FRAME_BUF_DELETE(f, PICO_LAYER_NETWORK, r, 0);
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
        FRAME_REARRANGE_PTRS(f);
        return sixlowpan_nhc_udp_undo((struct sixlowpan_nhc_udp *)f->transport_hdr, f);
    } else {
        /* Shouldn't be possible */
        return 0xFF;
    }
}

static void sixlowpan_nhc_ext(enum nhc_ext_eid eid, uint8_t **buf, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    struct pico_ipv6_exthdr *ext = NULL;
    struct sixlowpan_nhc_ext *nhc = NULL;
    
    CHECK_PARAM_VOID(f);
    CHECK_PARAM_VOID(buf);
    CHECK_PARAM_VOID(*buf);
    
    /* *ALWAYS* prepend some space for the LOWPAN_NHC header */
    r.offset = (uint16_t)(*buf - f->net_hdr);
    r.length = DISPATCH_NHC_EXT(INFO_HDR_LEN);
    if (!(*buf = FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, r))) {
        f->state = FRAME_ERROR;
        return;
    }
    
    /* Rearrange the pointers */
    ext = (struct pico_ipv6_exthdr *)(*buf + DISPATCH_NHC_EXT(INFO_HDR_LEN));
    nhc = (struct sixlowpan_nhc_ext *)*buf;
    f->nxthdr = ext->nxthdr;
    
    /* Set the dispatch of the LOWPAN_NHC header */
    nhc->dispatch = DISPATCH_NHC_EXT(INFO_VAL);
    nhc->eid = eid; /* Extension IDentifier */
    
    /* Determine if the next header is compressible */
    if (sixlowpan_nh_is_compressible(f->nxthdr)) {
        /* Next header is compressible */
        f->state = FRAME_COMPRESSIBLE_NH;
        nhc->nh = NH_COMPRESSED;
        
        /* Next header is compressed, sent as part of the LOWPAN_NHC header so can be elicited. */
        r.offset = (uint16_t)((uint16_t)(*buf - f->net_hdr) + DISPATCH_NHC_EXT(INFO_HDR_LEN));
        r.length = IPV6_EXT_LEN_NXTHDR;
        if (!FRAME_BUF_DELETE(f, PICO_LAYER_NETWORK, r, 0)) {
            f->state = FRAME_ERROR;
            return;
        }
    } else {
        /* The frame is compressed following LOWPAN_NHC */
        f->state = FRAME_COMPRESSED_NHC;
        nhc->nh = NH_COMPRESSED_NONE;
        
        /* Next header field is transmitted in-line */
    }
    
    /* Set the pointer to the next sheader */
    if (EID_FRAGMENT != eid)
        *buf = ((uint8_t *)*buf) + IPV6_OPTLEN(ext->ext.destopt.len);
    else
        *buf = ((uint8_t *)*buf) + 8u;
}

static void sixlowpan_nhc_decompress(struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    union nhc_hdr *nhc = NULL;
    uint8_t d = 0;
    
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    nhc = (union nhc_hdr *)f->net_hdr + PICO_SIZE_IP6HDR;
    d = *(uint8_t *)(nhc);
    
    /* Set size temporarily of the net_hdr */
    f->net_len = PICO_SIZE_IP6HDR;
    FRAME_REARRANGE_PTRS(f);
    
    if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_EXT)) {
        hdr->nxthdr = sixlowpan_nhc_ext_undo((struct sixlowpan_nhc_ext *)nhc, f);
    } else if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_UDP)) {
        hdr->nxthdr = sixlowpan_nhc_udp_undo((struct sixlowpan_nhc_udp *)f->transport_hdr, f);
    } else {
        f->state = FRAME_ERROR;
        return;
    }
    
    f->state = FRAME_DECOMPRESSED;
}

static void sixlowpan_nhc(struct sixlowpan_frame *f, uint8_t **buf)
{
    /* Check which type of next header we heave to deal with */
    switch (f->nxthdr) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
            sixlowpan_nhc_ext(EID_HOPBYHOP, buf, f);
            break;
        case PICO_IPV6_EXTHDR_ROUTING:
            sixlowpan_nhc_ext(EID_ROUTING, buf, f);
            break;
        case PICO_IPV6_EXTHDR_FRAG:
            sixlowpan_nhc_ext(EID_FRAGMENT, buf, f);
            break;
        case PICO_IPV6_EXTHDR_DESTOPT:
            sixlowpan_nhc_ext(EID_DESTOPT, buf, f);
            break;
        case PICO_PROTO_UDP:
            sixlowpan_nhc_udp(f); /* Will always in the transport layer so we can just pass the frame */
            break;
        default:
            f->state = FRAME_ERROR;
    }
}

static void sixlowpan_nhc_compress(struct sixlowpan_frame *f)
{
    uint8_t *nh = NULL;
    CHECK_PARAM_VOID(f);
    
    /* First time in this function, next header is right after IPv6 header */
    nh = f->net_hdr + DISPATCH_IPHC(INFO_HDR_LEN) + PICO_SIZE_IP6HDR;
    
    /* Compress header untill it isn't compressible anymore */
    while (FRAME_COMPRESSIBLE_NH == f->state) {
        sixlowpan_nhc(f, &nh);
    }
}

/* -------------------------------------------------------------------------------- */
// MARK: LOWPAN_IPHC
static int sixlowpan_iphc_am_undo(enum iphc_am am, uint8_t id, struct pico_sixlowpan_addr addr, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_ADDR_OFFSET(id), .length = IPV6_LEN_SRC};
    CHECK_PARAM(f);
    
    /* For now, the src-address is either fully elided or sent inline */
    if (AM_COMPRESSED_FULL == am) {
        /* Insert the Source Address-field again */
        if (!FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, r))
            return -1;
        
        /* Derive the IPv6 Link Local source address from the IEEE802.15.4 src-address */
        if (sixlowpan_ipv6_derive_local(&addr, f->net_hdr + IPV6_ADDR_OFFSET(id)))
            return -1;
    } else {
        /* Nothing is needed, IPv6-address is fully carried in-line */
    }
    
    return 0;
}

inline static struct range sixlowpan_iphc_mcast_dam(enum iphc_mcast_dam am)
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

static struct range sixlowpan_iphc_rearrange_mcast(uint8_t *addr, struct sixlowpan_iphc *iphc)
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
    
    return sixlowpan_iphc_mcast_dam(iphc->dam);
}

static int sixlowpan_iphc_dam_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Check for multicast destination */
    if (MCAST_MULTICAST == iphc->mcast) {
        if (!(FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, sixlowpan_iphc_mcast_dam(iphc->dam))))
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
        r = sixlowpan_iphc_rearrange_mcast(addr, iphc);
    } else {
        /* This will not occur */
    }
    
    return r;
}

static int sixlowpan_iphc_sam_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    return sixlowpan_iphc_am_undo(iphc->sam, IPV6_SOURCE, f->peer, f);
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

static int sixlowpan_iphc_hl_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_OFFSET_HL, .length = IPV6_LEN_HL};
    struct pico_ipv6_hdr *hdr = NULL;
    
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Check whether or not the Hop Limit is compressed */
    if (iphc->hop_limit) {
        /* Insert the Hop Limit-field again */
        if (!FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, r))
            return -1;
        
        /* Fill in the Hop Limit-field */
        hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        if (HL_COMPRESSED_1 == iphc->hop_limit) {
            hdr->hop = (uint8_t) 1;
        } else if (HL_COMPRESSED_64 == iphc->hop_limit) {
            hdr->hop = (uint8_t) 64;
        } else {
            hdr->hop = (uint8_t) 255;
        } /* smt else isn't possible */
    }
    
    return 0;
}

static struct range sixlowpan_iphc_hl(struct sixlowpan_iphc *iphc, uint8_t hl)
{
    struct range r = {.offset = 0, .length = 0};
    
    _CHECK_PARAM(iphc, r);
    
    switch (hl) {
        case 1:
            iphc->hop_limit = HL_COMPRESSED_1;
            break;
        case 64:
            iphc->hop_limit = HL_COMPRESSED_64;
            break;
        case 255:
            iphc->hop_limit = HL_COMPRESSED_255;
            break;
        default:
            iphc->hop_limit = HL_COMPRESSED_NONE;
            break;
    }
    
    if (iphc->hop_limit) {
        r.offset = IPV6_OFFSET_HL;
        r.length = IPV6_LEN_HL;
    }
    
    return r;
}

static void sixlowpan_iphc_nh_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_OFFSET_NH, .length = IPV6_LEN_NH};
    
    CHECK_PARAM_VOID(iphc);
    CHECK_PARAM_VOID(f);
    
    /* Check if Next Header is compressed */
    if (iphc->next_header) {
        /* Insert the Next Header-field again */
        if (!FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, r)) {
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

static struct range sixlowpan_iphc_nh(struct sixlowpan_iphc *iphc, uint8_t nh, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    
    _CHECK_PARAM(iphc, r);
    _CHECK_PARAM(f, r);
    
    /* See if the next header can be compressed */
    if (sixlowpan_nh_is_compressible(nh)) {
        iphc->next_header = NH_COMPRESSED;
        f->state = FRAME_COMPRESSIBLE_NH;
        f->nxthdr = nh;
        r.offset = IPV6_OFFSET_NH;
        r.length = IPV6_LEN_NH;
    } else {
        iphc->next_header = NH_COMPRESSED_NONE;
        f->state = FRAME_COMPRESSED;
    }
    
    return r;
}

inline static struct range sixlowpan_iphc_pl(void)
{
    struct range r = {.offset = IPV6_OFFSET_LEN, .length = IPV6_LEN_LEN};
    return r;
}

inline static int sixlowpan_iphc_pl_redo(struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    CHECK_PARAM(f);
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    hdr->len = short_be(f->net_len);
    return 0;
}

static int sixlowpan_iphc_pl_undo(struct sixlowpan_frame *f)
{
    CHECK_PARAM(f);
    /* Insert the payload-field again */
    if (!FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, sixlowpan_iphc_pl()))
        return -1;
    return sixlowpan_iphc_pl_redo(f);
}

inline static struct range sixlowpan_iphc_get_range(enum iphc_tf tf)
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

static int sixlowpan_iphc_tf_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    uint32_t *vtf = NULL;
    
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Insert the right amount of bytes so that the VTF-field is again 32-bits */
    if (!FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, sixlowpan_iphc_get_range(iphc->tf))) {
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
            /* Not possible */
            break;
    }
    
    return 0;
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
    
    return sixlowpan_iphc_get_range(iphc->tf);
}

static void sixlowpan_iphc_compress(struct sixlowpan_frame *f)
{
    struct range deletions[IPV6_FIELDS_NUM];
    struct pico_ipv6_hdr *hdr = NULL;
    struct sixlowpan_iphc iphc;
    uint8_t i = 0;
    
    CHECK_PARAM_VOID(f);
    
    /* Prepend IPHC header space */
    if (!(FRAME_BUF_PREPEND(f, PICO_LAYER_NETWORK, DISPATCH_IPHC(INFO_HDR_LEN)))) {
        f->state = FRAME_ERROR;
        return;
    }
    
    /* Fill in IPHC header */
    hdr = (struct pico_ipv6_hdr *)(f->net_hdr + DISPATCH_IPHC(INFO_HDR_LEN));
    iphc.dispatch = DISPATCH_IPHC(INFO_VAL);
    deletions[0] = sixlowpan_iphc_tf(&iphc, &hdr->vtf);
    deletions[1] = sixlowpan_iphc_pl();
    deletions[2] = sixlowpan_iphc_nh(&iphc, hdr->nxthdr, f);
    deletions[3] = sixlowpan_iphc_hl(&iphc, hdr->hop);
    deletions[4] = sixlowpan_iphc_sam(&iphc, hdr->src.addr);
    deletions[5] = sixlowpan_iphc_dam(&iphc, hdr->dst.addr);
    
    /* Copy the the IPHC header into the buffer */
    memcpy(f->net_hdr, (void *)&iphc, sizeof(struct sixlowpan_iphc));
    
    /* Try to apply Next Header compression */
    sixlowpan_nhc_compress(f);
    
    /* Elide fields in IPv6 header */
    for (i = IPV6_FIELDS_NUM; i > 0; i--) {
        if (!FRAME_BUF_DELETE(f, PICO_LAYER_NETWORK, deletions[i - 1], DISPATCH_IPHC(INFO_HDR_LEN))) {
            f->state = FRAME_ERROR;
            return;
        }
    }

    /* Check whether packet now fits inside the frame */
    if ((IEEE802154_len(f) <= IEEE802154_MAC_MTU)) {
        f->state = FRAME_FITS_COMPRESSED;
    } else {
        f->state = FRAME_COMPRESSED;
    }
}

static void sixlowpan_uncompressed(struct sixlowpan_frame *f)
{
    CHECK_PARAM_VOID(f);
    
    /* Provide space for the dispatch type */
    if (!FRAME_BUF_PREPEND(f, PICO_LAYER_NETWORK, DISPATCH_IPV6(INFO_HDR_LEN))) {
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
    if ((IEEE802154_len(f) + DISPATCH_IPV6(INFO_HDR_LEN)) <= IEEE802154_MAC_MTU) {
        sixlowpan_uncompressed(f);
    } else {
        sixlowpan_iphc_compress(f);
    }
}

static void sixlowpan_decompress_iphc(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_IPHC(INFO_HDR_LEN)};
    struct sixlowpan_iphc *iphc = NULL;
    CHECK_PARAM_VOID(f);
    
    /* Provide space for a copy of the LOWPAN_IPHC-header */
    if (!(iphc = PICO_ZALLOC(sizeof(struct sixlowpan_iphc)))) {
        pico_err = PICO_ERR_ENOMEM;
        f->state = FRAME_ERROR;
        return;
    }
    
    /* Parse in the LOWPAN_IPHC-header */
    memcpy(iphc, f->net_hdr, (size_t) DISPATCH_IPHC(INFO_HDR_LEN));
    
    /* Remove the IPHC header from the buffer at once */
    FRAME_BUF_DELETE(f, PICO_LAYER_NETWORK, r, 0);
    
    sixlowpan_iphc_tf_undo(iphc, f);
    sixlowpan_iphc_pl_undo(f);
    sixlowpan_iphc_nh_undo(iphc, f);
    sixlowpan_iphc_hl_undo(iphc, f);
    sixlowpan_iphc_sam_undo(iphc, f);
    sixlowpan_iphc_dam_undo(iphc, f);
    
    /* Recalculate the Payload Length again because it changed since ..._pl_undo() */
    sixlowpan_iphc_pl_redo(f);
    
    /* If there isn't any Next Header compression we can assume the IPv6 Header is default
     * and therefore 40 bytes in size */
    if (FRAME_COMPRESSED_NHC == f->state)
        sixlowpan_nhc_decompress(f);
    
    /* The differentation isn't usefull anymore, make it a single buffer */
    f->net_len = (uint16_t)(f->net_len + f->transport_len);
    f->transport_len = (uint16_t)(0);

    /* Indicate decompression */
    f->state = FRAME_DECOMPRESSED;
    
    /* Give the memory allocated back */
    PICO_FREE(iphc);
}

static void sixlowpan_decompress_ipv6(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = DISPATCH_IPV6(INFO_HDR_LEN)};
    CHECK_PARAM_VOID(f);
    FRAME_BUF_DELETE(f, PICO_LAYER_NETWORK, r, 0);
    f->state = FRAME_DECOMPRESSED;
}

static void sixlowpan_decompress(struct sixlowpan_frame *f)
{
    uint8_t d = 0;
    CHECK_PARAM_VOID(f);
    
    /* Determine compression */
    d = f->net_hdr[0]; /* dispatch type */
    if (CHECK_DISPATCH(d, SIXLOWPAN_IPV6)) {
        sixlowpan_decompress_ipv6(f);
    } else if (CHECK_DISPATCH(d, SIXLOWPAN_IPHC)) {
        sixlowpan_decompress_iphc(f);
    }
    
    /* Dispatch is unknown, no decompression is needed */
}

/* -------------------------------------------------------------------------------- */
// MARK: TRANSLATING

/**
 *  Determines the link-layer destination address.
 *
 *  @param f   struct pico_frame *, to send to destination.
 *  @param l   struct pico_sixlowpan_addr *, to fill with the link-layer
 *             destination-address.
 *
 *  @return 0 when the link-layer dst is properly determined, something else otherwise.
 */
static int sixlowpan_ll_derive_dst(struct pico_frame *f,
                                   struct pico_sixlowpan_addr *l)
{
    struct pico_ip6 *dst = NULL;
    
    CHECK_PARAM(f);
    
    dst = &((struct pico_ipv6_hdr *)f->net_hdr)->dst;
    
    if (pico_ipv6_is_multicast(dst->addr)) {
        /* Derive link layer address from IPv6 Multicast address */
        return sixlowpan_ll_derive_mcast(l, dst);
    } else if (pico_ipv6_is_linklocal(dst->addr)) {
        /* Derive link layer address from IPv6 Link Local address */
        return sixlowpan_ll_derive_local(l, dst);
    } else {
        /* Resolve unicast link layer address using 6LoWPAN-ND */
        return sixlowpan_ll_derive_nd(f, l);
    }
    
    return 0;
}

/**
 *  Provides IEEE802.15.4 MAC header based on information contained in the
 *  6LoWPAN-frame.
 *
 *  @param f struct sixlowpan_frame *, frame to provide Link Layer header for.
 *
 *  @return 0 on success, something else on failure.
 */
static int sixlowpan_ll_provide(struct sixlowpan_frame *f)
{
    struct IEEE802154_fcf *fcf = NULL;
    IEEE802154_hdr_t *hdr = NULL;
    static uint8_t seq = 0; /* STATIC SEQUENCE NUMBER */
    radio_t *radio = NULL;
    
    CHECK_PARAM(f);
    
    radio = ((struct pico_device_sixlowpan *)f->dev)->radio;

    /* Set some shortcuts */
    hdr = f->link_hdr;
    fcf = &(hdr->fcf);
    
    /* Set Frame Control Field flags. */
    fcf->frame_type = IEEE802154_FRAME_TYPE_DATA;
    fcf->security_enabled = IEEE802154_FALSE;
    fcf->frame_pending = IEEE802154_FALSE;
    fcf->ack_required = IEEE802154_FALSE;
    fcf->intra_pan = IEEE802154_TRUE;
    fcf->frame_version = IEEE802154_FRAME_VERSION_2003;
    
    /* Set the addressing modes */
    if (IEEE802154_ADDRESS_MODE_BOTH == f->peer._mode)
        fcf->dam = IEEE802154_ADDRESS_MODE_SHORT;
    else
        fcf->dam = f->peer._mode;
    if (IEEE802154_ADDRESS_MODE_BOTH == f->local._mode)
        fcf->sam = IEEE802154_ADDRESS_MODE_SHORT;
    else
        fcf->sam = f->local._mode;
    
    /* Set sequence number and PAN ID */
    hdr->seq = seq;
    hdr->pan = radio->get_pan_id(radio);
    
    sixlowpan_addr_copy_flat(hdr->addresses, f->peer, 0, ENDIAN_IEEE802154);
    sixlowpan_addr_copy_flat(hdr->addresses, f->local, IEEE802154_ADDR_LEN(f->peer._mode), ENDIAN_IEEE802154);
    
    seq++; /* Increment sequence number for the next time */
    return 0;
}

/**
 *  Prepares the buffers of a 6LoWPAN-frame.
 *
 *  @param f  struct sixlowpan_frame *, to prepare the buffers for.
 *  @param pf struct pico_frame *, to copy the buffers from
 *
 *  @return 0 when everything went well.
 */
static int sixlowpan_frame_convert(struct sixlowpan_frame *f, struct pico_frame *pf)
{
    CHECK_PARAM(f);
    CHECK_PARAM(pf);
    
    /* Determine size of the transport-layer */
    f->transport_len = (uint16_t)(pf->len - pf->net_len);
    
    /* Determine size of the network-layer */
    f->net_len = (uint8_t)pf->net_len;
    f->dgram_size = (uint16_t)(f->net_len + f->transport_len);
    
    /* Determine the size */
    IEEE802154_len(f);
    if (!(f->phy_hdr = PICO_ZALLOC(f->size))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    
    FRAME_REARRANGE_PTRS(f);
    
    /* Copy in data from the pico_frame */
    memcpy(f->net_hdr, pf->net_hdr, f->net_len);
    memcpy(f->transport_hdr, pf->transport_hdr, f->transport_len);
    
    /* PROVIDE LINK LAYER INFORMATION */
    return sixlowpan_ll_provide(f);
}

static struct sixlowpan_frame *sixlowpan_frame_translate(struct pico_frame *f)
{
    struct sixlowpan_frame *frame = NULL;
    
    CHECK_PARAM_NULL(f);

    /* Provide space for the 6LoWPAN frame */
    if (!(frame = PICO_ZALLOC(sizeof(struct sixlowpan_frame)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    frame->dev = f->dev;
    frame->local = *(f->dev->sixlowpan); /* Set the LL-address of the local host */
    
    /* Determine the link-layer address of the destination */
    if (sixlowpan_ll_derive_dst(f, &frame->peer) < 0) {
        pico_ipv6_nd_postpone(f);
        sixlowpan_frame_destroy(frame);
        pico_err = PICO_ERR_EHOSTUNREACH;
        return NULL;
    }
    
    /* Prepare seperate buffers for compressing */
    if (sixlowpan_frame_convert(frame, f)) {
        sixlowpan_frame_destroy(frame);
        return NULL;
    }
    
    return frame;
}

static void sixlowpan_frame_frag(struct sixlowpan_frame *f)
{
    struct range r = {0, .length = DISPATCH_FRAGN(INFO_HDR_LEN)};
    struct sixlowpan_frag1 *frag1 = NULL;
    struct sixlowpan_fragn *fragn = NULL;
    static uint16_t dtag = 0;
    uint8_t max_psize = 0, n = 0, i = 0, diff = 0, *buf = NULL;
    
    CHECK_PARAM_VOID(f);
    
    /* Determine how many bytes need to be transmitted to send the entire IPv6-payload */
    f->to_send = (uint16_t)(f->net_len + f->transport_len);
    
    /* Determine how many bytes fits inside a single IEEE802.15.4-frame including 802.15.4-header and frag-header */
    max_psize = (uint8_t)(IEEE802154_MAC_MTU - f->link_hdr_len);
    max_psize = (uint8_t)(max_psize - sizeof(struct sixlowpan_fragn));
    
    diff = (uint8_t)(f->dgram_size - f->to_send);
    max_psize = (uint8_t)(max_psize + diff);
    
    /* Determine how many multiples of eight bytes fit inside that same amount of bytes determined a line above */
    f->max_bytes = (uint8_t)((uint8_t)((max_psize / 8) * 8) - diff); /* <- integer division */
    
    /* Determine how many packets excluding the first fragment need to be send in order send the entire payload */
    n = (uint8_t)(f->to_send / f->max_bytes);
    
    /* Prepend space for the first Fragmentation header */
    if (!FRAME_BUF_PREPEND(f, PICO_LAYER_NETWORK, sizeof(struct sixlowpan_frag1))) {
        f->state = FRAME_ERROR;
        return;
    }
    
    /* Set the LOWPAN_FRAG1-fields */
    frag1 = (struct sixlowpan_frag1 *)f->net_hdr;
    frag1->dispatch = DISPATCH_FRAG1(INFO_VAL);
    frag1->datagram_tag = short_be(++dtag);
    SET_FRAG_SIZE(frag1, f->dgram_size);
    
    /* Iterate of the network header until the end and insert fragmentation headers */
    buf = (uint8_t *)(f->net_hdr + f->max_bytes + sizeof(struct sixlowpan_frag1));
    
    for (i = 0; i < n; i++) {
        r.offset = (uint16_t)(buf - f->net_hdr);
        /* Insert chunk for another fragementation header */
        if (!(buf = FRAME_BUF_INSERT(f, PICO_LAYER_NETWORK, r))) {
            f->state = FRAME_ERROR;
            return;
        }
        
        /* Set the fields of the current frag-header */
        fragn = (struct sixlowpan_fragn *)buf;
        fragn->dispatch = DISPATCH_FRAGN(INFO_VAL);
        fragn->datagram_tag = short_be(dtag);
        fragn->offset = (uint8_t)((i + 1) * (uint8_t)((f->max_bytes + diff) / 8));
        SET_FRAG_SIZE(fragn, f->dgram_size);
        
        /* Move to next place to insert a fragmentation header */
        buf = buf + f->max_bytes + sizeof(struct sixlowpan_fragn);
    }
    
    f->state = FRAME_FRAGMENTED;
}

static uint8_t *sixlowpan_frame_tx_next(struct sixlowpan_frame *f, uint8_t *len)
{
    struct range r = {.offset = 0, .length = 0};
    uint8_t *buf = NULL;
    uint8_t fragl = 0;
    
    CHECK_PARAM_NULL(f);
    CHECK_PARAM_NULL(len);
    
    if (0 == f->to_send)
        return NULL;

    if (CHECK_DISPATCH((*f->net_hdr), SIXLOWPAN_FRAG1)) {
        fragl = (uint8_t)(f->max_bytes + sizeof(struct sixlowpan_frag1));
        f->to_send = (uint16_t)(f->to_send - f->max_bytes);
    } else {
        /* Determine if we're at the rest or not */
        if (f->to_send < f->max_bytes) {
            fragl = (uint8_t)(f->to_send + sizeof(struct sixlowpan_fragn));
            f->to_send = (uint16_t)0;
        } else {
            fragl = (uint8_t)(f->max_bytes + sizeof(struct sixlowpan_fragn));
            f->to_send = (uint16_t)(f->to_send - f->max_bytes);
        }
    }
    
    *len = (uint8_t)(f->link_hdr_len + (uint8_t)(fragl + IEEE802154_PHY_OVERHEAD));
    if (!(buf = PICO_ZALLOC((size_t)(*len)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    memcpy(buf + IEEE802154_LEN_LEN, f->link_hdr, (size_t)(*len - IEEE802154_PHY_OVERHEAD));
    
    /* Remove the fragment from the frame */
    r.length = (uint16_t)fragl;
    FRAME_BUF_DELETE(f, PICO_LAYER_NETWORK, r, 0);
    
    return buf;
}

static int sixlowpan_send_cur_frame(struct pico_device_sixlowpan *slp)
{
    uint8_t *buf = NULL;
    uint8_t len = 0;
    int ret = 0;
    
    CHECK_PARAM(slp);
    CHECK_PARAM(cur_frame);
    
    /* Check whether the fragment is fragmented */
    if (FRAME_FRAGMENTED == cur_frame->state) {
        /* Get the next frame of current_frame */
        if ((buf = sixlowpan_frame_tx_next(cur_frame, &len))) {
            /* If buf, transmit the buf and free memory */
            ret = slp->radio->transmit(slp->radio, buf, len);
            PICO_FREE(buf);
        } else {
            /* If buf is NULL, that means that the fragged packet is tx'd */
            sixlowpan_state = SIXLOWPAN_READY;
            ret = cur_frame->size;
            PICO_FREE(cur_frame);
            cur_frame = NULL;
        }
    } else {
        /* Send the current frame as a whole */
        ret = slp->radio->transmit(slp->radio, cur_frame->phy_hdr, cur_frame->size);
        sixlowpan_state = SIXLOWPAN_READY;
        PICO_FREE(cur_frame);
        cur_frame = NULL;
    }
    
    return ret;
}

static uint16_t sixlowpan_defrag_prep(struct sixlowpan_frame *f)
{
    struct range r = { 0, 0 };
    uint16_t offset = 0; /* frag_offset in bytes */
    int first = 0;
    
    /* Determine the offset of the fragment */
    first = CHECK_DISPATCH(f->net_hdr[0], SIXLOWPAN_FRAG1);
    if (!first) {
        offset = (uint16_t)(((struct sixlowpan_fragn *)f->net_hdr)->offset * 8);
    }
    
    /* Determine the size of the IP-packet before LL compression/fragmentation */
    f->dgram_size = GET_FRAG_SIZE((struct sixlowpan_frag1 *)f->net_hdr);
    f->dgram_tag = short_be((uint16_t)(((struct sixlowpan_frag1 *)f->net_hdr)->datagram_tag));
    
    /* Delete the fragmentation header from the buffer */
    r.length = (first) ? (DISPATCH_FRAG1(INFO_HDR_LEN)) : (DISPATCH_FRAGN(INFO_HDR_LEN));
    if (!FRAME_BUF_DELETE(f, PICO_LAYER_NETWORK, r, 0)) {
        f->state = FRAME_ERROR;
        return 0;
    }
    
    /* Try to decompress the received frame */
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
    
    /* [ PHY | ~~LINK~~ | IPv6-PAYLOAD ... | PHY ] <- size */
    reassembly->size = (uint16_t)(IEEE802154_PHY_OVERHEAD + f->link_hdr_len + f->dgram_size);
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
    FRAME_REARRANGE_PTRS(reassembly);
    
    /* Copy in the buffer fields from the received frame */
    memmove(reassembly->phy_hdr, f->phy_hdr, IEEE802154_LEN_LEN);
    memmove(reassembly->link_hdr, f->link_hdr, f->link_hdr_len);
    memmove(reassembly->net_hdr + offset, f->net_hdr, f->net_len);
    
    /* How many bytes there still need to be puzzled */
    reassembly->to_send = (uint16_t)(reassembly->dgram_size - f->net_len);
    
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
    struct pico_ipv6_hdr *hdr = NULL;
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
        reassembly->to_send = (uint16_t)(reassembly->to_send - f->net_len);
        
        /* TODO: Check for overlapping */
        
        /* Check if the IPv6 frame is completely defragged */
        if (0 == reassembly->to_send) {
            ret = reassembly;
            if (!pico_tree_delete(&Frags, reassembly))
                PAN_ERR("Reassembly frame not in the tree, could not delete.\n");
            ret->state = FRAME_DEFRAGMENTED;
            hdr = (struct pico_ipv6_hdr *)reassembly->net_hdr;
            hdr->len = (uint16_t)(reassembly->dgram_size - PICO_SIZE_IP6HDR);
        }
    }
    
    /* Everything went okay, destroy fragment */
    sixlowpan_frame_destroy(f);
    return ret; /* Returns either NULL, or defragged frame */
}

static struct sixlowpan_frame *sixlowpan_defrag(struct sixlowpan_frame *f)
{
    uint8_t d = 0;
    CHECK_PARAM_NULL(f);
    
    d = f->net_hdr[0];
    
    /* Check for LOWPAN_FRAGx dispatch header */
    if (CHECK_DISPATCH(d, SIXLOWPAN_FRAG1) || CHECK_DISPATCH(d, SIXLOWPAN_FRAGN))
        f = sixlowpan_defrag_puzzle(f);
    
    return f;
}

/* -------------------------------------------------------------------------------- */
// MARK: PICO_DEV
static int sixlowpan_send(struct pico_device *dev, void *buf, int len)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *)dev;
    struct pico_frame *f = (struct pico_frame *)buf;
    struct sixlowpan_frame *frame = NULL;
    
    /* While transmitting no frames can be passed to the 6LoWPAN-device */
    if (SIXLOWPAN_TRANSMITTING == sixlowpan_state)
        return 0;
    
    CHECK_PARAM(dev);
    CHECK_PARAM(buf);
    IGNORE_PARAMETER(len);
    
    /* Translate the pico_frame */
    if (!(frame = sixlowpan_frame_translate(f))) {
        PAN_ERR("Failed translating pico_frame\n");
        return -1;
    }
    
    /* Try to compress the 6LoWPAN-frame */
    sixlowpan_compress(frame);
    if (FRAME_COMPRESSED == frame->state) {
        /* Try to fragment the entire compressed frame */
        sixlowpan_frame_frag(frame);
        if (FRAME_ERROR == frame->state) {
            PAN_ERR("Failed fragmenting 6LoWPAN-frame\n");
            sixlowpan_frame_destroy(frame);
            return -1;
        }
    } else if (FRAME_FITS == frame->state || FRAME_FITS_COMPRESSED == frame->state) {
        /* Nothing to do */
    } else {
        PAN_ERR("Unkown frame state (%d).\n", frame->state);
        sixlowpan_frame_destroy(frame);
        return -1;
    }
    
    /* TODO: [6LOWPAN ADAPTION LAYER] prepend BROADCASTING/MESH ROUTING */
    
    /* 1. - Whether or not the packet need to broadcasted */
    /* 2. - Whether or not the packet needs to be mesh routed */
    
    /* Schedule for sending */
    if (frame) {
        cur_frame = frame;
        sixlowpan_state = SIXLOWPAN_TRANSMITTING;
        return sixlowpan_send_cur_frame(sixlowpan);
    }
    
    return -1;
}

static int sixlowpan_poll(struct pico_device *dev, int loop_score)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *) dev;
    struct sixlowpan_frame *f = NULL;
    radio_t *radio = sixlowpan->radio;
    uint8_t buf[IEEE802154_PHY_MTU];
    uint8_t len = 0;
    
    do {
        if (RADIO_ERR_NOERR == radio->receive(radio, buf)) {
            if ((len = buf[0]) > 0) {
                /* [IEEE802.15.4 LINK LAYER] decapsulate MAC frame to IPv6 */
                if (!(f = IEEE802154_unbuf(dev, buf, len)))
                    return loop_score;
                
                /* 1. Check for MESH Dispatch header */
                /* 2. Check for BROADCAST header */
                
                /* [6LOWPAN ADAPTION LAYER] unfragment */
                f = sixlowpan_defrag(f);
                
                /* If NULL, everthing OK, but I'm still waiting for some other packets */
                if (!f) {
                    --loop_score;
                    continue;
                } else {
                    if (FRAME_ERROR == f->state) {
                        PAN_ERR("During defragmentation.\n");
                        sixlowpan_frame_destroy(f);
                        return loop_score;
                    } else if (FRAME_DEFRAGMENTED == f->state) {
                        /* IPv6-datagram is completely defragged, do nothing */
                        dbg_mem("DEFRAGGED", f->net_hdr, f->net_len);
                    } else {
                        /* [6LOWPAN ADAPTION LAYER] apply decompression/defragmentation */
                        sixlowpan_decompress(f);
                        if (FRAME_ERROR == f->state) {
                            PAN_ERR("During decompression.\n");
                            sixlowpan_frame_destroy(f);
                            return loop_score;
                        }
                    }
                }
                
                pico_stack_recv(dev, f->net_hdr, (uint32_t)(f->net_len));
                
                /* Discard frame */
                sixlowpan_frame_destroy(f);
                
                --loop_score;
            }
        } else {
            break;
        }
	} while (loop_score > 0);
	
    /* Can I do smt. else? */
    if (SIXLOWPAN_TRANSMITTING == sixlowpan_state)
        sixlowpan_send_cur_frame(sixlowpan); /* Yes! Send current frame! */
    
    return loop_score;
}

/* -------------------------------------------------------------------------------- */
// MARK: API
void pico_sixlowpan_set_prefix(struct pico_device *dev, struct pico_ip6 prefix)
{
    struct pico_ip6 netmask = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    struct pico_ip6 routable;
    struct pico_device_sixlowpan *slp = NULL;
    struct pico_ipv6_link *link = NULL;
    CHECK_PARAM_VOID(dev);
    
    /* Parse the pico_device structure to the internal sixlowpan-structure */
    slp = (struct pico_device_sixlowpan *) dev;
    
    /* Set a routable-address */
    memcpy(routable.addr, prefix.addr, PICO_SIZE_IP6);
    memcpy(routable.addr + 8, dev->sixlowpan->_ext.addr, PICO_SIZE_SIXLOWPAN_EXT);
    routable.addr[8] = routable.addr[8] ^ 0x02;
    
    /* Store the PAN-prefix in the device-instance */
    memcpy(slp->prefix.addr, routable.addr, PICO_SIZE_IP6);
    
    /* Add a link with IPv6-address generated from EUI-64 address */
    if (!(link = pico_ipv6_link_add(dev, routable, netmask)))
        return;
    
    if (dev->sixlowpan->_short.addr != IEEE802154_BCST_ADDR) {
        memset(routable.addr + 8, 0x00, 8);
        routable.addr[11] = 0xFF;
        routable.addr[12] = 0xFE;
        memcpy(routable.addr + 14, &(dev->sixlowpan->_short.addr), PICO_SIZE_SIXLOWPAN_SHORT);
        
        /* Add another link with IPv6-address generated from the short 16-bit address */
        if (!(link = pico_ipv6_link_add(dev, routable, netmask)))
            return;
    }
}

void pico_sixlowpan_short_addr_configured(struct pico_device *dev)
{
    struct pico_device_sixlowpan *slp = NULL;
    
    CHECK_PARAM_VOID(dev);
    
    /* Parse the pico_device structure to the internal sixlowpan-structure */
    slp = (struct pico_device_sixlowpan *) dev;
    
    if (dev->sixlowpan) {
        /**
         *  Set the short-address of the device. A check whether or not
         *  the device already had a short-address is not needed. I assume
         *  the device-driver has priority of configuring addresses and assume
         *  it takes this into account.
         */
        dev->sixlowpan->_short.addr = slp->radio->get_addr_short(slp->radio);
        
        /* Set the address mode accordingly */
        if (IEEE802154_BCST_ADDR != dev->sixlowpan->_short.addr) {
            if (IEEE802154_ADDRESS_MODE_EXTENDED == dev->sixlowpan->_mode)
                dev->sixlowpan->_mode = IEEE802154_ADDRESS_MODE_BOTH;
            else
                dev->sixlowpan->_mode = IEEE802154_ADDRESS_MODE_SHORT;
        }
    }
}

struct pico_device *pico_sixlowpan_create(radio_t *radio)
{
    struct pico_device_sixlowpan *sixlowpan = NULL;
    struct pico_sixlowpan_addr slp;
    char dev_name[MAX_DEVICE_NAME];
    
    CHECK_PARAM_NULL(radio);

    if (!(sixlowpan = PICO_ZALLOC(sizeof(struct pico_device_sixlowpan))))
        return NULL;
    
    /* Generate pico_sixlowpan_addr for the pico_device */
    radio->get_addr_ext(radio, slp._ext.addr);
    slp._short.addr = radio->get_addr_short(radio);
    slp._mode = IEEE802154_ADDRESS_MODE_EXTENDED;
    if (IEEE802154_BCST_ADDR != slp._short.addr)
        slp._mode = IEEE802154_ADDRESS_MODE_BOTH;
    
	/* Try to init & register the device to picoTCP */
    snprintf(dev_name, MAX_DEVICE_NAME, "sixlowpan%04d", sixlowpan_devnum++);
    if (0 != pico_sixlowpan_init((struct pico_device *)sixlowpan, dev_name, slp)) {
        dbg("Device init failed.\n");
        return NULL;
    }
	
    /* Set the device-parameters*/
    sixlowpan->dev.overhead = 0;
    sixlowpan->dev.send = sixlowpan_send;
    sixlowpan->dev.poll = sixlowpan_poll;
    
    /* Assign the radio-instance to the pico_device-instance */
    sixlowpan->radio = radio;
	
	/* Cast internal 6LoWPAN-structure to picoTCP-device structure */
    return (struct pico_device *)sixlowpan;
}
#endif /* PICO_SUPPORT_SIXLOWPAN */
