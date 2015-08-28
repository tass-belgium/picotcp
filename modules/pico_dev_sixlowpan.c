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
#define pan_dbg(s, ...) dbg("[SIXLOWPAN]$ " s, ##__VA_ARGS__)
#define pan_dbg_c dbg
#else
#define pan_dbg(...) do {} while(0)
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
#define IPV6_ADDR_OFFSET(id)        ((IPV6_SOURCE == (id)) ? (IPV6_OFFSET_SRC) : (IPV6_OFFSET_DST))

#define IPHC_SHIFT_ECN              (10u)
#define IPHC_SHIFT_DSCP             (2u)
#define IPHC_SHIFT_FL               (8u)
#define IPHC_MASK_DSCP              (uint32_t)(0xFC00000)
#define IPHC_MASK_ECN               (uint32_t)(0x300000)
#define IPHC_MASK_FL                (uint32_t)(0xFFFFF)
#define IPHC_SIZE_MCAST_8           (1u)
#define IPHC_SIZE_MCAST_32          (4u)
#define IPHC_SIZE_MCAST_48          (6u)

#define VERSION                     ((uint32_t)(0x60000000))
#define DSCP(vtf)                   (((vtf) >> IPHC_SHIFT_DSCP) & IPHC_MASK_DSCP)
#define ECN(vtf)                    (((vtf) >> IPHC_SHIFT_ECN) & IPHC_MASK_ECN)
#define FLS(vtf)                    (((vtf) >> IPHC_SHIFT_FL) & IPHC_MASK_FL)
#define FL(vtf)                     ((vtf) & IPHC_MASK_FL)

#define IPHC_DSCP(vtf)              ((long_be((vtf)) << IPHC_SHIFT_DSCP) & IPHC_MASK_DSCP)
#define IPHC_ECN(vtf)               ((long_be((vtf)) << IPHC_SHIFT_ECN) & IPHC_MASK_ECN)
#define IPHC_FLS(vtf)               ((long_be((vtf)) & IPHC_MASK_FL) << IPHC_SHIFT_FL);
#define IPHC_FL(vtf)                (long_be((vtf)) & IPHC_MASK_FL);

#define IPV6_IS_MCAST_8(addr)       ((addr)[1] == 0x02 && (addr)[14] == 0x00)
#define IPV6_IS_MCAST_32(addr)      ((addr)[12] == 0x00)
#define IPV6_IS_MCAST_48(addr)      ((addr)[10] == 0x00)

#define R_VOID
#define R_NULL                      (NULL)
#define R_ZERO                      (0)
#define R_PLAIN                     (-1)
#define _CHECK_PARAM(a, b)          if(!(a)){ \
                                        pico_err = PICO_ERR_EINVAL; \
                                        pan_dbg("!ERR!: %s: %d\n", __FUNCTION__, __LINE__); \
                                        return b; \
                                    } do {} while(0)
#define CHECK_PARAM(a)              _CHECK_PARAM((a), R_PLAIN)
#define CHECK_PARAM_NULL(a)         _CHECK_PARAM((a), R_NULL)
#define CHECK_PARAM_ZERO(a)         _CHECK_PARAM((a), R_ZERO)
#define CHECK_PARAM_VOID(a)         _CHECK_PARAM((a), R_VOID)

static int sixlowpan_devnum = 0;

enum sixlowpan_state
{
    SIXLOWPAN_NREADY = -1,
    SIXLOWPAN_READY,
    SIXLOWPAN_TRANSMITTING
};

static volatile enum sixlowpan_state sixlowpan_state = SIXLOWPAN_READY;

/* -------------------------------------------------------------------------------- */
// MARK: 6LoWPAN types

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

/**
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
    FRAME_NOT_COMPRESSED_NHC,
    FRAME_DECOMPRESSED
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
    
    uint8_t *fcs;
    
    uint8_t max_bytes;
    uint16_t to_send;
    
    /* Next Header field */
    uint8_t nxthdr;

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

/**
 *  Possible 6LoWPAN dispatch type definitions
 *  MARK: Dispatch Types
 */
enum dispatch_type
{
    SIXLOWPAN_NALP,     /* Not a 6LoWPAN frame */
    SIXLOWPAN_IPV6,     /* Uncompressed IPv6 frame */
    SIXLOWPAN_HC1,      /* LOWPAN_HC1 compressed IPv6 */
    SIXLOWPAN_BC0,      /* LOWPAN_BC0 broadcast frame */
    SIXLOWPAN_ESC,      /* Additional dispatch byte follows [RFC4944] */
    SIXLOWPAN_MESH,     /* Mesh Header */
    SIXLOWPAN_FRAG1,    /* First fragmentation header */
    SIXLOWPAN_FRAGN,    /* Subsequent fragmentation header */
    SIXLOWPAN_NESC,     /* Replacement ESC dispatch [RFC6282] */
    SIXLOWPAN_IPHC,     /* LOWPAN_IPHC compressed IPv6 */
    SIXLOWPAN_NHC_EXT,  /* LOWPAN_NHC compressed IPv6 EXTension Header */
    SIXLOWPAN_NHC_UDP   /* LOWPAN_NHC compressed UDP header */
};

/**
 *  Contains information about a specific 6LoWPAN dispatch type;
 *
 *  VAL:        Actual dispatch-type value itself, to compare against
 *  COMP:       Value to compare to after shifting the actual dispatch-
 *              value SHIFT times.
 *  SHIFT:      Times to shift right before values can be compared, is
 *              actually 8 - LEN.
 *  HDR_LEN:    Full 6LoWPAN header length (in bytes) for the specific
 *              dispatch type, including dispatch type itself.
 *              0xFF means variable length.
 */
const uint8_t const dispatch_info[12][4] =
{
    //  {VAL, COMP, SHIFT, HDR_LEN}
    {0x00, 0x00, 0x06, 0x00}, /* NALP */
    {0x41, 0x41, 0x00, 0x01}, /* IPV6 */
    {0x42, 0x42, 0x00, 0x02}, /* HC1 (DEPRECATED, N.I). */
    {0x50, 0x50, 0x00, 0x02}, /* BC0 */
    {0x7F, 0x7F, 0x00, 0xFF}, /* ESC */
    {0x80, 0x02, 0x06, 0xFF}, /* MESH */
    {0xC0, 0x18, 0x03, 0x04}, /* FRAG1 */
    {0xE0, 0x1C, 0x03, 0x05}, /* FRAGN */
    {0x80, 0x80, 0x00, 0xFF}, /* NESC */
    {0x60, 0x03, 0x05, 0x02}, /* IPHC */
    {0xE0, 0x0E, 0x04, 0x01}, /* NHC_EXT */
    {0xF0, 0x1E, 0x03, 0x01}  /* NHC_UDP */
};

/**
 *  Possible information type definitions
 */
enum dispatch_info_type
{
    INFO_VAL,
    INFO_COMP,
    INFO_SHIFT,
    INFO_HDR_LEN
};

#define CHECK_DISPATCH(d, type) (((d) >> dispatch_info[(type)][INFO_SHIFT]) == dispatch_info[(type)][INFO_COMP])

/**
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

/**
 *  LOWPAN_NHC_EXT Header structure
 *  MARK: LOWPAN_NHC types
 */
PACKED_STRUCT_DEF sixlowpan_nhc_ext
{
    uint8_t nh: 1;
    uint8_t eid: 3;
    uint8_t dispatch: 4;
}; /* NHC_EXT Header */

enum nhc_ext_eid
{
    EID_HOPBYHOP = 0,
    EID_ROUTING,
    EID_FRAGMENT,
    EID_DESTOPT,
}; /* IPv6 Extension IDentifier */

/**
 *  LOWPAN_NHC_UDP Header structure
 */
PACKED_STRUCT_DEF sixlowpan_nhc_udp
{
    uint8_t ports: 2;
    uint8_t checksum: 1;
    uint8_t dispatch: 5;
}; /* NHC_UDP Header */

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

/**
 *  LOWPAN_NHC Header structure
 *  MARK: Generic types
 */
struct range
{
    uint16_t offset;
    uint16_t length;
};

/* -------------------------------------------------------------------------------- */
// MARK: DEBUG
#ifdef DEBUG
static void UNUSED dbg_ipv6(const char *pre, struct pico_ip6 *ip)
{
    uint8_t i = 0;
    
    pan_dbg("%s", pre);
    for (i = 0; i < 16; i = (uint8_t)(i + 2)) {
        pan_dbg_c("%02x%02x", ip->addr[i], ip->addr[i + 1]);
        if (i != 14)
            pan_dbg_c(":");
    }
    pan_dbg_c("\n");
}

static void UNUSED dbg_mem(const char *pre, void *buf, uint16_t len)
{
    uint16_t i = 0, j = 0;
    
    /* Print in factors of 8 */
    pan_dbg("%s\n", pre);
    for (i = 0; i < (len / 8); i++) {
        pan_dbg("%03d. ", i * 8);
        for (j = 0; j < 8; j++) {
            pan_dbg_c("%02X ", ((uint8_t *)buf)[j + (i * 8)] );
            if (j == 3)
                pan_dbg_c(" ");
        }
        pan_dbg_c("\n");
    }
    
    if (!(len % 8))
        return;
    
    /* Print the rest */
    pan_dbg("%03d. ", i * 8);
    for (j = 0; j < (len % 8); j++) {
        pan_dbg_c("%02X ", ((uint8_t *)buf)[j + (i * 8)] );
        if (j == 3)
            pan_dbg_c(" ");
    }
    pan_dbg_c("\n");
}
#endif

/* -------------------------------------------------------------------------------- */
// MARK: MEMORY
static uint16_t buf_delete(void *buf, uint16_t len, struct range r)
{
    uint16_t rend = (uint16_t)(r.offset + r.length);
    
    CHECK_PARAM_ZERO(buf);
    
    if (!rend || r.offset > len || rend > len)
        return len;
    
    memmove(buf + r.offset, buf + rend, (size_t)((buf + len) - (buf + rend)));
    
    return (uint8_t)(len - r.length);
}
#define MEM_DELETE(buf, len, range) (len) = (uint16_t)buf_delete((buf),(uint16_t)(len),(range))

static void *buf_insert(void *buf, uint16_t len, struct range r)
{
    uint16_t rend = (uint16_t)(r.offset + r.length);
    void *new = NULL;
    
    CHECK_PARAM_NULL(buf);
    
    if (!rend || r.offset > len || rend > len)
        return buf;
    
    if (!(new = PICO_ZALLOC((size_t)(len + r.length))))
        return buf;
    
    /* aggregate buffer again */
    memmove(new, buf, (size_t)r.offset);
    memmove(new + r.offset + r.length, buf + r.offset, (size_t)(len - r.offset));
    memset(new + r.offset, 0x00, r.length);
    
    PICO_FREE(buf);
    
    return new;
}
#define MEM_INSERT(buf, len, range) (buf) = buf_insert((buf),(uint16_t)(len),(range))

static inline int FRAME_REARRANGE_PTRS(struct sixlowpan_frame *f)
{
    CHECK_PARAM(f);
    
    f->link_hdr = (IEEE802154_hdr_t *)((void *)(f->phy_hdr) + IEEE802154_LEN_LEN);
    f->net_hdr = ((uint8_t *)f->link_hdr) + f->link_hdr_len;
    f->transport_hdr = f->net_hdr + f->net_len;
    f->fcs = f->transport_hdr + f->transport_len;
    
    return 0;
}

static uint8_t *FRAME_BUF_INSERT(struct sixlowpan_frame *f, uint8_t *buf, struct range r)
{
    uint8_t *ret = NULL;
    
    CHECK_PARAM_NULL(f);
    CHECK_PARAM_NULL(buf);
    
    if (buf == (uint8_t *)f->link_hdr) {
        /* Set the new size of the link layer-chunk */
        f->link_hdr_len = (uint8_t)(f->link_hdr_len + r.length);
    } else if (buf == (uint8_t *)f->net_hdr) {
        /* Set the new size of the network layer-chunk */
        f->net_len = (uint8_t)(f->net_len + r.length);
    } else if (buf == (uint8_t *)f->transport_hdr) {
        /* Set the new size of the transport layer-chunk */
        f->transport_len = (uint16_t)(f->transport_len + r.length);
    } else {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    r.offset = (uint16_t)((uint16_t)(buf - f->phy_hdr) + r.offset);
    
    if (!(MEM_INSERT(f->phy_hdr, f->size, r)))
        return NULL;

    ret = (uint8_t *)(f->phy_hdr + r.offset);
    
    /* Set the new buffer size */
    f->size = (uint16_t)(f->size + r.length);
    
    /* Reangere chunk-ptrs */
    if (FRAME_REARRANGE_PTRS(f))
        return NULL;
    
    return ret;
}

static uint8_t *FRAME_BUF_PREPEND(struct sixlowpan_frame *f, uint8_t *buf, uint16_t len)
{
    struct range r = {.offset = 0, .length = len};
    return FRAME_BUF_INSERT(f, buf, r);
}

static int FRAME_BUF_DELETE(struct sixlowpan_frame *f, uint8_t *buf, struct range r, uint16_t offset)
{
    CHECK_PARAM(f);
    CHECK_PARAM(buf);
    
    if (buf == (uint8_t *)f->link_hdr) {
        /* Set the new size of the link layer-chunk */
        f->link_hdr_len = (uint8_t)(f->link_hdr_len - r.length);
    } else if (buf == (uint8_t *)f->net_hdr) {
        /* Set the new size of the network layer-chunk */
        f->net_len = (uint8_t)(f->net_len - r.length);
    } else if (buf == (uint8_t *)f->transport_hdr) {
        /* Set the new size of the transport layer-chunk */
        f->transport_len = (uint16_t)(f->transport_len - r.length);
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    r.offset = (uint16_t)((uint16_t)(buf - f->phy_hdr) + r.offset + offset);
    MEM_DELETE(f->phy_hdr, f->size, r);
    
    /* Reangere chunk-ptrs */
    if (FRAME_REARRANGE_PTRS(f))
        return -1;
    
    return 0;
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
    
    /* Parse in the FCS, Not Really Necessary */
    f->fcs = f->net_hdr + f->net_len;
    
    /* Set the device */
    f->dev = dev;
    
    /* Process the addresses-fields seperately */
    IEEE802154_process_addresses(f->link_hdr, &(f->local), &(f->peer));

    return f;
}

/* -------------------------------------------------------------------------------- */
// MARK: SIXLOWPAN

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
inline static int UNUSED sixlowpan_iid_is_derived_64(uint8_t in[8])
{
    return ((in[3] != 0xFF && in[4] != 0xFE) ? 1 : 0);
}

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

#define UDP_IS_PORT_8(p)            ((0xF0) == ((p) >> 8))
#define UDP_IS_PORT_4(p)            ((0xF0B) == ((p) >> 4))
#define UDP_ARE_PORTS_4(src, dst)   (UDP_IS_PORT_4((src)) && UDP_IS_PORT_4((dst)))
#define UINT32_4LSB(lsb)            (((uint32_t)lsb) & 0x000F)
#define UINT32_8LSB(lsb)            (((uint32_t)lsb) & 0x00FF)

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
            pan_dbg("COMPRESSED FULL\n");
            sport = (uint16_t)(sport | 0x00B0 | (uint16_t)(buf[0] >> 4));
            dport = (uint16_t)(dport | 0x00B0 | (uint16_t)(buf[0] & 0x0F));
            FRAME_BUF_PREPEND(f, f->transport_hdr, 3);
            break;
        case PORTS_COMPRESSED_DST:
            pan_dbg("COMPRESSED DST\n");
            sport = short_be(*(uint16_t *)(buf));
            dport = (uint16_t)(dport | (uint16_t)buf[2]);
            FRAME_BUF_PREPEND(f, f->transport_hdr, 1);
            break;
        case PORTS_COMPRESSED_SRC:
            pan_dbg("COMPRESSED SRC\n");
            sport = (uint16_t)(sport | (uint16_t)buf[0]);
            dport = short_be(*(uint16_t *)(buf + 1));
            FRAME_BUF_PREPEND(f, f->transport_hdr, 1);
            break;
        default:
            pan_dbg("COMPRESSED NONE\n");
            /* Do nothing */
            return;
    }
    
    pan_dbg("DECOMPRESSED SRC: %d - DST: %d\n", sport, dport);
    
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
    struct range r = {.offset = 0, .length = dispatch_info[SIXLOWPAN_NHC_UDP][INFO_HDR_LEN]};
    struct pico_ipv6_hdr *hdr = NULL;
    uint16_t *len = NULL;
    enum nhc_udp_ports ports = PORTS_COMPRESSED_NONE;
    
    _CHECK_PARAM(udp, 0xFF);
    _CHECK_PARAM(f, 0xFF);
    
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    ports = udp->ports;
    FRAME_BUF_DELETE(f, f->transport_hdr, r, 0);
    
    /* UDP is in the transport layer */
    if (ports) {
        sixlowpan_nhc_udp_ports_undo(ports, f);
    }
    
    r.offset = 4;
    r.length = 2;
    len = (uint16_t *)FRAME_BUF_INSERT(f, f->transport_hdr, r);
    *len = hdr->len;
    
    return PICO_PROTO_UDP;
}

static enum frame_status sixlowpan_nhc_udp(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    struct pico_udp_hdr *udp = NULL;
    struct sixlowpan_nhc_udp *nhc = NULL;
    
    CHECK_PARAM(f);
    
    if (!FRAME_BUF_PREPEND(f, f->transport_hdr, dispatch_info[SIXLOWPAN_NHC_UDP][INFO_HDR_LEN]))
        return FRAME_ERROR;
    
    /* Parse in the UDP header */
    udp = (struct pico_udp_hdr *)(f->transport_hdr + 1);
    nhc = (struct sixlowpan_nhc_udp *)f->transport_hdr;
    
    nhc->dispatch = 0x1E;
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
    FRAME_BUF_DELETE(f, f->transport_hdr, r, dispatch_info[SIXLOWPAN_NHC_UDP][INFO_HDR_LEN]);
    
    return FRAME_COMPRESSED_NHC;
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
    struct range r = {.offset = 0, .length = dispatch_info[SIXLOWPAN_NHC_EXT][INFO_HDR_LEN]};
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
            FRAME_BUF_DELETE(f, (uint8_t *)f->net_hdr, r, 0);
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

static enum frame_status sixlowpan_nhc_ext(enum nhc_ext_eid eid, uint8_t **buf, struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = 0};
    struct pico_ipv6_exthdr *ext = NULL;
    struct sixlowpan_nhc_ext *nhc = NULL;
    enum frame_status ret = 0;
    
    CHECK_PARAM(f);
    CHECK_PARAM(buf);
    CHECK_PARAM(*buf);
    
    /* Parse in the extension header */
    ext = (struct pico_ipv6_exthdr *)(*buf);
    nhc = (struct sixlowpan_nhc_ext *)(*buf);
    
    if (sixlowpan_nh_is_compressible(f->nxthdr)) {
        ret = FRAME_COMPRESSIBLE_NH;
        nhc->nh = NH_COMPRESSED;
    } else {
        /* If the next header isn't compressible prepend a byte for the NHC-dispatch */
        r.offset = (uint16_t)(*buf - f->net_hdr);
        r.length = dispatch_info[SIXLOWPAN_NHC_EXT][INFO_HDR_LEN];
        if (!(*buf = FRAME_BUF_INSERT(f, f->net_hdr, r)))
            return FRAME_ERROR;
        
        /* Rearrange the pointers */
        ext = (struct pico_ipv6_exthdr *)(*buf + dispatch_info[SIXLOWPAN_NHC_EXT][INFO_HDR_LEN]);
        nhc = (struct sixlowpan_nhc_ext *)*buf;
        
        ret = FRAME_COMPRESSED_NHC;
        nhc->nh = NH_COMPRESSED_NONE;
    }
    
    nhc->dispatch = 0x0E;
    nhc->eid = eid;
    
    f->nxthdr = ext->nxthdr; /* Get the next header */
    
    /* Set the pointer to the next header */
    if (EID_FRAGMENT != eid)
        *buf = ((uint8_t *)*buf) + IPV6_OPTLEN(ext->ext.destopt.len);
    else
        *buf = ((uint8_t *)*buf) + 8u;
    
    return ret;
}

static enum frame_status sixlowpan_nhc(struct sixlowpan_frame *f, uint8_t **buf)
{
    /* Check which type of next header we heave to deal with */
    switch (f->nxthdr) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
            return sixlowpan_nhc_ext(EID_HOPBYHOP, buf, f);
        case PICO_IPV6_EXTHDR_ROUTING:
            return sixlowpan_nhc_ext(EID_ROUTING, buf, f);
        case PICO_IPV6_EXTHDR_FRAG:
            return sixlowpan_nhc_ext(EID_FRAGMENT, buf, f);
        case PICO_IPV6_EXTHDR_DESTOPT:
            return sixlowpan_nhc_ext(EID_DESTOPT, buf, f);
        case PICO_PROTO_UDP:
            /* Will always in the transport layer so we can just pass the frame */
            return sixlowpan_nhc_udp(f);
        default:
            return FRAME_ERROR;
    }
}

static enum frame_status sixlowpan_nhc_compress(struct sixlowpan_frame *f)
{
    enum frame_status ret = FRAME_COMPRESSIBLE_NH;
    uint8_t *nh = NULL;
    CHECK_PARAM(f);
    
    /* First time in this function, next header is right after IPv6 header */
    nh = f->net_hdr + dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN] + PICO_SIZE_IP6HDR;
    
    while (FRAME_COMPRESSIBLE_NH == ret) {
        ret = sixlowpan_nhc(f, &nh);
    }
    return ret;
}

/* -------------------------------------------------------------------------------- */
// MARK: LOWPAN_IPHC
static int sixlowpan_iphc_am_undo(enum iphc_am am, uint8_t id, struct pico_sixlowpan_addr addr, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_ADDR_OFFSET(id), .length = IPV6_LEN_SRC};
    
    /* For now, the src-address is either fully elided or sent inline */
    if (AM_COMPRESSED_FULL == am) {
        /* Insert the Source Address-field again */
        if (!FRAME_BUF_INSERT(f, f->net_hdr, r))
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

static int sixlowpan_iphc_dam_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Check for multicast destination */
    if (MCAST_MULTICAST == iphc->mcast) {
        if (!FRAME_BUF_INSERT(f, f->net_hdr, sixlowpan_iphc_mcast_dam(iphc->dam)))
            return -1;
        hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        /* Rearrange the mcast-address again to form a proper IPv6-address */
        return sixlowpan_ipv6_derive_mcast(iphc->dam, hdr->dst.addr);
    } else {
        /* If destination address is not multicast it's, either not sent at all or 
         * fully carried in-line */
        return sixlowpan_iphc_am_undo(iphc->dam, IPV6_DESTINATION, f->local, f);
    }
    
    return 0;
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

static struct range sixlowpan_iphc_dam(struct sixlowpan_iphc *iphc, uint8_t *addr, IEEE802154_address_mode_t dam)
{
    struct range r = {.offset = 0, .length = 0};
    
    IGNORE_PARAMETER(dam);
    if (!iphc || !addr) /* Checking params */
        return r;
    
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

static struct range sixlowpan_iphc_sam(struct sixlowpan_iphc *iphc, uint8_t *addr, IEEE802154_address_mode_t sam)
{
    struct range r = {.offset = 0, .length = 0};
    IGNORE_PARAMETER(sam);
    if (!iphc || !addr) /* Checking params */
        return r;
    
    /* For now, don't add a context extension byte to IPHC-header */
    iphc->context_ext = 0x0;
    
    /* For now, use stateless compression of Source Address */
    iphc->sac = 0x0;
    
    if (pico_ipv6_is_linklocal(addr)) {
        iphc->sam = AM_COMPRESSED_FULL;
        r.offset = IPV6_OFFSET_SRC;
        r.length = IPV6_LEN_SRC;
    } else
        iphc->sam = AM_COMPRESSED_NONE;
    
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
        if (!FRAME_BUF_INSERT(f, f->net_hdr, r))
            return -1;
        
        hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        
        /* Fill in the Hop Limit-field  */
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

static struct range sixlowpan_iphc_hl(struct sixlowpan_iphc *iphc, uint8_t hl)
{
    struct range r = {.offset = 0, .length = 0};
    
    if (!iphc) /* Checking params */
        return r;
    
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

static enum frame_status sixlowpan_iphc_nh_undo(struct sixlowpan_iphc *iphc, struct sixlowpan_frame *f)
{
    struct range r = {.offset = IPV6_OFFSET_NH, .length = IPV6_LEN_NH};
    
    CHECK_PARAM(iphc);
    CHECK_PARAM(f);
    
    /* Check if Next Header is compressed */
    if (iphc->next_header) {
        /* Insert the Next Header-field again */
        if (!FRAME_BUF_INSERT(f, f->net_hdr, r))
            return FRAME_ERROR;
        
        /* Will fill in the Next Header field later on, when the Next Header is actually
         * being decompressed, but indicate that it still needs to happen */
        
        return FRAME_COMPRESSED_NHC;
    }
    
    return FRAME_NOT_COMPRESSED_NHC;
}

static struct range sixlowpan_iphc_nh(struct sixlowpan_iphc *iphc, uint8_t nh, struct sixlowpan_frame *f, enum frame_status *status)
{
    struct range r = {.offset = 0, .length = 0};
    
    _CHECK_PARAM(iphc, r);
    _CHECK_PARAM(f, r);
    _CHECK_PARAM(status, r);
    
    /* See if the next header can be compressed */
    if (sixlowpan_nh_is_compressible(nh)) {
        f->nxthdr = nh;
        iphc->next_header = NH_COMPRESSED;
        r.offset = IPV6_OFFSET_NH;
        r.length = IPV6_LEN_NH;
        *status = FRAME_COMPRESSIBLE_NH;
    } else {
        iphc->next_header = NH_COMPRESSED_NONE;
        *status = FRAME_COMPRESSED;
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
    /* Packet length is already set in f->net_len */
    hdr->len = short_be(f->net_len);
    return 0;
}

static int sixlowpan_iphc_pl_undo(struct sixlowpan_frame *f)
{
    CHECK_PARAM(f);
    /* Insert the payload-field again */
    if (!FRAME_BUF_INSERT(f, f->net_hdr, sixlowpan_iphc_pl()))
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
    if (!FRAME_BUF_INSERT(f, f->net_hdr, sixlowpan_iphc_get_range(iphc->tf)))
        return -1;
    
    /* Parse in the IPv6 header */
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    vtf = &(hdr->vtf);
    
    /* Reconstruct the original VTF-field */
    switch (iphc->tf) {
        case TF_COMPRESSED_NONE:
            /* [ EEDDDDDD | xxxxFFFF | FFFFFFFF | FFFFFFFF ] */
            *vtf = long_be(VERSION | DSCP(*vtf) | ECN(*vtf) | FL(*vtf));
            break;
        case TF_COMPRESSED_TC:
            /* [ EExxFFFF | FFFFFFFF | FFFFFFFF ] vvvvvvvv | */
            *vtf = long_be(VERSION | ~IPHC_MASK_DSCP | ECN(*vtf) | FLS(*vtf));
            break;
        case TF_COMPRESSED_FL:
            /* [ EEDDDDDD ] vvvvvvvv | vvvvvvvv | vvvvvvvv | */
            *vtf = long_be(VERSION | DSCP(*vtf) | ECN(*vtf));
            break;
        case TF_COMPRESSED_FULL:
            /* | vvvvvvvv | vvvvvvvv | vvvvvvvv | vvvvvvvv | */
            *vtf = long_be(VERSION);
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

static enum frame_status sixlowpan_iphc_compress(struct sixlowpan_frame *f)
{
    struct range deletions[IPV6_FIELDS_NUM];
    struct pico_ipv6_hdr *hdr = NULL;
    struct sixlowpan_iphc iphc;
    enum frame_status ret;
    uint8_t i = 0;
    
    CHECK_PARAM(f);
    
    /* 1. - Prepend IPHC header space */
    if (!FRAME_BUF_PREPEND(f, f->net_hdr, dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN]))
        return FRAME_ERROR;
    hdr = (struct pico_ipv6_hdr *)(f->net_hdr + dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN]);
    
    /* 2. - Fill in IPHC header */
    iphc.dispatch = 0x3;
    deletions[0] = sixlowpan_iphc_tf(&iphc, &hdr->vtf);
    deletions[1] = sixlowpan_iphc_pl();
    deletions[2] = sixlowpan_iphc_nh(&iphc, hdr->nxthdr, f, &ret);
    deletions[3] = sixlowpan_iphc_hl(&iphc, hdr->hop);
    deletions[4] = sixlowpan_iphc_sam(&iphc, hdr->src.addr, f->local._mode);
    deletions[5] = sixlowpan_iphc_dam(&iphc, hdr->dst.addr, f->peer._mode);
    
    /* 2b. - Copy the the IPHC header into the buffer */
    memcpy(f->net_hdr, (void *)&iphc, sizeof(struct sixlowpan_iphc));
    
    /* 2c. - Apply LOWPAN_NHC if the flag is set */
    if (FRAME_COMPRESSIBLE_NH == ret)
        ret = sixlowpan_nhc_compress(f);
    
    /* 3. - Elide fields in IPv6 header */
    for (i = IPV6_FIELDS_NUM; i > 0; i--) {
        if (FRAME_BUF_DELETE(f, f->net_hdr, deletions[i - 1], dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN]))
            return FRAME_ERROR;
    }

    /* 5. - Check whether packet now fits inside the frame */
    if ((IEEE802154_len(f) <= IEEE802154_MAC_MTU))
        return FRAME_FITS_COMPRESSED;
    
    return FRAME_COMPRESSED;
}

static enum frame_status sixlowpan_uncompressed(struct sixlowpan_frame *f)
{
    CHECK_PARAM(f);
    
    /* Provide space for the dispatch type */
    if (!FRAME_BUF_PREPEND(f, f->net_hdr, dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]))
        return FRAME_ERROR;
    
    /* Provide the LOWPAN_IPV6 dispatch code */
    f->net_hdr[0] = dispatch_info[SIXLOWPAN_IPV6][INFO_VAL];
    f->net_len = (uint8_t)(f->net_len + dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]);
    return FRAME_FITS;
}

static enum frame_status sixlowpan_compress(struct sixlowpan_frame *f)
{
    enum frame_status ret = FRAME_ERROR;
    CHECK_PARAM(f);
    
    /* Check whether or not the frame actually needs compression */
    if ((IEEE802154_len(f) + dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]) <= IEEE802154_MAC_MTU)
        return sixlowpan_uncompressed(f);
    
    /* Try to fit the packet with LOWPAN_IPHC */
    ret = sixlowpan_iphc_compress(f);
    if (FRAME_FITS_COMPRESSED == ret || FRAME_ERROR == ret)
        return ret;
    
    /* Indicate that the packet is compressed but still doesn't fit */
    return FRAME_COMPRESSED;
}

static enum frame_status sixlowpan_decompress_nhc(struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    union nhc_hdr *nhc = NULL;
    uint8_t d = 0;
    
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    nhc = (union nhc_hdr *)f->net_hdr + PICO_SIZE_IP6HDR;
    d = *(uint8_t *)(nhc);
    
    if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_EXT)) {
        hdr->nxthdr = sixlowpan_nhc_ext_undo((struct sixlowpan_nhc_ext *)nhc, f);
    } else if (CHECK_DISPATCH(d, SIXLOWPAN_NHC_UDP)) {
        f->net_len = PICO_SIZE_IP6HDR;
        FRAME_REARRANGE_PTRS(f);
        hdr->nxthdr = sixlowpan_nhc_udp_undo((struct sixlowpan_nhc_udp *)f->transport_hdr, f);
    } else {
        return FRAME_ERROR;
    }
    return FRAME_DECOMPRESSED;
}

static enum frame_status sixlowpan_decompress_iphc(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN]};
    struct sixlowpan_iphc *iphc = NULL;
    enum frame_status f_state;
    
    CHECK_PARAM(f);
    
    /* Provide space for a copy of the LOWPAN_IPHC-header */
    if (!(iphc = PICO_ZALLOC(sizeof(struct sixlowpan_iphc)))) {
        pico_err = PICO_ERR_ENOMEM;
        return FRAME_ERROR;
    }
    /* Parse in the LOWPAN_IPHC-header */
    memcpy(iphc, f->net_hdr, (size_t)dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN]);
    
    /* Remove the IPHC header from the buffer at once */
    FRAME_BUF_DELETE(f, f->net_hdr, r, 0);
    sixlowpan_iphc_tf_undo(iphc, f);
    sixlowpan_iphc_pl_undo(f);
    /* Make place for IPv6 Next Header field again and indicate whether or not the Next Header
     * needs to be decompressed as well, or not. */
    if (FRAME_NOT_COMPRESSED_NHC == (f_state = sixlowpan_iphc_nh_undo(iphc, f)))
        f_state = FRAME_DECOMPRESSED;
    sixlowpan_iphc_hl_undo(iphc, f);
    sixlowpan_iphc_sam_undo(iphc, f);
    sixlowpan_iphc_dam_undo(iphc, f);
    /* Recalculate the Payload Length again because it changed since ..._pl_undo() */
    sixlowpan_iphc_pl_redo(f);
    
    /* If there isn't any Next Header compression we can assume the IPv6 Header is default
     * and therefore 40 bytes in size */
    if (FRAME_DECOMPRESSED == f_state) {
        f->transport_len = (uint16_t)(f->net_len - PICO_SIZE_IP6HDR);
        f->net_len = (uint16_t)PICO_SIZE_IP6HDR;
        FRAME_REARRANGE_PTRS(f);
    } else if (FRAME_COMPRESSED_NHC == f_state) {
        f_state = sixlowpan_decompress_nhc(f);
    }
    
    /* Give the memory allocated back */
    PICO_FREE(iphc);
    
    return f_state;
}

static enum frame_status sixlowpan_decompress_ipv6(struct sixlowpan_frame *f)
{
    struct range r = {.offset = 0, .length = dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]};
    
    CHECK_PARAM(f);
    
    FRAME_BUF_DELETE(f, f->net_hdr, r, 0);
    
    return FRAME_DECOMPRESSED;
}

static enum frame_status sixlowpan_decompress(struct sixlowpan_frame *f)
{
    enum frame_status ret;
    uint8_t d = 0;
    
    CHECK_PARAM(f);
    
    /* Determine compression */
    d = f->net_hdr[0]; /* dispatch type */
    if (CHECK_DISPATCH(d, SIXLOWPAN_IPV6)) {
        return sixlowpan_decompress_ipv6(f);
    }
    else if (CHECK_DISPATCH(d, SIXLOWPAN_IPHC)) {
        if (FRAME_COMPRESSED_NHC == (ret = sixlowpan_decompress_iphc(f))) {
            ret = sixlowpan_decompress_nhc(f);
        }
        return ret;
    } else {
        return FRAME_ERROR;
    }
    
    
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

/**
 *  Translate a standard pico_frame-structure to a 6LoWPAN-specific structure.
 *  This allows the 6LoWPAN adaption layer to do much more in a more structured
 *  manner.
 *
 *  @param f struct pico_frame *, frame to translate to a 6LoWPAN-ones.
 *
 *  @return struct sixlowpan_frame *, translated 6LoWPAN-frame.
 */
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

typedef PACKED_STRUCT_DEF
{
    uint8_t size0: 3;
    uint8_t dispatch: 5;
    uint8_t size1;
    uint16_t datagram_tag;
} sixlowpan_frag1_t;

typedef PACKED_STRUCT_DEF
{
    uint8_t size0: 3;
    uint8_t dispatch: 5;
    uint8_t size1;
    uint16_t datagram_tag;
    uint8_t offset;
} sixlowpan_fragn_t;

#define SET_FRAG_SIZE(frag, size) \
        frag->size0 = (uint8_t)short_be(short_be(size) >> 0xD); \
        frag->size1 = (uint8_t)size

static int sixlowpan_frame_frag(struct sixlowpan_frame *f)
{
    struct range r = {0, .length = dispatch_info[SIXLOWPAN_FRAGN][INFO_HDR_LEN]};
    uint8_t max_psize = 0, n = 0, i = 0;
    sixlowpan_frag1_t *frag1 = NULL;
    sixlowpan_fragn_t *fragn = NULL;
    static uint16_t dtag = 0;
    uint8_t *buf = NULL;
    
    CHECK_PARAM(f);
    
    f->to_send = (uint16_t)(f->size + IEEE802154_PHY_OVERHEAD - f->link_hdr_len); /* Entire size of the payload */
    max_psize = (uint8_t)(IEEE802154_MAC_MTU - f->link_hdr_len - sizeof(sixlowpan_fragn_t));
    f->max_bytes = (uint8_t)((uint8_t)((uint8_t)max_psize / 8) * 8);
    n = (uint8_t)(f->to_send / f->max_bytes); /* Number of packets to send an entire payload */
    
    /* Prepend space for the first Fragmentation header */
    if (!FRAME_BUF_PREPEND(f, f->net_hdr, sizeof(sixlowpan_frag1_t)))
        return -1;
    frag1 = (sixlowpan_frag1_t *)f->net_hdr;
    
    /* Set the LOWPAN_FRAG1-fields */
    frag1->dispatch = 0x18;
    SET_FRAG_SIZE(frag1, f->to_send);
    frag1->datagram_tag = short_be(++dtag);
    buf = (uint8_t *)(f->net_hdr + f->max_bytes + sizeof(sixlowpan_frag1_t));
    
    /* Iterate of the network header until the end and insert fragmentation headers */
    for (i = 0; i < n; i++) {
        r.offset = (uint16_t)(buf - f->net_hdr);
        if (!(buf = FRAME_BUF_INSERT(f, f->net_hdr, r)))
            return -1;
        
        /* Set the fields of the current frag-header */
        pan_dbg("buf offset %d should be 104 + 4\n", (uint16_t)(buf - f->net_hdr));
        fragn = (sixlowpan_fragn_t *)buf;
        fragn->dispatch = 0x1C;
        SET_FRAG_SIZE(fragn, f->to_send);
        fragn->datagram_tag = short_be(dtag);
        fragn->offset = (uint8_t)((i + 1) * (f->max_bytes / 8));
        
        /* Move to next place to insert a fragmentation header */
        buf = buf + f->max_bytes + sizeof(sixlowpan_fragn_t);
    }
    
    pan_dbg("TOTAL PSIZE %d %d / MAX_BYTES %d\n", f->to_send, (f->net_len + f->transport_len), f->max_bytes);
    dbg_mem("FRAG:", f->net_hdr, (uint16_t)(f->net_len + f->transport_len));
    
    return 0;
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
        fragl = (uint8_t)(f->max_bytes + sizeof(sixlowpan_frag1_t));
        f->to_send = (uint16_t)(f->to_send - f->max_bytes);
    } else {
        /* Determine if we're at the rest or not */
        if (f->to_send < f->max_bytes) {
            fragl = (uint8_t)(f->to_send + sizeof(sixlowpan_fragn_t));
            f->to_send = (uint16_t)0;
        } else {
            fragl = (uint8_t)(f->max_bytes + sizeof(sixlowpan_fragn_t));
            f->to_send = (uint16_t)(f->to_send - f->max_bytes);
        }
    }
    
    *len = (uint8_t)(f->link_hdr_len + (uint8_t)(fragl + IEEE802154_PHY_OVERHEAD));
    pan_dbg("LEN OF FRAGMENT: %d whereof pure data %d\n", *len, fragl);
    if (!(buf = PICO_ZALLOC((size_t)(*len)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    memcpy(buf + IEEE802154_LEN_LEN, f->link_hdr, (size_t)(*len - IEEE802154_PHY_OVERHEAD));
    
    /* Remove the fragment from the frame */
    r.length = (uint16_t)fragl;
    FRAME_BUF_DELETE(f, f->net_hdr, r, 0);
    
    return buf;
}

struct stream_info
{
    struct sixlowpan_frame *f;
    struct pico_device_sixlowpan *dev;
};

static void sixlowpan_frame_tx_stream_start(pico_time now, void *arg)
{
    struct stream_info *i = NULL;
    uint8_t len = 0;
    uint8_t *buf = NULL;
    
    IGNORE_PARAMETER(now);
    CHECK_PARAM_VOID(arg);
    i = (struct stream_info *)arg;
    
    while ((buf = sixlowpan_frame_tx_next(i->f, &len))) {
        if (i->dev->radio->transmit(i->dev->radio, buf, len) > 0) {
            PICO_FREE(buf);
        } else {
            PICO_FREE(buf);
            PICO_FREE(i->f);
            PICO_FREE(i);
            return;
        }
    }
    
    /* Free the allocated frame and stream-info */
    sixlowpan_frame_destroy(i->f);
    PICO_FREE(i);
    sixlowpan_state = SIXLOWPAN_READY;
}

/* -------------------------------------------------------------------------------- */
// MARK: PICO_DEV
static int sixlowpan_send(struct pico_device *dev, void *buf, int len)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *)dev;
    struct pico_frame *f = (struct pico_frame *)buf;
    struct sixlowpan_frame *frame = NULL;
    enum frame_status s = FRAME_ERROR;
    struct stream_info *i = NULL;
    int ret = 0;
    
    /* While transmitting no frames can be passed to the 6LoWPAN-device */
    if (SIXLOWPAN_TRANSMITTING == sixlowpan_state)
        return 0;
    
    CHECK_PARAM(dev);
    CHECK_PARAM(buf);
    IGNORE_PARAMETER(len);
    
    /* Translate the pico_frame */
    if (!(frame = sixlowpan_frame_translate(f))) {
        pan_dbg("Could not translate pico_frame\n");
        return -1;
    }
    
    /* Try to compress the 6LoWPAN-frame */
    if (FRAME_COMPRESSED == (s = sixlowpan_compress(frame))) {
        /* 1. - Split up the entire compressed frame */
        if (sixlowpan_frame_frag(frame)) {
            sixlowpan_frame_destroy(frame);
            return -1;
        }
        
        if (!(i = PICO_ZALLOC(sizeof(struct stream_info)))) {
            pico_err = PICO_ERR_ENOMEM;
            sixlowpan_frame_destroy(frame);
            return -1;
        }
        
        i->f = frame;
        i->dev = sixlowpan;
        
        /* Schedule for sending */
        sixlowpan_state = SIXLOWPAN_TRANSMITTING;
        
        ret = frame->size;
        
        pico_timer_add(0, sixlowpan_frame_tx_stream_start, (void *)i);
        
        return ret;
    } else if (FRAME_ERROR == s) {
        pan_dbg("FRAME_ERROR occured during compressing!\n");
        sixlowpan_frame_destroy(frame);
        return -1;
    } else {
        ret = sixlowpan->radio->transmit(sixlowpan->radio, frame->phy_hdr, frame->size);
        sixlowpan_frame_destroy(frame);
    }
    
    /* TODO: [6LOWPAN ADAPTION LAYER] prepend BROADCASTING/MESH ROUTING */
    
    /* 1. - Whether or not the packet need to broadcasted */
    /* 2. - Whether or not the packet needs to be mesh routed */
    
    
    return ret;
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
                /* 1. Check for MESH Dispatch header */
                /* 2. Check for BROADCAST header */
                
                /* TODO: [6LOWPAN ADAPTION LAYER] unfragment */
                
                /* [IEEE802.15.4 LINK LAYER] decapsulate MAC frame to IPv6 */
                if (!(f = IEEE802154_unbuf(dev, buf, len)))
                    return loop_score;
                
                /* [6LOWPAN ADAPTION LAYER] apply decompression/defragmentation */
                if (FRAME_DECOMPRESSED != sixlowpan_decompress(f)) {
                    sixlowpan_frame_destroy(f);
                    return loop_score;
                }
                
                pico_stack_recv(dev, f->net_hdr, (uint32_t)(f->net_len + f->transport_len));
                
                /* Discard frame */
                sixlowpan_frame_destroy(f);
                
                --loop_score;
            }
        } else
            return loop_score;
	} while (loop_score > 0);
	
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

/**
 *  The radio may or may not already have had a short 16-bit address
 *  configured. If it didn't, this function allows the radio to notify the
 *  6LoWPAN layer when it did configured a short 16-bit address after the
 *  initialisation-procedure. This can be possible due to an association
 *  event while comminissioning the IEEE802.15.4 PAN.s
 *
 *  This function will call radio_t->get_addr_short in it's turn.
 *
 *  @param dev pico_device *, the 6LoWPAN pico_device-instance.
 */
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

/**
 *  Custom pico_device creation function.
 *
 *  @param radio Instance of device-driver to assign to 6LoWPAN device
 *
 *  @return Generic pico_device structure.
 */
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
