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
/* --------------- */

#ifdef PICO_SUPPORT_SIXLOWPAN

#define DEBUG

#ifdef DEBUG
#define pan_dbg dbg
#else
#define pan_dbg(...) do {} while(0)
#endif

#define IEEE802154_MIN_HDR_LEN              (5u)
#define IEEE802154_MAX_HDR_LEN              (23u)
#define IEEE802154_LEN_LEN                  (1u)
#define IEEE802154_FCF_LEN                  (2u)
#define IEEE802154_SEQ_LEN                  (1u)
#define IEEE802154_PAN_LEN                  (2u)
#define IEEE802154_FCS_LEN                  (2u)

#define IEEE802154_FCF_OFFSET(buf)          ((buf))
#define IEEE802154_SEQ_OFFSET(buf)          (IEEE802154_FCF_OFFSET((buf)) + IEEE802154_FCF_LEN)
#define IEEE802154_PAN_OFFSET(buf)          (IEEE802154_SEQ_OFFSET((buf)) + IEEE802154_SEQ_LEN)
#define IEEE802154_DST_OFFSET(buf)          (IEEE802154_PAN_OFFSET((buf)) + IEEE802154_PAN_LEN)

#define IPV6_FIELDS_NUM                     (6u)

#define IPV6_SHIFT_DSCP                     (22u)
#define IPV6_SHIFT_ECN                      (20u)
#define IPV6_MASK_DSCP                      (0x3F)
#define IPV6_MASK_ECN                       (0x3)
#define IPV6_MASK_FL                        (0xFFFFF)
#define IPV6_OFFSET_LEN                     (4u)
#define IPV6_OFFSET_NH                      (6u)
#define IPV6_OFFSET_HL                      (7u)
#define IPV6_OFFSET_SRC                     (8u)
#define IPV6_OFFSET_DST                     (16u)
#define IPV6_LEN_LEN                        (2u)
#define IPV6_LEN_NH                         (1u)
#define IPV6_LEN_HL                         (1u)
#define IPV6_LEN_SRC                        (16u)
#define IPV6_LEN_DST                        (16u)

#define CHECK_PARAM(a)       if(!(a)){ \
                                pico_err = PICO_ERR_EINVAL; \
                                pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, __LINE__); \
                                return (-1); \
                             } do {} while(0)
#define CHECK_PARAM_NULL(a)  if(!(a)){ \
                                pico_err = PICO_ERR_EINVAL; \
                                pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, __LINE__); \
                                return NULL; \
                             } do {} while(0)
#define CHECK_PARAM_ZERO(a)  if(!(a)){ \
                                pico_err = PICO_ERR_EINVAL; \
                                pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, __LINE__); \
                                return (0); \
                             } do {} while(0)
#define CHECK_PARAM_VOID(a)  if(!(a)){ \
                                pico_err = PICO_ERR_EINVAL; \
                                pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, __LINE__); \
                                return; \
                             } do {} while(0)

#define IEEE802154_BCST_ADDR    (0xFFFFu)

static int sixlowpan_devnum = 0;

/**
 *  Definition of 6LoWPAN pico_device
 */
struct pico_device_sixlowpan
{
	struct pico_device dev;
	
	/* Interface between pico_device-structure & 802.15.4-device driver */
	radio_t *radio;
    
    /* Every PAN has to have a routable IPv6 prefix. */
    struct pico_ip6 pan_prefix;
};

/**
 *  Definition of a 6LoWPAN frame
 */
struct sixlowpan_frame
{
    /* Link header buffer */
    uint8_t *link_hdr;
    uint8_t link_hdr_len;
    
    /* IPv6 header buffer */
    uint8_t *net_hdr;
    uint8_t net_len;
    
    /* Transport layer buffer */
    uint8_t *transport_hdr;
    uint16_t transport_len;
    
    /* Protocol over IP */
    uint8_t proto;
    
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
 *  Status
 */
typedef enum
{
    FRAME_ERROR = -1,
    FRAME_FITS,
    FRAME_FITS_COMPRESSED,
    FRAME_COMPRESSED,
    FRAME_FRAGMENTED,
    FRAME_PENDING,
    FRAME_SENT,
    FRAME_ACKED
} frame_status_t;

/**
 *  Possible 6LoWPAN dispatch type definitions
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
    SIWLOWPAN_FRAGN,    /* Subsequent fragmentation header */
    SIXLOWPAN_NESC,     /* Replacement ESC dispatch [RFC6282] */
    SIXLOWPAN_IPHC,     /* LOWPAN_IPHC compressed IPv6 */
    SIXLOWPAN_NHC_EXT,  /* LOWPAN_NHC compressed IPv6 EXTension Header */
    SIXLOWPAN_NHC_UDP   /* LOWPAN_NHC compressed UDP header */
};

/**
 *  Contains information about a specific 6LoWPAN dispatch type;
 *
 *  VAL:        Actual dispatch-type value itself, to compare against
 *  LEN:        Length (in bits) of the dispatch-type value, how many
 *              bits to take into account.
 *  SHIFT:      Times to shift right before values can be compared, is
 *              actually 8 - LEN.
 *  HDR_LEN:    Full 6LoWPAN header length (in bytes) for the specific
 *              dispatch type, including dispatch type itself.
 *              0xFF means variable length.
 */
const uint8_t const dispatch_info[12][4] =
{
    //  {VAL, LEN, SHIFT, HDR_LEN}
    {0x00, 0x02, 0x06, 0x00}, /* NALP */
    {0x41, 0x08, 0x00, 0x01}, /* IPV6 */
    {0x42, 0x08, 0x00, 0x02}, /* HC1 */
    {0x50, 0x08, 0x00, 0x02}, /* BC0 */
    {0x7F, 0x08, 0x00, 0xFF}, /* ESC */
    {0x80, 0x02, 0x06, 0xFF}, /* MESH */
    {0xC0, 0x05, 0x03, 0x04}, /* FRAG1 */
    {0xE0, 0x05, 0x03, 0x05}, /* FRAGN */
    {0x80, 0x08, 0x00, 0xFF}, /* NESC */
    {0x60, 0x03, 0x05, 0x02}, /* IPHC */
    {0xE0, 0x03, 0x05, 0xFF}, /* NHC_EXT */
    {0xF0, 0x05, 0x03, 0x01}  /* NHC_UDP */
};

/**
 *  Possible information type definitions
 */
enum dispatch_info_type
{
    INFO_VAL,
    INFO_LEN,
    INFO_SHIFT,
    INFO_HDR_LEN
};

typedef union
{
    struct IPHC {
        uint8_t dispatch: 3;
        uint8_t tf: 2;
        uint8_t next_header: 1;
        uint8_t hop_limit: 2;
        uint8_t context_ext: 1;
        uint8_t sac: 1;
        uint8_t sam: 2;
        uint8_t mcast: 1;
        uint8_t dac: 1;
        uint8_t dam: 2;
    } iphc;
    uint8_t components[2];
} sixlowpan_iphc_t;

typedef struct
{
    uint8_t offset;
    uint8_t length;
} range_t;

/* -------------------------------------------------------------------------------- */
// MARK: MEMORY
static void *buf_prepend(void *buf, size_t len, size_t pre_len)
{
    void *new = NULL;
    CHECK_PARAM_NULL(buf);
    
    if (!(new = PICO_ZALLOC((len + pre_len))))
        return new;
    
    memmove(new + pre_len, buf, len);
    PICO_FREE(buf);
    
    return new;
}
#define MEM_PREPEND(buf, len, pre_len) (buf)=buf_prepend((buf),(len),(pre_len))

static uint8_t buf_delete(void *buf, uint8_t len, range_t r)
{
    uint16_t rend = (uint16_t)(r.offset + r.length);
    CHECK_PARAM_ZERO(buf);
    
    if (!rend || r.offset > len || rend > len)
        return len;
    
    memmove(buf + r.offset, buf + rend, (size_t)((buf + len) - (buf + rend)));
    
    return len - r.length;
}
#define MEM_DELETE(buf, len, range) (len)=buf_delete((buf),(len),(range))

/* -------------------------------------------------------------------------------- */
// MARK: IEEE802.15.4

inline static void IEEE802154_EUI64_SE(uint8_t EUI64[8])
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
        case IEEE802154_ADDRESS_MODE_SHORT:
            len = 2;
            break;
        case IEEE802154_ADDRESS_MODE_EXTENDED:
            len = 8;
        default:
            len = 0;
            break;
    }
    return len;
}

static inline uint8_t IEEE802154_hdr_len(struct sixlowpan_frame *f)
{
    CHECK_PARAM_ZERO(f);
    
    f->link_hdr_len = (uint8_t)(IEEE802154_MIN_HDR_LEN +
                                IEEE802154_ADDR_LEN(f->peer._mode) +
                                IEEE802154_ADDR_LEN(f->dev->sixlowpan->_mode));
    
    /* TODO: Add Auxiliary Security Header */
    
    return f->link_hdr_len;
}

static inline uint8_t IEEE802154_len(struct sixlowpan_frame *f)
{
    CHECK_PARAM_ZERO(f);
    
    return (uint8_t)(IEEE802154_hdr_len(f) + f->net_len + f->transport_len);
}

/**
 *  Creates a Frame Control Field-instance with all the field configured
 *
 *  @param frame_type       See IEEE802154_frame_type_t.
 *  @param security_enabled See IEEE802154_flag_t.
 *  @param frame_pending    See IEEE802154_flag_t.
 *  @param ack_required     See IEEE802154_flag_t.
 *  @param intra_pan        See IEEE802154_flag_t.
 *  @param sam              See IEEE802154_address_mode_t.
 *  @param dam              See IEEE802154_address_mode_t.
 *
 *  @return Instance of IEEE802154_fcf_t.
 */
static IEEE802154_fcf_t IEEE802154_fcf_create(IEEE802154_frame_type_t frame_type,
                                              IEEE802154_flag_t security_enabled,
                                              IEEE802154_flag_t frame_pending,
                                              IEEE802154_flag_t ack_required,
                                              IEEE802154_flag_t intra_pan,
                                              IEEE802154_address_mode_t sam,
                                              IEEE802154_address_mode_t dam)
{
    IEEE802154_fcf_t fcf;
    
    fcf.fcf.frame_type = frame_type;
    fcf.fcf.frame_version = IEEE802154_FRAME_VERSION_2003;
    fcf.fcf.security_enabled = security_enabled;
    fcf.fcf.frame_pending = frame_pending;
    fcf.fcf.ack_required = ack_required;
    fcf.fcf.intra_pan = intra_pan;
    
    /* Set adressing mode to SHORT when address has both addresses */
    if (sam == IEEE802154_ADDRESS_MODE_BOTH)
        fcf.fcf.sam = IEEE802154_ADDRESS_MODE_SHORT;
    else
        fcf.fcf.sam = sam;
    
    /* Set adressing mode to SHORT when address has both addresses */
    if (dam == IEEE802154_ADDRESS_MODE_BOTH)
        fcf.fcf.dam = IEEE802154_ADDRESS_MODE_SHORT;
    else
        fcf.fcf.dam = dam;
    
    return fcf;
}

/**
 *  Converts the sixlowpan_frame-structure to a flat memory-buffer 
 *  containing the packet to send to the radio.
 *
 *  @param f   struct sixlowpan_frame *, frame to convert
 *  @param len uint8_t *, pointer to variable that gets filled with len of created buf
 *
 *  @return uint8_t *, buffer containing the frame
 */
static uint8_t *IEEE802154_frame(struct sixlowpan_frame *f, uint8_t *len)
{
    uint8_t *buf = NULL;
    CHECK_PARAM_NULL(f);
    CHECK_PARAM_NULL(len);
    
    *len = (uint8_t)(IEEE802154_len(f) + 3u);
    
    if (!(buf = PICO_ZALLOC(*len))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    memcpy(buf, len, IEEE802154_LEN_LEN);
    memcpy(buf + 1, f->link_hdr, f->link_hdr_len);
    memcpy(buf + f->link_hdr_len + 1, f->net_hdr, f->net_len);
    memcpy(buf + f->link_hdr_len + f->net_len + 1, f->transport_hdr, f->transport_len);
    
    return buf;
}

/* -------------------------------------------------------------------------------- */
// MARK: SIXLOWPAN

/**
 *  Copies a 6LoWPAN address to a flat buffer space.
 *
 *  @param d      void *, destination-pointer to buffer to copy address to. 
 *                Needs to be big enough to store the entire address, defined by
 *                addr.mode. If addr.mode is IEEE802154_ADDRESS_MODE_BOTH, the short-
 *                address will be copied in.
 *  @param addr   struct pico_sixlowpan_addr, address to copy.
 *  @param offset uint8_t, offset to add to 'd' for where to copy the address.
 *
 *  @return 0 When copying went OK, smt. else when it didn't.
 */
static int sixlowpan_addr_copy_flat(void *d,
                                         struct pico_sixlowpan_addr addr,
                                         uint8_t offset)
{
    CHECK_PARAM(d);
    
    if (addr._mode == IEEE802154_ADDRESS_MODE_SHORT ||
        addr._mode == IEEE802154_ADDRESS_MODE_BOTH) {
        memcpy(d + offset, &addr._short.addr, PICO_SIZE_SIXLOWPAN_SHORT);
    } else if (addr._mode == IEEE802154_ADDRESS_MODE_EXTENDED) {
        memcpy(d + offset, addr._ext.addr, PICO_SIZE_SIXLOWPAN_EXT);
    } else {
        return -1;
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
static int sixlowpan_link_provide(struct sixlowpan_frame *f)
{
    struct pico_device_sixlowpan *slp = NULL;
    /* STATIC SEQUENCE NUMBER */
    static uint16_t seq = 0;
    IEEE802154_fcf_t fcf;
    uint16_t pan = 0;
    uint8_t dlen = 0;
    
    CHECK_PARAM(f);
    
    /* Get some frame parameters */
    slp = (struct pico_device_sixlowpan *)(f->dev);
    pan = slp->radio->get_pan_id(slp->radio);
    dlen = IEEE802154_ADDR_LEN(f->peer._mode);
    
    /* Generate a Frame Control Field */
    fcf = IEEE802154_fcf_create(IEEE802154_FRAME_TYPE_DATA,
                                IEEE802154_FALSE,
                                IEEE802154_FALSE,
                                IEEE802154_FALSE,
                                IEEE802154_TRUE,
                                f->local._mode,
                                f->peer._mode);
    
    /* Provide space for the IEEE802154 header */
    IEEE802154_hdr_len(f);
    if (!(f->link_hdr = PICO_ZALLOC(f->link_hdr_len))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    
    /* Copy all the parameters in the flat link-layer buffer of the frame */
    memcpy(IEEE802154_FCF_OFFSET(f->link_hdr), &fcf, IEEE802154_FCF_LEN);
    memcpy(IEEE802154_SEQ_OFFSET(f->link_hdr), &seq, IEEE802154_SEQ_LEN);
    memcpy(IEEE802154_PAN_OFFSET(f->link_hdr), &pan, IEEE802154_PAN_LEN);
    
    /* Copy in dst- and src- link layer addresses */
    sixlowpan_addr_copy_flat(IEEE802154_DST_OFFSET(f->link_hdr), f->peer, 0);
    sixlowpan_addr_copy_flat(IEEE802154_DST_OFFSET(f->link_hdr), f->local, dlen);
    
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
static int sixlowpan_prepare(struct sixlowpan_frame *f, struct pico_frame *pf)
{
    int ret = 0;
    CHECK_PARAM(f);
    CHECK_PARAM(pf);
    
    /* COPY TRANSPORT PAYLOAD FROM PICO_FRAME */
    f->transport_len = (uint16_t)(pf->len - pf->net_len);
    if (!(f->transport_hdr = PICO_ZALLOC((size_t)f->transport_len))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    memcpy(f->transport_hdr, pf->transport_hdr, f->transport_len);
    pan_dbg("[SIXLOWPAN]$ transport_len: %d\n", f->transport_len);
    
    /* COPY NETWORK HEADER FROM PICO_FRAME */
    f->net_len = (uint8_t)pf->net_len;
    if (!(f->net_hdr = PICO_ZALLOC((size_t)f->net_len))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    memcpy(f->net_hdr, pf->net_hdr, f->net_len);
    pan_dbg("[SIXLOWPAN]$ net_len: %d\n", f->net_len);
    
    /* PROVIDE LINK LAYER INFORMATION */
    ret = sixlowpan_link_provide(f);
    pan_dbg("[SIXLOWPAN]$ link_hdr_len: %d\n", f->link_hdr_len);
    
    return ret;
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
static int sixlowpan_nd_derive(struct pico_frame *f,
                               struct pico_sixlowpan_addr *l)
{
    struct pico_sixlowpan_addr *neighbor = NULL;
    CHECK_PARAM(f);
    CHECK_PARAM(l);
    
    /* Discover neighbor link address using 6LoWPAN ND for dst address */
    if ((neighbor = pico_ipv6_get_sixlowpan_neighbor(f))) {
        /* If discovered neighbour has a Short address, use it */
        if (neighbor->_short.addr != 0xFFFF) {
            l->_mode = IEEE802154_ADDRESS_MODE_SHORT;
            l->_short.addr = neighbor->_short.addr;
        } else {
            /* Otherwise use the 64-bit extended address */
            l->_mode = IEEE802154_ADDRESS_MODE_EXTENDED;
            memcpy(l->_ext.addr, neighbor->_ext.addr, PICO_SIZE_SIXLOWPAN_EXT);
        }
        return 0;
    }
    
    return -1;
}

/**
 *  Derive a 6LoWPAN mcast link layer address from a mcast IPv6 address
 *
 *  @param l  pico_sixlowpan_addr *, gets filled with multicast link addr.
 *  @param ip struct pico_ip6 *, contains the multicast IPv6-address.
 *
 *  @return 0 when derivation was a success, smt. else when it was not.
 */
static int sixlowpan_mcast_derive(struct pico_sixlowpan_addr *l,
                                       struct pico_ip6 *ip)
{
    /* For now, ignore IP */
    IGNORE_PARAMETER(ip);
    CHECK_PARAM(l);
    
    /*  RFC: IPv6 level multicast packets MUST be carried as link-layer broadcast
     *  frame in IEEE802.15.4 networks. */
    l->_mode = IEEE802154_ADDRESS_MODE_SHORT;
    l->_short.addr = 0xFFFF;
    
    return 0;
}

/**
 *  Derive a 6LoWPAN link layer address from an IPv6-address.
 *
 *  @param l  struct pico_sixlowpan_addr *, gets filled with the derived addr.
 *  @param ip struct pico_ip6 *, contains the IPv6-address.
 *
 *  @return 0 on succes, smt. else otherwise.
 */
static int sixlowpan_addr_derive(struct pico_sixlowpan_addr *l,
                                      struct pico_ip6 *ip)
{
    CHECK_PARAM(ip);
    CHECK_PARAM(l);
    
    /* Check if the IP is derived from a 16-bit short address */
    if ((ip->addr[11] & 0xFF) && (ip->addr[12] & 0xFE)) {
        /* IPv6 is formed from 16-bit short address */
        l->_mode = IEEE802154_ADDRESS_MODE_SHORT;
        l->_short.addr = (uint16_t)(((uint16_t)ip->addr[14]) << 8);
        l->_short.addr = (uint16_t)(l->_short.addr | ip->addr[15]);
    } else {
        /* IPv6 is formed from EUI-64 address */
        l->_mode = IEEE802154_ADDRESS_MODE_EXTENDED;
        memcpy(l->_ext.addr, (void *)(ip->addr + 8), PICO_SIZE_SIXLOWPAN_EXT);
    }

    return 0;
}

/**
 *  Determines the link-layer destination address.
 *
 *  @param f   struct pico_frame *, to send to destination.
 *  @param dst struct pico_ip6, destination IPv6 address of the pico_frame.
 *  @param l   struct pico_sixlowpan_addr *, to fill with the link-layer 
 *             destination-address.
 *
 *  @return 0 when the link-layer dst is properly determined, something else otherwise.
 */
static int sixlowpan_link_dst(struct pico_frame *f,
                                   struct pico_ip6 *dst,
                                   struct pico_sixlowpan_addr *l)
{
    CHECK_PARAM(f);
    CHECK_PARAM(dst);
    
    if (pico_ipv6_is_multicast(dst->addr)) {
        /* Derive link layer address from IPv6 Multicast address */
        return sixlowpan_mcast_derive(l, dst);
    } else if (pico_ipv6_is_linklocal(dst->addr)) {
        /* Derive link layer address from IPv6 Link Local address */
        return sixlowpan_addr_derive(l, dst);
    } else {
        /* Resolve unicast link layer address using 6LoWPAN-ND */
        return sixlowpan_nd_derive(f, l);
    }
    
    return 0;
}

/**
 *  Destroys 6LoWPAN-frame
 *
 *  @param f struct pico_frame, frame instance to destroy
 */
static void sixlowpan_frame_destroy(struct sixlowpan_frame *f)
{
    if (!f)
        return;
    
    if (f->link_hdr)
        PICO_FREE(f->link_hdr);
    
    if (f->net_hdr)
        PICO_FREE(f->net_hdr);
    
    if (f->transport_hdr)
        PICO_FREE(f->transport_hdr);
    
    PICO_FREE(f);
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
static struct sixlowpan_frame *sixlowpan_translate(struct pico_frame *f)
{
    struct sixlowpan_frame *frame = NULL;
    struct pico_ipv6_hdr *hdr = NULL;
    
    CHECK_PARAM_NULL(f);
    
    /* Parse in the IPv6 header from the pico_frame */
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    
    /* Provide space for the 6LoWPAN frame */
    if (!(frame = PICO_ZALLOC(sizeof(struct sixlowpan_frame)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    frame->dev = f->dev;
    frame->proto = f->proto;
    frame->local = *(f->dev->sixlowpan); /* Set the LL-address of the local host */
    
    /* Determine the link-layer address of the destination */
    if (sixlowpan_link_dst(f, &(hdr->dst), &(frame->peer)) < 0) {
        pico_ipv6_nd_postpone(f);
        sixlowpan_frame_destroy(frame);
        return NULL;
    }
    
    /* Prepare seperate buffers for compressing */
    if (sixlowpan_prepare(frame, f)) {
        sixlowpan_frame_destroy(frame);
        return NULL;
    }

    return frame;
}

static frame_status_t sixlowpan_uncompressed(struct sixlowpan_frame *f)
{
    CHECK_PARAM(f);

    /* Provide space for the dispatch type */
    MEM_PREPEND(f->net_hdr, f->net_len, dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]);
    if (!f->net_hdr)
        return FRAME_ERROR;
    
    /* Provide the LOWPAN_IPV6 dispatch code */
    f->net_hdr[0] = dispatch_info[SIXLOWPAN_IPV6][INFO_VAL];
    f->net_len = (uint8_t)(f->net_len + dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]);
    return FRAME_FITS;
}

static frame_status_t sixlowpan_compress_nhc(struct sixlowpan_frame *f)
{
    CHECK_PARAM(f);
    
    return FRAME_COMPRESSED;
}

static range_t sixlowpan_iphc_dam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE802154_address_mode_t dam)
{
    range_t r = {.offset = 0, .length = 0};
    
    IGNORE_PARAMETER(dam);
    if (!iphc || !addr) /* Checking params */
        return r;
    
    /* For now, use stateless compression of Source Address */
    iphc->iphc.dac = 0x1;
    
    if (pico_ipv6_is_linklocal(addr)) {
        iphc->iphc.dam = 0x3;
        r.offset = IPV6_OFFSET_SRC;
        r.length = IPV6_LEN_SRC;
    } else if (pico_ipv6_is_multicast(addr)) {
        iphc->iphc.mcast = 0x1;
        if (addr[1] == 0x02 && addr[14] == 0x00) {
            iphc->iphc.dam = 0x3;
            r.offset = IPV6_OFFSET_DST + 1;
            r.length = IPV6_LEN_DST - 1;
            addr[0] = addr[15];
        } else if (addr[12] == 0x00) {
            iphc->iphc.dam = 0x2;
            r.offset = IPV6_OFFSET_DST + 4;
            r.length = IPV6_LEN_DST - 4;
            addr[0] = addr[1];
            addr[1] = addr[13];
            addr[2] = addr[14];
            addr[3] = addr[15];
        } else if (addr[10] == 0x00) {
            iphc->iphc.dam = 0x1;
            r.offset = IPV6_OFFSET_DST + 6;
            r.length = IPV6_LEN_DST - 6;
            addr[0] = addr[1];
            addr[1] = addr[11];
            addr[2] = addr[12];
            addr[3] = addr[13];
            addr[4] = addr[14];
            addr[3] = addr[15];
        } else {
            iphc->iphc.dam = 0x0;
        }
    } else {
        iphc->iphc.dam = 0x0;
    }
    
    return r;
}

static range_t sixlowpan_iphc_sam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE802154_address_mode_t sam)
{
    range_t r = {.offset = 0, .length = 0};
    
    IGNORE_PARAMETER(sam);
    if (!iphc || !addr) /* Checking params */
        return r;
    
    /* For now, don't add a context extension byte to IPHC-header */
    iphc->iphc.context_ext = 0x0;
    
    /* For now, use stateless compression of Source Address */
    iphc->iphc.sac = 0x1;
    
    if (pico_ipv6_is_linklocal(addr)) {
        iphc->iphc.sam = 0x3;
        r.offset = IPV6_OFFSET_SRC;
        r.length = IPV6_LEN_SRC;
    } else
        iphc->iphc.sam = 0x0;
    
    return r;
}

static range_t sixlowpan_iphc_hl(sixlowpan_iphc_t *iphc, uint8_t hl)
{
    range_t r = {.offset = 0, .length = 0};
    
    if (!iphc) /* Checking params */
        return r;
    
    r.offset = IPV6_OFFSET_HL;
    r.length = IPV6_LEN_HL;
    
    if (1 == hl) {
        iphc->iphc.hop_limit = 0x1;
    } else if (64 == hl) {
        iphc->iphc.hop_limit = 0x2;
    } else if (255 == hl) {
        iphc->iphc.hop_limit = 0x3;
    } else {
        iphc->iphc.hop_limit = 0x1;
        r.offset = 0;
        r.length = 0;
    }
    
    return r;
}

static range_t sixlowpan_iphc_nh(sixlowpan_iphc_t *iphc, uint8_t nh)
{
    range_t r = {.offset = 0, .length = 0};
    
    if (!iphc) /* Checking params */
        return r;
    
    if (PICO_IPV6_EXTHDR_HOPBYHOP == nh ||
        PICO_IPV6_EXTHDR_DESTOPT == nh ||
        PICO_IPV6_EXTHDR_ROUTING == nh ||
        PICO_IPV6_EXTHDR_FRAG == nh ||
        PICO_PROTO_UDP) {
//        iphc->iphc.next_header = 0x1;
//        r.offset = IPV6_OFFSET_NH;
//        r.length = IPV6_LEN_NH;
    }
    
    return r;
}

static range_t sixlowpan_iphc_tf(sixlowpan_iphc_t *iphc, uint32_t *vtf)
{
    range_t r = {.offset = 0, .length = 0};
    uint32_t ecn = 0, dscp = 0, fl = 0;
    
    if (!iphc || !vtf) /* Checking params */
        return r;
    
    /* Get seperate values of the vtf-field */
    dscp = ((*vtf) >> IPV6_SHIFT_DSCP) & IPV6_MASK_DSCP;
    ecn = ((*vtf) >> IPV6_SHIFT_ECN) & IPV6_MASK_ECN;
    fl = ((*vtf) & IPV6_MASK_FL);
    
    if (!dscp && !ecn && !fl)
    {
        /* | vvvvvvvv | vvvvvvvv | vvvvvvvv | vvvvvvvv | */
        iphc->iphc.tf = 0x3;
        r.offset = 0;
        r.length = 4;
    } else if (!dscp && (fl || ecn)) {
        /* [ EExxFFFF | FFFFFFFF | FFFFFFFF ] vvvvvvvv | */
        *vtf = (ecn << 30) | (fl << 8);
        iphc->iphc.tf = 0x1;
        r.offset = 0;
        r.length = 4;
    } else if (!fl && (ecn || dscp))  {
        /* [ EEDDDDDD ] vvvvvvvv | vvvvvvvv | vvvvvvvv | */
        *vtf = (ecn << 30) | (dscp << 24);
        iphc->iphc.tf = 0x2;
        r.offset = 0;
        r.length = 4;
    } else {
        /* [ EEDDDDDD | FFFFFFFF | FFFFFFFF | FFFFFFFF ] */
        *vtf = (ecn << 30) | (dscp << 24) | fl;
        iphc->iphc.tf = 0x0;
    }
    
    return r;
}

static frame_status_t sixlowpan_compress_iphc(struct sixlowpan_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    sixlowpan_iphc_t iphc;
    range_t deletions[IPV6_FIELDS_NUM];
    uint8_t i = 0;
    CHECK_PARAM(f);
    
    /* 1. - Prepend IPHC header space */
    MEM_PREPEND(f->net_hdr, f->net_len, dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN]);
    if (!f->net_hdr)
        return FRAME_ERROR;
    hdr = (struct pico_ipv6_hdr *)(f->net_hdr + dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN]);
    
    /* 2. - Fill in IPHC header */
    iphc.iphc.dispatch = 0x2;
    deletions[0] = sixlowpan_iphc_tf(&iphc, &hdr->vtf);
    deletions[1].offset = 4;
    deletions[1].length = 2;
    deletions[2] = sixlowpan_iphc_nh(&iphc, hdr->nxthdr);
    deletions[3] = sixlowpan_iphc_hl(&iphc, hdr->hop);
    deletions[4] = sixlowpan_iphc_sam(&iphc, hdr->src.addr, f->local._mode);
    deletions[5] = sixlowpan_iphc_dam(&iphc, hdr->dst.addr, f->peer._mode);
    
    /* 3. - Elide fields in IPv6 header */
    for (i = IPV6_FIELDS_NUM; i > 0; i--)
        MEM_DELETE(hdr, f->net_len, deletions[i - 1]);
    
    /* Compensate for prepending first */
    f->net_len = f->net_len + dispatch_info[SIXLOWPAN_IPHC][INFO_HDR_LEN];
    
    /* 4. - Check whether packet now fits inside the frame */
    if ((IEEE802154_len(f) + dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]) <= IEEE802154_MAC_MTU)
        return FRAME_FITS_COMPRESSED;
    
    return FRAME_COMPRESSED;
}

static frame_status_t sixlowpan_compress(struct sixlowpan_frame *f)
{
    frame_status_t ret = FRAME_ERROR;
    CHECK_PARAM(f);
    
    /* Check whether or not the frame actually needs compression */
    //if ((IEEE802154_len(f) + dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]) <= IEEE802154_MAC_MTU)
        //return sixlowpan_uncompressed(f);
    
    /* First try to fit the packet with LOWPAN_IPHC */
    ret = sixlowpan_compress_iphc(f);
    if (FRAME_FITS_COMPRESSED == ret || FRAME_ERROR == ret)
        return ret;
    
    /* If that failed, try with LOWPAN_NHC */
    ret = sixlowpan_compress_nhc(f);
    if (FRAME_FITS_COMPRESSED == ret || FRAME_ERROR == ret)
        return ret;
    
    /* Indicate that the packet is compressed but still doesn't fit */
    return FRAME_COMPRESSED;
}

static int sixlowpan_send(struct pico_device *dev, void *buf, int len)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *)dev;
    struct pico_frame *f = (struct pico_frame *)buf;
    struct sixlowpan_frame *frame = NULL;
    frame_status_t s = FRAME_ERROR;
    uint8_t *payload = NULL, plen = 0;
    
    CHECK_PARAM(dev);
    CHECK_PARAM(buf);
    IGNORE_PARAMETER(len);
    
    /* Translate the pico_frame */
    frame = sixlowpan_translate(f);
    
    /* Try to compress the 6LoWPAN-frame */
    if (FRAME_FITS != (s = sixlowpan_compress(frame))) {
        if (FRAME_ERROR == s) return -1;
        
        /* TODO: [6LOWPAN ADAPTION LAYER] prepend FRAG HEADER */
        
        /* 1. - Split up the entire compressed frame */
        /* 2. - Schedule for sending*/
        
    }
    
    /* TODO: [6LOWPAN ADAPTION LAYER] prepend BROADCASTING/MESH ROUTING */
    
    /* 1. - Whether or not the packet need to broadcasted */
    /* 2. - Whether or not the packet needs to be mesh routed */
    
	/* [IEEE802.15.4 LINK LAYER] encapsulate in MAC frame */
    payload = IEEE802154_frame(frame, &plen);
    
    /* Call the transmit-callback on this sixlowpan's specific radio-instance */
    return sixlowpan->radio->transmit(sixlowpan->radio, payload, plen);
}

static int sixlowpan_poll(struct pico_device *dev, int loop_score)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *) dev;
    radio_t *radio = sixlowpan->radio;
    uint8_t buf[IEEE802154_PHY_MTU];
    uint8_t len = 0;
    
    do {
        if (RADIO_ERR_NOERR == radio->receive(radio, buf)) {
            if ((len = buf[0]) > 0) {
                /* [IEEE802.15.4 LINK LAYER] decapsulate MAC frame to IPv6 */
                //frame = IEEE802154_buf_to_frame(buf, (uint8_t)len);
                
                /* TODO: [6LOWPAN ADAPTION LAYER] apply decompression/defragmentation */
                
                pico_stack_recv(dev, buf, (uint32_t)len);
                --loop_score;
            }
        } else
            return loop_score;
	} while (loop_score > 0);
	
    return loop_score;
}

/* -------------------------------------------------------------------------------- */
// MARK: API

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
        if (0xFFFF != dev->sixlowpan->_short.addr) {
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
    if (0xFFFF != slp._short.addr)
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
