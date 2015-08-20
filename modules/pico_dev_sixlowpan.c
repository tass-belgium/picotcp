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

/* ---- DEBUG ---- */
//#define pan_dbg(...) do {} while(0)
#define pan_dbg dbg

#define IEEE802154_MIN_HDR_LEN  (5u)
#define IEEE802154_MAX_HDR_LEN  (23u)
#define IEEE802154_FCS_LEN      (2u)
#define IEEE802154_LEN_LEN      (1u)
#define IEEE802154_FCF_LEN      (2u)
#define IEEE802154_SEQ_LEN      (1u)
#define IEEE802154_PAN_LEN      (2u)

/* CONDITIONING */
#define CHECK_PARAM(a, b)       if(!(a)){ \
                                    pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, (b)); \
                                    return (-1); \
                                } do {} while(0)
#define CHECK_PARAM_NULL(a, b)  if(!(a)){ \
                                    pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, (b)); \
                                    return NULL; \
                                } do {} while(0)
#define CHECK_PARAM_ZERO(a, b)  if(!(a)){ \
                                    pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, (b)); \
                                    return (0); \
                                } do {} while(0)
#define CHECK_PARAM_VOID(a, b)  if(!(a)){ \
                                    pan_dbg("[SIXLOWPAN]$ %s: %d\n", __FUNCTION__, (b)); \
                                    return void; \
                                } do {} while(0)

#define IEEE802154_BCST_ADDR    (0xFFFFu)

static int pico_sixlowpan_devnum = 0;

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
    /* Buffer for incoming packets */
    uint8_t *buffer;
    uint8_t buffer_len;
    
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
     *  address when receiving
     */
    struct pico_sixlowpan_addr peer;
};

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

/* -------------------------------------------------------------------------------------- */
// MARK: BEGIN OF IEEE802.15.4-layer

inline static void IEEE802154_EUI64_SE(uint8_t EUI64[8])
{
    uint8_t i = 0, temp = 0;
    
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
    CHECK_PARAM_ZERO(f, __LINE__);
    
    f->link_hdr_len = (uint8_t)(IEEE802154_MIN_HDR_LEN + IEEE802154_ADDR_LEN(f->peer._mode) + IEEE802154_ADDR_LEN(f->dev->sixlowpan->_mode));
    
    /* TODO: Add Auxiliary Security Header */
    
    return f->link_hdr_len;
}

static inline uint8_t IEEE802154_len(struct sixlowpan_frame *f)
{
    CHECK_PARAM_ZERO(f, __LINE__);
    
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

static int IEEE802154_frame(struct sixlowpan_frame *f)
{
    f->buffer_len = (uint8_t)(IEEE802154_len(f) + 3u);
    
    if (!(f->buffer = PICO_ZALLOC(f->buffer_len))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    
    memcpy(f->buffer, &(f->buffer_len), IEEE802154_LEN_LEN);
    memcpy(f->buffer + 1, f->link_hdr, f->link_hdr_len);
    memcpy(f->buffer + f->link_hdr_len + 1, f->net_hdr, f->net_len);
    memcpy(f->buffer + f->link_hdr_len + f->net_len + 1, f->transport_hdr, f->transport_len);
    
    return 0;
}

// MARK: END OF IEEE802.15.4-layer
/* -------------------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------------------- */
// MARK: BEGIN OF SIXLOWPAN-layer

/**
 *  Copies a 6LoWPAN address to a flat buffer space.
 *
 *  @param d    void *, destination-pointer to buffer to copy address to. Needs to be big enough
 *              to store the entire address, defined by addr.mode. If addr.mode is 
 *              IEEE802154_ADDRESS_MODE_BOTH, the short-address will be copied in.
 *  @param addr struct pico_sixlowpan_addr, address to copy.
 *
 *  @return 0 When copying went OK, smt. else when it didn't.
 */
static int pico_sixlowpan_addr_copy_flat(void *d, struct pico_sixlowpan_addr addr)
{
    if (addr._mode == IEEE802154_ADDRESS_MODE_SHORT || addr._mode == IEEE802154_ADDRESS_MODE_BOTH) {
        memcpy(d, (void *)&(addr._short.addr), PICO_SIZE_SIXLOWPAN_SHORT);
    } else if (addr._mode == IEEE802154_ADDRESS_MODE_EXTENDED) {
        memcpy(d, addr._ext.addr, PICO_SIZE_SIXLOWPAN_EXT);
    } else {
        return -1;
    }
    return 0;
}

static int pico_sixlowpan_link_prepare(struct sixlowpan_frame *f)
{
    struct pico_device_sixlowpan *slp = (struct pico_device_sixlowpan *)f->dev;
    static uint16_t sequence_number = 0;
    IEEE802154_fcf_t fcf;
    uint16_t pan_id;
    
    /* Provide space for the IEEE802154 header */
    IEEE802154_hdr_len(f);
    if (!(f->link_hdr = PICO_ZALLOC(f->link_hdr_len))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    
    pan_dbg("[SIXLOWPAN]$ link_hdr_len: %d\n", f->link_hdr_len);
    
    /* Generate a Frame Control Field */
    fcf = IEEE802154_fcf_create(IEEE802154_FRAME_TYPE_DATA,
                                IEEE802154_FALSE,
                                IEEE802154_FALSE,
                                IEEE802154_FALSE,
                                IEEE802154_TRUE,
                                f->dev->sixlowpan->_mode,
                                f->peer._mode);
    /* Get the pan ID */
    pan_id = slp->radio->get_pan_id(slp->radio);
    
    memcpy(f->link_hdr, (void *)&fcf, IEEE802154_FCF_LEN);
    memcpy(f->link_hdr + 2, (void *)&sequence_number, IEEE802154_SEQ_LEN);
    memcpy(f->link_hdr + 3, (void *)&pan_id, IEEE802154_PAN_LEN);
    pico_sixlowpan_addr_copy_flat(f->link_hdr + 5, f->peer);
    pico_sixlowpan_addr_copy_flat(f->link_hdr + IEEE802154_ADDR_LEN(f->peer._mode), *(f->dev->sixlowpan));
    
    sequence_number++;
    
    return 0;
}

static int pico_sixlowpan_net_prepare(struct sixlowpan_frame *f, struct pico_frame *pf)
{
    /* Provide space for net_hdr */
    f->net_len = (uint8_t)pf->net_len; /* Initial size of net_hdr-buffer */
    
    if ((uint16_t)(IEEE802154_len(f) + 1) <= IEEE802154_MAC_MTU) {
        f->net_len++;
        if (!(f->net_hdr = PICO_ZALLOC((size_t)f->net_len))) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
        memcpy(f->net_hdr + 1, pf->net_hdr, pf->net_len);
        memcpy(f->net_hdr, &dispatch_info[SIXLOWPAN_IPV6][INFO_VAL], dispatch_info[SIXLOWPAN_IPV6][INFO_HDR_LEN]);
    } else {
        if (!(f->net_hdr = PICO_ZALLOC((size_t)f->net_len))) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
        /* COPY NETWORK HEADER FROM PICO_FRAME */
        memcpy(f->net_hdr, pf->net_hdr, f->net_len);
    }
    pan_dbg("[SIXLOWPAN]$ net_len: %d\n", f->net_len);
    
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
static int pico_sixlowpan_prepare(struct sixlowpan_frame *f, struct pico_frame *pf)
{
    CHECK_PARAM(f, __LINE__);
    CHECK_PARAM(pf, __LINE__);
    
    /* Provide space for transport_hdr */
    f->transport_len = (uint16_t)(pf->len - pf->net_len);
    if (!(f->transport_hdr = PICO_ZALLOC((size_t)f->transport_len))) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    /* COPY TRANSPORT PAYLOAD FROM PICO_FRAME */
    memcpy(f->transport_hdr, pf->transport_hdr, f->transport_len);
    pan_dbg("[SIXLOWPAN]$ transport_len: %d\n", f->transport_len);
    
    if (pico_sixlowpan_net_prepare(f, pf))
        return -1;

    return pico_sixlowpan_link_prepare(f);
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
static int pico_sixlowpan_nd_dst(struct pico_frame *f,
                                 struct pico_sixlowpan_addr *l)
{
    struct pico_sixlowpan_addr *neighbor = NULL;
    
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
static int pico_sixlowpan_mcast_derive(struct pico_sixlowpan_addr *l,
                                       struct pico_ip6 *ip)
{
    /* For now, ignore IP */
    IGNORE_PARAMETER(ip);
    
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
static int pico_sixlowpan_addr_derive(struct pico_sixlowpan_addr *l,
                                      struct pico_ip6 *ip)
{
    CHECK_PARAM(ip, __LINE__);
    CHECK_PARAM(l, __LINE__);
    
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
 *  @param f  struct pico_frame *, to send to destination.
 *  @param ip struct pico_ip6, destination IPv6 address of the pico_frame.
 *  @param l  struct pico_sixlowpan_addr *, to fill with the link-layer destination-address.
 *
 *  @return 0 when the link-layer dst is properly determined, something else otherwise.
 */
static int pico_sixlowpan_link_dst(struct pico_frame *f,
                                   struct pico_ip6 *ip,
                                   struct pico_sixlowpan_addr *l)
{
    CHECK_PARAM(f, __LINE__);
    CHECK_PARAM(ip, __LINE__);
    
    if (pico_ipv6_is_multicast(ip->addr)) {
        /* Derive link layer address from IPv6 Multicast address */
        return pico_sixlowpan_mcast_derive(l, ip);
    } else if (pico_ipv6_is_linklocal(ip->addr)) {
        /* Derive link layer address from IPv6 Link Local address */
        return pico_sixlowpan_addr_derive(l, ip);
    } else {
        /* Resolve unicast link layer address using 6LoWPAN-ND */
        return pico_sixlowpan_nd_dst(f, l);
    }
    
    return 0;
}

/**
 *  Destroys 6LoWPAN-frame
 *
 *  @param f struct pico_frame, frame instance to destroy
 */
static void pico_sixlowpan_frame_destroy(struct sixlowpan_frame *f)
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

static struct sixlowpan_frame *pico_sixlowpan_translate(struct pico_frame *f)
{
    struct sixlowpan_frame *frame = NULL;
    struct pico_ipv6_hdr *hdr = NULL;
    
    CHECK_PARAM_NULL(f, __LINE__);
    
    /* Parse in the IPv6 header from the pico_frame */
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    
    /* Provide space for the 6LoWPAN frame */
    if (!(frame = PICO_ZALLOC(sizeof(struct sixlowpan_frame)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    frame->dev = f->dev;
    frame->proto = f->proto;
    
    /* Determine the link-layer address of the destination */
    if (pico_sixlowpan_link_dst(f, &(hdr->dst), &(frame->peer)) < 0) {
        pico_ipv6_nd_postpone(f);
        pico_sixlowpan_frame_destroy(frame);
        return NULL;
    }
    
    /* Prepare seperate buffers for compressing */
    if (pico_sixlowpan_prepare(frame, f)) {
        pico_sixlowpan_frame_destroy(frame);
        return NULL;
    }
    
    /* See if compression is needed */
    if (IEEE802154_len(frame) <= IEEE802154_MAC_MTU) {
        IEEE802154_frame(frame);
        return frame;
    }
    
    /* TODO: apply compression */
    return frame;
}

static int pico_sixlowpan_send(struct pico_device *dev, void *buf, int len)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *)dev;
    struct pico_frame *f = (struct pico_frame *)buf;
    struct sixlowpan_frame *frame = NULL;
    
    IGNORE_PARAMETER(len);
    CHECK_PARAM(dev, __LINE__);
    CHECK_PARAM(buf, __LINE__);
    
    frame = pico_sixlowpan_translate(f);
    
    /* TODO: [6LOWPAN ADAPTION LAYER] prepend IPHC and NHC */
    
    /* 1. - prepend IPHC header whether or not */
    /* 2. - fill in IPHC header */
    /* 3. - elide fields in IPv6 header */
    
    /* TODO: [6LOWPAN ADAPTION LAYER] prepend FRAG HEADER */
    
    /* 1. - Split up the entire compressed frame */
    /* 2. - Schedule for sending*/
    
    /* TODO: [6LOWPAN ADAPTION LAYER] prepend BROADCASTING/MESH ROUTING */
    
    /* 1. - Whether or not the packet need to broadcasted */
    /* 2. - Whether or not the packet needs to be mesh routed */
    
	/* [IEEE802.15.4 LINK LAYER] encapsulate in MAC frame */
    //buf = IEEE802154_frame(dev, buf, &len);
    
    /* Call the transmit-callback on this sixlowpan's specific radio-instance */
    return sixlowpan->radio->transmit(sixlowpan->radio, frame->buffer, frame->buffer_len);
}

static int pico_sixlowpan_poll(struct pico_device *dev, int loop_score)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *) dev;
    uint8_t buf[IEEE802154_PHY_MTU];
    int len = 0;
    
    do {
		/* Try to receive data from radio-interface */
        if ((len = sixlowpan->radio->receive(sixlowpan->radio, buf, IEEE802154_PHY_MTU)) < 0) {
			return loop_score;
        } else if (len > 0) {
            /* [IEEE802.15.4 LINK LAYER] decapsulate MAC frame to IPv6 */
            //frame = IEEE802154_buf_to_frame(buf, (uint8_t)len);
            
            /* TODO: [6LOWPAN ADAPTION LAYER] apply decompression/defragmentation */
            
			pico_stack_recv(dev, buf, (uint32_t)len);
            --loop_score;
		}
	} while (loop_score > 0);
	
    return loop_score;
}

// MARK: END OF SIXLOWPAN-layer
/* -------------------------------------------------------------------------------------- */

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
    
    CHECK_PARAM_NULL(radio, __LINE__);

    if (!(sixlowpan = PICO_ZALLOC(sizeof(struct pico_device_sixlowpan))))
        return NULL;
    
    /* Generat pico_sixlowpan_addr */
    radio->get_addr_ext(radio, slp._ext.addr);
    slp._short.addr = radio->get_addr_short(radio);
    slp._mode = IEEE802154_ADDRESS_MODE_EXTENDED;
    if (0xFFFF != slp._short.addr)
        slp._mode = IEEE802154_ADDRESS_MODE_BOTH;
    
	/* Try to init & register the device to picoTCP */
    snprintf(dev_name, MAX_DEVICE_NAME, "sixlowpan%04d", pico_sixlowpan_devnum++);
    if (0 != pico_sixlowpan_init((struct pico_device *)sixlowpan, dev_name, slp)) {
        dbg("Device init failed.\n");
        return NULL;
    }
	
    /* Set the device-parameters*/
    sixlowpan->dev.overhead = 0;
    sixlowpan->dev.send = pico_sixlowpan_send;
    sixlowpan->dev.poll = pico_sixlowpan_poll;
    
    /* Assign the radio-instance to the pico_device-instance */
    sixlowpan->radio = radio;
	
	/* Cast internal 6LoWPAN-structure to picoTCP-device structure */
    return (struct pico_device *)sixlowpan;
}
#endif /* PICO_SUPPORT_SIXLOWPAN */
