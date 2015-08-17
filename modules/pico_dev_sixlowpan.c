/* Custom includes */
#include "pico_dev_sixlowpan.h"
#include "pico_ipv6.h"
/* --------------- */

#define IEEE802154_MAC_MTU (127)

#define IEEE802154_HDR_LEN      (20u)
#define IEEE802154_LEN_LEN      (1u)
#define IEEE802154_FCF_LEN      (2u)
#define IEEE802154_SEQ_LEN      (1u)
#define IEEE802154_PAN_LEN      (2u)
#define IEEE802154_ADDR_LEN(am) ((IEEE802154_ADDRESS_MODE_SHORT == (am)) ? ((uint8_t)2u) : \
                                ((IEEE802154_ADDRESS_MODE_EXTENDED == (am)) ? ((uint8_t)8u) : ((uint8_t)0u)))

#define IEEE802154_LEN_OFFSET(buf)      (void *)((buf) + 0)
#define IEEE802154_FCF_OFFSET(buf)      (void *)(IEEE802154_LEN_OFFSET((buf)) + IEEE802154_LEN_LEN)
#define IEEE802154_SEQ_OFFSET(buf)      (void *)(IEEE802154_FCF_OFFSET((buf)) + IEEE802154_FCF_LEN)
#define IEEE802154_DPAN_OFFSET(buf)     (void *)(IEEE802154_SEQ_OFFSET((buf)) + IEEE802154_SEQ_LEN)
#define IEEE802154_DADDR_OFFSET(buf)    (void *)(IEEE802154_DPAN_OFFSET((buf)) + IEEE802154_PAN_LEN)

static int pico_sixlowpan_devnum = 0;

/**
 *  Definition of 6LoWPAN pico_device
 */
struct pico_device_sixlowpan {
	struct pico_device dev;
	
	/* Interface between pico_device-structure & 802.15.4-device driver */
	radio_t *radio;
};

static IEEE802154_fcf_t pico_sixlowpan_fcf_create(pico_802154_frame_type_t frame_type,
                                                  pico_802154_flag_t security_enabled,
                                                  pico_802154_flag_t frame_pending,
                                                  pico_802154_flag_t ack_required,
                                                  pico_802154_flag_t intra_pan,
                                                  pico_802154_address_mode_t sam,
                                                  pico_802154_address_mode_t dam)
{
    IEEE802154_fcf_t fcf;
    
    fcf.frame_type = frame_type;
    fcf.frame_version = IEEE802154_FRAME_VERSION_2003;
    fcf.security_enabled = security_enabled;
    fcf.frame_pending = frame_pending;
    fcf.ack_required = ack_required;
    fcf.intra_pan = intra_pan;
    fcf.sam = sam;
    fcf.dam = dam;
    
    return fcf;
}

/**
 *  Calculates the size a buffer needs to be to fit in the entire 802.15.4 frame
 *
 *  @param frame Frame to calculate the buffer-size for.
 *
 *  @return len of the payload + 2 bytes for the FCS and + 1 for the length-byte
 *          in the beginning.
 */
static uint8_t pico_802154_frame_len(pico_802154_frame_t *frame)
{
    /* Start with the maximum length of the header (3 bytes) */
    uint8_t len = (uint8_t)(IEEE802154_FCF_LEN + IEEE802154_SEQ_LEN);
    
    /* Take into account the security header */
    if (frame->mhr.fcf.security_enabled) {
        /* TODO: Add the length of the auxiliary security header to the total length */
    }
    
    /* Take into account the PAN ID compression (Intra PAN) */
    if (!(frame->mhr.fcf.intra_pan))
        len = (uint8_t)(len + 2); /* Add 2 bytes to the total length */
    
    /* Take into account the addressing modes */
    len = (uint8_t)(len + IEEE802154_ADDR_LEN((frame->mhr.fcf.dam)));
    len = (uint8_t)(len + IEEE802154_ADDR_LEN((frame->mhr.fcf.sam)));
    
    /* Take the payload into account */
    len = (uint8_t)(len + frame->payload_len);
    
    /* Return len + 3 for the length byte & Frame Check Sequence */
    return (uint8_t)(len + 3);
}

static uint8_t pico_802154_hdr_len(void *buf)
{
    return 0;
}

static void *pico_sixlowpan_frame_to_buf(pico_802154_frame_t frame, int *len)
{
    uint8_t *buf = NULL, *offset = NULL;
    uint8_t plen = 0;
    
    /* Calculate the length that the buffer needs to be to fit in entire frame */
    *len = pico_802154_frame_len(&frame);
    plen = (uint8_t)(*len - 1);
    
    /* Provide space for the buffer + 2 bytes for the CRC */
    if (!(buf = PICO_ZALLOC((size_t)(*len)))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Copy the fields into the flat buffer */
    memcpy(IEEE802154_LEN_OFFSET(buf), (void *)&(plen), IEEE802154_LEN_LEN);
    memcpy(IEEE802154_FCF_OFFSET(buf), (void *)&(frame.mhr.fcf), IEEE802154_FCF_LEN);
    memcpy(IEEE802154_SEQ_OFFSET(buf), (void *)&(frame.mhr.sequence_number), IEEE802154_SEQ_LEN);
    memcpy(IEEE802154_DPAN_OFFSET(buf), (void *)&(frame.mhr.dest_pan_id), IEEE802154_PAN_LEN);
    memcpy(IEEE802154_DADDR_OFFSET(buf), (void *)(frame.mhr.dest_address), IEEE802154_ADDR_LEN(frame.mhr.fcf.dam));
    
    offset = IEEE802154_DADDR_OFFSET(buf) + IEEE802154_ADDR_LEN(frame.mhr.fcf.dam);
    if (!(frame.mhr.fcf.intra_pan)) {
        memcpy(offset, (void *)&(frame.mhr.src_pan_id), IEEE802154_PAN_LEN);
        memcpy(offset + IEEE802154_PAN_LEN, (void *)(frame.mhr.src_address), IEEE802154_ADDR_LEN(frame.mhr.fcf.sam));
        offset = offset + IEEE802154_PAN_LEN + IEEE802154_ADDR_LEN(frame.mhr.fcf.sam);
    } else {
        memcpy(offset, (void *)(frame.mhr.src_address), IEEE802154_ADDR_LEN(frame.mhr.fcf.sam));
        offset = offset + IEEE802154_ADDR_LEN(frame.mhr.fcf.sam);
    }
    
    memcpy(offset, frame.payload, frame.payload_len);
    
    return buf;
}

static void *pico_iee802154_frame(struct pico_device *dev, void *buf, int *len)
{
    /* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *)dev;
    struct pico_ipv6_hdr *header = (struct pico_ipv6_hdr *)buf;
    static uint8_t seq_number;
    pico_802154_frame_t frame;
    uint16_t sshort = 0;
    pico_802154_address_mode_t sam = 0, dam = 0;
    
    frame.mhr.sequence_number = seq_number++;
    
    /* Fill in link-layer source address */
    if ((sshort = sixlowpan->radio->get_short_16(sixlowpan->radio)) != 0xFFFF) {
        /* Use Link-layer short 16-bit address */
        sam = IEEE802154_ADDRESS_MODE_SHORT;
        frame.mhr.src_address[0] = (uint8_t)(sshort >> 8);
        frame.mhr.src_address[1] = (uint8_t)(sshort & 0xFF);
    } else {
        /* Use Link-layer EUI-64 address */
        sam = IEEE802154_ADDRESS_MODE_EXTENDED;
        sixlowpan->radio->get_EUI64(sixlowpan->radio, frame.mhr.src_address);
    }
    
    /* Fill in link-layer destination address */
    dam = IEEE802154_ADDRESS_MODE_SHORT;
    if (pico_ipv6_is_multicast(header->dst.addr)) {
        /*  RFC: IPv6 level multicast packets MUST be carroed as link-layer broadcast
         *  frame in IEEE802.15.4 networks. */
        /*  MARK: ^ The above statement is temporary, when Mesh routing is implemented
         *  link-layer destination addresses are formed as per section 9 in RFC4944 */
        frame.mhr.dest_address[0] = 0xFF;
        frame.mhr.dest_address[1] = 0xFF;
    } else if ((header->dst.addr[11] & 0xFF) && (header->dst.addr[12] & 0xFE)) {
        /* IPv6 is formed from 16-bit short address */
        frame.mhr.dest_address[0] = header->dst.addr[14];
        frame.mhr.dest_address[1] = header->dst.addr[15];
    } else {
        /* IPv6 is formed from EUI-64 address */
        dam = IEEE802154_ADDRESS_MODE_EXTENDED;
        memcpy(frame.mhr.dest_address, (void *)(header->dst.addr + 8), 8);
    }
    
    /* Fill in destination PAN ID */
    frame.mhr.dest_pan_id = sixlowpan->radio->get_pan_id(sixlowpan->radio);
    
    /* Generate the frame control field */
    frame.mhr.fcf = pico_sixlowpan_fcf_create(IEEE802154_FRAME_TYPE_DATA,   /* DATA FRAME */
                                              IEEE802154_FALSE,             /* NO LL-SECURITY */
                                              IEEE802154_FALSE,             /* SINGLE FRAME */
                                              IEEE802154_TRUE,              /* ACK REQUIRED */
                                              IEEE802154_TRUE,              /* INTRA PAN */
                                              sam,                          /* SOURCE AM */
                                              dam                           /* DEST AM */
                                              );
    
    /* Set the frame payload */
    frame.payload = (uint8_t *)buf;
    frame.payload_len = (uint8_t)*len;
    
    return pico_sixlowpan_frame_to_buf(frame, len);
}

static void *pico_iee802154_unframe(void *buf, int *len)
{
    uint8_t frame_header_len = 0;
    
    
}

static int pico_sixlowpan_send(struct pico_device *dev, void *buf, int len)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *)dev;
	
    /* TODO: [6LOWPAN ADAPTION LAYER] apply compression/fragmentation */
    
	/* [IEEE802.15.4 LINK LAYER] encapsulate in MAC frame */
    buf = pico_iee802154_frame(dev, buf, &len);
    
    /* Call the transmit-callback on this sixlowpan's specific radio-instance */
    return sixlowpan->radio->transmit(sixlowpan->radio, buf, len);
}

static int pico_sixlowpan_poll(struct pico_device *dev, int loop_score)
{
	/* Parse the pico_device structure to the internal sixlowpan-structure */
    struct pico_device_sixlowpan *sixlowpan = (struct pico_device_sixlowpan *) dev;
    uint8_t buf[IEEE802154_MAC_MTU], *frame_buf = NULL;
    int len = 0;
    
    do {
		/* Try to receive data from radio-interface */
		len = sixlowpan->radio->receive(sixlowpan->radio, buf, IEEE802154_MAC_MTU);
		if (len < 0)
			return loop_score;
		else if (len > 0) {
            /* [IEEE802.15.4 LINK LAYER] decapsulate MAC frame to IPv6 */
            //frame_buf = pico_iee802154_unframe(buf, len);
            
            /* TODO: [6LOWPAN ADAPTION LAYER] apply decompression/defragmentation */
            
			pico_stack_recv(dev, buf, (uint32_t)len);
            --loop_score;
		}
	} while (loop_score > 0);
	
    return 0;
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
    struct pico_device_sixlowpan *sixlowpan = PICO_ZALLOC(sizeof(struct pico_device_sixlowpan));
    char dev_name[MAX_DEVICE_NAME];
    uint8_t buf[8];
	
    /* Check if the structure is correctly initialised */
    if (!radio ||
        !(radio->transmit) ||
        !(radio->receive) ||
        !(radio->get_EUI64) ||
        !(radio->get_pan_id) ||
        !(radio->get_short_16) ||
        !(radio->set_short_16))
        return NULL;

	/* Try to init & register the device to picoTCP */
    radio->get_EUI64(radio, buf);
    snprintf(dev_name, MAX_DEVICE_NAME, "sixlowpan%04d", pico_sixlowpan_devnum++);
    if (0 != pico_sixlowpan_init((struct pico_device *)sixlowpan, dev_name, buf)) {
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
