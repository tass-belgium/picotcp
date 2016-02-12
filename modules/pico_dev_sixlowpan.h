/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/
#ifndef INCLUDE_PICO_SIXLOWPAN
#define INCLUDE_PICO_SIXLOWPAN

/* picoTCP includes */
#include "pico_device.h"
#include "pico_config.h"

// ADDRESS DEFINITIONS (IEEE802.15.4)
#define IEEE_ADDR_BCAST_SHORT       (0xFFFFu)
#define IEEE_ADDR_BCAST             {{0xFFFF}, {{0,0,0,0,0,0,0,0}}, IEEE_AM_SHORT}
#define IEEE_ADDR_ZERO              {{0x0000}, {{0,0,0,0,0,0,0,0}}, IEEE_AM_NONE}
#define PICO_SIZE_IEEE_ADDR_STR     (24)

// SIZE DEFINITIONS (IEEE802.15.4)
#define IEEE_PHY_MTU                (128u)
#define IEEE_MAC_MTU                (125u)
#define IEEE_PHY_OVERHEAD           (3u)
#define IEEE_MAC_OVERHEAD           (2u)

// FLAG DEFINITIONS (IEEE802.15.4)
#define IEEE_FALSE                  (0u)
#define IEEE_TRUE                   (1u)

// FRAME TYPE DEFINITIONS (IEEE802.15.4)
#define IEEE_FRAME_TYPE_BEACON      (0u)
#define IEEE_FRAME_TYPE_DATA        (1u)
#define IEEE_FRAME_TYPE_ACK         (2u)
#define IEEE_FRAME_TYPE_COMMAND     (3u)

// FRAME VERSION DEFINITIONS (IEEE802.15.4)
#define IEEE_FRAME_VERSION_2003     (0u)
#define IEEE_FRAME_VERSION_2006     (1u)

// SECURITY LEVEL DEFINITIONS (IEEE802.15.4)
#define IEEE_SEC_LVL_NONE           (0u)
#define IEEE_SEC_LVL_MIC_32         (1u)
#define IEEE_SEC_LVL_MIC_64         (2u)
#define IEEE_SEC_LVL_MIC_128        (3u)
#define IEEE_SEC_LVL_ENC            (4u)
#define IEEE_SEC_LVL_ENC_MIC_32     (5u)
#define IEEE_SEC_LVL_ENC_MIC_64     (6u)
#define IEEE_SEC_LVL_ENC_MIC_128    (7u)

// 6LOWPAN DEVICE MODE DEFINITIONS (6LOWPAN)
#define SIXLOWPAN_6LBR              (1u)
#define SIXLOWPAN_6LN               (0u)

// SECURITY CONTROL FIELD (IEEE802.15.4)
PACKED_STRUCT_DEF ieee_sec_cf
{
    uint8_t reserved: 3;
    uint8_t key_identifier_mode: 2;
    uint8_t security_level: 3;
};

// AUXILIARY SECURITY HEADER (IEEE802.15.4)
PACKED_STRUCT_DEF ieee_sec_hdr
{
    struct ieee_sec_cf scf;
    uint32_t frame_count;
    uint8_t key_id[0];
};

// FRAME CONTROL FIELD (IEEE802.15.4)
PACKED_STRUCT_DEF ieee_fcf
{
    uint8_t frame_type: 3;          /* Type of frame, see PICO_FRAME_TYPE_x */
    uint8_t security_enabled: 1;    /* '1' When frame is secured */
    uint8_t frame_pending: 1;       /* '1' When the sending host has more data */
    uint8_t ack_required: 1;        /* Request for an acknowledgement */
    uint8_t intra_pan: 1;           /* PAN ID's are equal, src-PAN is elided */
    uint8_t res0: 1;                /* 1 reserved bit */
    uint8_t res1: 2;                /* 2 reserved bits */
    uint8_t dam: 2;                 /* Destination AM, see PICO_ADDR_MODE_x */
    uint8_t frame_version: 2;       /* Version, see PICO_FRAME_VERSION_x */
    uint8_t sam: 2;                 /* Source AM, see PICO_ADDR_MODE_x */
};

// FRAME HEADER (IEEE802.15.4)
PACKED_STRUCT_DEF ieee_hdr
{
    struct ieee_fcf fcf;
    uint8_t seq;
    uint16_t pan;
    uint8_t addresses[0];
};

int pico_ieee_addr_to_hdr(struct ieee_hdr *hdr, struct pico_ieee_addr src, struct pico_ieee_addr dst);
struct pico_ieee_addr pico_ieee_addr_from_hdr(struct ieee_hdr *hdr, uint8_t src);

/**
 *  Generic radio-structure to provide an interface between the
 *	IEEE802.15.4-radio specific device driver and the 6LoWPAN-
 *	adaption layer.
 */
struct ieee_radio
{
	/**
	 *
	 */
	int (*transmit)(struct ieee_radio *radio, void *buf, int len);

	/**
	 *
	 */
	int (*receive)(struct ieee_radio *radio, uint8_t *buf, int len);

	/**
	 *
	 */
	int (*get_addr_ext)(struct ieee_radio *radio, uint8_t *buf);

	/**
	 *
	 */
	uint16_t (*get_pan_id)(struct ieee_radio *radio);

	/**
	 *
	 */
	uint16_t (*get_addr_short)(struct ieee_radio *radio);

	/**
	 *
	 */
	int (*set_addr_short)(struct ieee_radio *radio, uint16_t short_16);
};

int pico_ieee_addr_cmp(void *va, void *vb);

/**
 *  Indicate to the 6LoWPAN layer that a frame is succesfully transmitted
 *  TODO: Examine if this can go
 */
void pico_sixlowpan_transmitted(void);

/* **************************** */
/* *** TEMPORARY DEMO STUFF *** */
void rtable_print(void);
uint8_t sixlowpan_get_neighbours(struct pico_device *dev, uint8_t *buf);
/* **************************** */
/* **************************** */

int pico_sixlowpan_iid_is_derived_16(uint8_t *iid);

/**
 *  Hardcode the prefix of the 6LoWPAN-device. Links with addresses derived from
 *  the IEEE802.15.4-address will be added to the device correspondingly. With
 *  this function you don't have to manually derive IPv6-addresses from Link Layer-
 *  addresses. This function will do this for you.
 *
 *  @param dev    struct pico_device *, device for which you want to set
 *                the network prefix.
 *  @param prefix struct pico_ip6, new prefix to set to, will assume /64 netmask
 */
int pico_sixlowpan_set_prefix(struct pico_device *dev, struct pico_ip6 prefix);

/**
 *  The radio may or may not already have had a short 16-bit address
 *  configured. If it didn't, this function allows the radio to notify the
 *  6LoWPAN layer when it did configured a short 16-bit address after the
 *  initialisation-procedure. This can be possible due to an association
 *  event while comminissioning the IEEE802.15.4 PAN.
 *  This function will call radio_t->get_addr_short in it's turn.
 *
 *  @param dev pico_device *, the 6LoWPAN pico_device-instance.
 */
void pico_sixlowpan_short_addr_configured(struct pico_device *dev);


int pico_sixlowpan_enable_6lbr(struct pico_device *dev, struct pico_ip6 prefix);

/**
 *  Creates a picoTCP-compatible pico_device. Creates the
 *  interface between picoTCP and the device driver (radio_t).
 *
 *  @param radio Radio-instance for the interface between 802.15.4 and
 *				 picoTCP.
 *
 *  @return pico_device-instance, initialised and everything.
 */
struct pico_device *pico_sixlowpan_create(struct ieee_radio *radio);

#endif /* INCLUDE_PICO_SIXLOWPAN */
