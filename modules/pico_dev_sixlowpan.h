#ifndef INCLUDE_PICO_SIXLOWPAN
#define INCLUDE_PICO_SIXLOWPAN

/* picoTCP includes */
#include "pico_device.h"
#include "pico_stack.h"

/**
 *  FRAME TYPE DEFINITIONS (IEEE802.15.4)
 */
typedef enum
{
    IEEE802154_FRAME_TYPE_BEACON,
    IEEE802154_FRAME_TYPE_DATA,
    IEEE802154_FRAME_TYPE_ACKNOWLEDGEMENT,
    IEEE802154_FRAME_TYPE_COMMAND
} pico_802154_frame_type_t;

/**
 *  FCF FLAG VALUE DEFINITIONS (IEEE802.15.4)
 */
typedef enum
{
    IEEE802154_FALSE,
    IEEE802154_TRUE
} pico_802154_flag_t;

/**
 *  ADDRESS MODE DEFINITIONS (IEEE802.15.4)
 */
typedef enum
{
    IEEE802154_ADDRESS_MODE_NONE,
    IEEE802154_ADDRESS_MODE_RESERVED,
    IEEE802154_ADDRESS_MODE_SHORT,
    IEEE802154_ADDRESS_MODE_EXTENDED
} pico_802154_address_mode_t;

/**
 *  FRAME VERSION DEFINITIONS (IEEE802.15.4)
 */
typedef enum
{
    IEEE802154_FRAME_VERSION_2003,
    IEEE802154_FRAME_VERSION_2006
} pico_802154_frame_version_t;

/**
 *  SECURITY LEVEL DEFINITIONS (IEEE802.15.4)
 */
typedef enum
{
    IEEE802154_SECURITY_LVL_NONE,
    IEEE802154_SECURITY_LVL_MIC_32,
    IEEE802154_SECURITY_LVL_MIC_64,
    IEEE802154_SECURITY_LVL_MIC_128,
    IEEE802154_SECURITY_LVL_ENC,
    IEEE802154_SECURITY_LVL_ENC_MIC_32,
    IEEE802154_SECURITY_LVL_ENC_MIC_64,
    IEEE802154_SECURITY_LVL_ENC_MIC_128
} pico_802154_security_level_t;

/**
 *  SECURITY CONTROL FIELD (IEEE802154)
 */
typedef PACKED_STRUCT_DEF
{
    uint8_t reserved: 3;
    uint8_t key_identifier_mode: 2;
    uint8_t security_level: 3;
}
IEEE802154_scf_t;

/**
 *  AUXILIARY SECURITY HEADER (IEEE802.15.4)
 */
typedef struct
{
    IEEE802154_scf_t scf;
    uint8_t frame_counter[4];
    uint8_t key_identifier[9];
}
IEEE802154_security_header_t;

/**
 *  FRAME CONTROL FIELD (IEEE802.15.4)
 */
typedef PACKED_STRUCT_DEF
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
}
IEEE802154_fcf_t;

/**
 *  FRAME HEADER (IEEE802.15.4)
 */
typedef struct
{
	IEEE802154_fcf_t fcf;           /* Frame Control Field */
    uint8_t sequence_number;        /* Sequence Number, for ACK */
    uint16_t dest_pan_id;           /* PAN ID of recipient (BRCST = 0xFFFF) */
	uint8_t dest_address[8];        /* Destination Link Layer address (0/2/8) */
	uint16_t src_pan_id;            /* PAN ID of source */
	uint8_t src_address[8];         /* Source Link Layer address (0/2/8) */
}
IEEE802154_frame_header_t;

/**
 *  FRAME (IEEE802.15.4)
 */
typedef struct
{
	IEEE802154_frame_header_t       mhr;
	IEEE802154_security_header_t    sh;
	uint8_t                         payload_len;
	uint8_t                         *payload;
}
pico_802154_frame_t;

/**
 *  RADIO DRIVER RETURN CODES (DRIVER)
 */
typedef enum
{
	RADIO_ERR_NOERR = 0,
	RADIO_ERR_EINVAL,
	RADIO_ERR_ENOMEM,
	RADIO_ERR_ENOCONN
}
radio_rcode_t;

/**
 *  Generic radio-structure to provide an interface between the 
 *	IEEE802.15.4-radio specific device driver and the 6LoWPAN-
 *	adaption layer.
 */
typedef struct RADIO
{
	/**
	 *
	 */
	radio_rcode_t (*transmit)(struct RADIO *radio, void *buf, int len);
	
	/**
	 *
	 */
	int (*receive)(struct RADIO *radio, void *buf, int len);
	
	/**
	 *
	 */
	radio_rcode_t (*get_EUI64)(struct RADIO *radio, uint8_t buf[8]);
	
	/**
	 *
	 */
	uint16_t (*get_pan_id)(struct RADIO *radio);
	
	/**
	 *
	 */
	uint16_t (*get_short_16)(struct RADIO *radio);
	
	/**
	 *
	 */
	radio_rcode_t (*set_short_16)(struct RADIO *radio, uint16_t short_16);
}
radio_t;

/**
 *  Creates a picoTCP-compatible pico_device. Creates the
 *  interface between picoTCP and the device driver (radio_t).
 *
 *  @param radio Radio-instance for the interface between 802.15.4 and
 *				 picoTCP.
 *
 *  @return pico_device-instance, initialised and everything.
 */
struct pico_device *pico_sixlowpan_create(radio_t *radio);

#endif /* INCLUDE_PICO_SIXLOWPAN */