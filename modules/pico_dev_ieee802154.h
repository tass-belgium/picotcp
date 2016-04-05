/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#ifndef INCLUDE_PICO_DEV_IEEE802154
#define INCLUDE_PICO_DEV_IEEE802154

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

/**
 *  To create a device 'pico_ieee802154_create(radio)' is called. A radio-
 *  structure has to be provided that complies to the structure defined in
 *  the header-file. In this method, everything is set up and initialised and
 *  finally 'sixlowpan_enable(dev)' is called to enable 6LoWPAN-communication on
 *  the device.
 */

/**
 *  Creates a picoTCP-compatible pico_device. Creates the
 *  interface between picoTCP and the device driver (radio_t).
 *
 *  @param radio Radio-instance for the interface between 802.15.4 and
 *				 picoTCP.
 *
 *  @return pico_device-instance, initialised and everything.
 */
struct pico_device *pico_dev_ieee802154_create(struct ieee_radio *radio);


#endif /* INCLUDE_PICO_DEV_IEEE802154 */
