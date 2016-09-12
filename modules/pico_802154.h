/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/
#ifndef INCLUDE_PICO_802154
#define INCLUDE_PICO_802154

#include "pico_device.h"
#include "pico_config.h"

/*******************************************************************************
 * Size definitions
 ******************************************************************************/

#define MTU_802154_PHY                  (128u)
#define MTU_802154_MAC                  (125u) // 127 - Frame Check Sequence

#define SIZE_802154_MHR_MIN             (5u)
#define SIZE_802154_MHR_MAX             (23u)
#define SIZE_802154_FCS                 (2u)
#define SIZE_802154_LEN                 (1u)
#define SIZE_802154_PAN                 (2u)

/*******************************************************************************
 * Structure definitions
 ******************************************************************************/

PACKED_STRUCT_DEF pico_802154_hdr
{
    uint16_t fcf;
    uint8_t seq;
    uint16_t pan_id;
};

/*******************************************************************************
 * Public functions
 ******************************************************************************/

union pico_ll_addr addr_802154(struct pico_ip6 *src, struct pico_ip6 *dst, struct pico_device *dev, int dest);
uint8_t pico_802154_estimator(struct pico_frame *f, struct pico_802154 *src, struct pico_802154 *dst);
int pico_802154_process_out(struct pico_frame *f, struct pico_802154 *src, struct pico_802154 *dst);
int pico_802154_process_in(struct pico_frame *f, struct pico_802154 *src, struct pico_802154 *dst);
int addr_802154_iid(uint8_t iid[8], union pico_ll_addr *addr);
int addr_802154_len(union pico_ll_addr *addr);
int addr_802154_cmp(union pico_ll_addr *a, union pico_ll_addr *b);

#endif /* INCLUDE_PICO_802154 */
