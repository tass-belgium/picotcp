/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights
 reserved.  See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#ifndef INCLUDE_PICO_6LOWPAN_LL
#define INCLUDE_PICO_6LOWPAN_LL

#include "pico_addressing.h"
#include "pico_protocol.h"
#include "pico_device.h"
#include "pico_config.h"
#include "pico_frame.h"

/*******************************************************************************
 *  CTX
 ******************************************************************************/

#ifdef PICO_6LOWPAN_IPHC_ENABLED

struct iphc_ctx
{
    struct pico_ip6 prefix;
    uint8_t id;
    int size;
};

struct iphc_ctx * ctx_lookup(struct pico_ip6 addr);
struct iphc_ctx * ctx_lookup_id(uint8_t id);
void ctx_remove(struct pico_ip6 addr);
int ctx_insert(struct pico_ip6 addr, uint8_t id, int size);

#endif

/******************************************************************************
 * Public functions
 ******************************************************************************/

int pico_6lowpan_ll_len(union pico_ll_addr *addr, struct pico_device *dev);
int pico_6lowpan_ll_iid(uint8_t *iid, union pico_ll_addr *addr, struct pico_device *dev);
int pico_6lowpan_ll_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst);
int pico_6lowpan_ll_addr(struct pico_frame *f, union pico_ll_addr *addr, int dst);
int pico_6lowpan_ll_cmp(union pico_ll_addr *a, union pico_ll_addr *b, struct pico_device *dev);
struct pico_frame *pico_6lowpan_frame_alloc(struct pico_protocol *self, struct pico_device *dev, uint16_t size);

#endif /* INCLUDE_PICO_6LOWPAN_LL */
