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
 * Type definitions
 ******************************************************************************/

#ifdef PICO_6LOWPAN_IPHC_ENABLED

/*******************************************************************************
 *  CTX
 ******************************************************************************/

#define PICO_IPHC_CTX_COMPRESS (0x01u)

struct iphc_ctx
{
    struct pico_ip6 prefix;
    uint8_t id;
    uint8_t size;
    pico_time lifetime;
    uint8_t flags;
    struct pico_device *dev;
};

struct iphc_ctx * ctx_lookup(struct pico_ip6 addr);
struct iphc_ctx * ctx_lookup_id(uint8_t id);
void ctx_update(struct pico_ip6 addr, uint8_t id, uint8_t size, pico_time lifetime, uint8_t flags, struct pico_device *dev);

#endif

/******************************************************************************
 * Public variables
 ******************************************************************************/

extern struct pico_protocol pico_proto_6lowpan_ll;

/******************************************************************************
 * Public functions
 ******************************************************************************/

void pico_6lowpan_ll_init(void);

int pico_6lowpan_ll_len(union pico_ll_addr *addr, struct pico_device *dev);
int pico_6lowpan_ll_iid(uint8_t *iid, union pico_ll_addr *addr, struct pico_device *dev);
int pico_6lowpan_ll_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst);
int pico_6lowpan_ll_pull(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst);
int pico_6lowpan_ll_addr(struct pico_frame *f, union pico_ll_addr *addr, int dst);
int pico_6lowpan_ll_cmp(union pico_ll_addr *a, union pico_ll_addr *b, struct pico_device *dev);
struct pico_frame *pico_6lowpan_frame_alloc(struct pico_protocol *self, struct pico_device *dev, uint16_t size);
union pico_ll_addr *frame_6lowpan_ll_store_addr(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst);

#endif /* INCLUDE_PICO_6LOWPAN_LL */
