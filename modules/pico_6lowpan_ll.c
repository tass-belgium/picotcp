/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_802154.h"
#include "pico_6lowpan.h"
#include "pico_protocol.h"
#include "pico_addressing.h"
#include "pico_6lowpan_ll.h"

#ifdef PICO_SUPPORT_6LOWPAN

/*******************************************************************************
 * Macros
 ******************************************************************************/

#ifdef DEBUG_6LOWPAN
#define ll_dbg dbg
#else
#define ll_dbg(...) do {} while(0)
#endif

/*******************************************************************************
 *  CTX
 ******************************************************************************/

#ifdef PICO_6LOWPAN_IPHC_ENABLED

/* Compares if the IPv6 prefix of two IPv6 addresses match */
static int compare_prefix(uint8_t *a, uint8_t *b, int len)
{
    uint8_t bitmask = (uint8_t)(0xff >> (8 - (len % 8)));
    size_t bytes = (size_t)len / 8;
    int ret = 0;
    if ((ret = memcmp(a, b, bytes)))
        return ret;
    return (int)((a[bytes] & bitmask) - (b[bytes] & bitmask));
}

/* Compares 2 IPHC context entries */
static int compare_ctx(void *a, void *b)
{
    struct iphc_ctx *ca = (struct iphc_ctx *)a;
    struct iphc_ctx *cb = (struct iphc_ctx *)b;
    return compare_prefix(ca->prefix.addr, cb->prefix.addr, ca->size);
}

PICO_TREE_DECLARE(CTXtree, compare_ctx);

/* Searches in the context tree if there's a context entry available with the
 * prefix of the IPv6 address */
struct iphc_ctx * ctx_lookup(struct pico_ip6 addr)
{
    struct iphc_ctx test = { addr, 0, 0 };
    return pico_tree_findKey(&CTXtree, &test);
}

/* Looks up the context by ID, for decompression */
struct iphc_ctx * ctx_lookup_id(uint8_t id)
{
    struct iphc_ctx *key = NULL;
    struct pico_tree_node *i = NULL;

    pico_tree_foreach(i, &CTXtree) {
        key = i->keyValue;
        if (key && id ==key->id)
            return key;
    }
    return NULL;
}

/* Deletes a context with a certain prefix from the context tree. The ctx is
 * either found and deleted, or not found, don't care. */
void ctx_remove(struct pico_ip6 addr)
{
    struct iphc_ctx test = { addr, 0, 0}, *key = NULL;
    if ((key = pico_tree_delete(&CTXtree, &test)))
        PICO_FREE(key);
}

/* Tries to insert a new IPHC-context into the Context-tree */
int ctx_insert(struct pico_ip6 addr, uint8_t id, int size)
{
    struct iphc_ctx *new = PICO_ZALLOC(sizeof(struct iphc_ctx));
    if (new) {
        new->prefix = addr;
        new->id = id;
        new->size = size;
        if (pico_tree_insert(&CTXtree, new)) {
            PICO_FREE(new);
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

#endif

/*******************************************************************************
 *  GENERIC 6LOWPAN LINK LAYER
 ******************************************************************************/

int pico_6lowpan_ll_cmp(union pico_ll_addr *a, union pico_ll_addr *b, struct pico_device *dev)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        /* TODO: Update to pico_protocol's alloc function */
        return addr_802154_cmp(a, b);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return 0;
    }
}

struct pico_frame *pico_6lowpan_frame_alloc(struct pico_protocol *self, struct pico_device *dev, uint16_t size)
{
    struct pico_frame *f;
    IGNORE_PARAMETER(self);
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        /* TODO: Update to pico_protocol's alloc function */
        f = pico_frame_alloc(SIZE_802154_MHR_MAX + size);
        if (f) {
            f->net_hdr = f->buffer + (int)(f->buffer_len - (uint32_t)size);
            f->dev = dev;
        }
        return f;
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return NULL;
    }
}

int pico_6lowpan_ll_iid(uint8_t *iid, union pico_ll_addr *addr, struct pico_device *dev)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        addr_802154_iid(iid, addr);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return -1;
    }
    return 0;
}

int pico_6lowpan_ll_len(union pico_ll_addr *addr, struct pico_device *dev)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == dev->mode) {
        return addr_802154_len(addr);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
    return -1;
}

int pico_6lowpan_ll_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == f->dev->mode) {
        return frame_802154_push(f, src, dst);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    /* No 6LoWPAN link layer protocols are supported */
    ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
    return -1;
}

int pico_6lowpan_ll_addr(struct pico_frame *f, union pico_ll_addr *addr, int dest)
{
    struct pico_ip6 src = ((struct pico_ipv6_hdr *)f->net_hdr)->src;
    struct pico_ip6 dst = ((struct pico_ipv6_hdr *)f->net_hdr)->dst;
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == f->dev->mode) {
        *addr = addr_802154(&src, &dst, f->dev, dest);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    else {
        /* No 6LoWPAN link layer protocols are supported */
        ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
        return -1;
    }
    return 0;
}

#endif /* PICO_SUPPORT_6LOWPAN */
