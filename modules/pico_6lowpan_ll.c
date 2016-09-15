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
 * Constants
 ******************************************************************************/

/* Lifetime check interval */
#define ONE_MINUTE  ((pico_time)(1000 * 60))

/* Number of extensions */
#define NUM_LL_EXTENSIONS       (2)

/* Possible actions to perform on a received frame */
#define FRAME_6LOWPAN_LL_RELEASE    (-1)
#define FRAME_6LOWPAN_LL_DISCARD    (-2)

/*******************************************************************************
 * Type definitions
 ******************************************************************************/

typedef struct extension {
    int (*estimate)(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst);
    int (*out)(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst);
    int (*in)(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst);
} extension_t;

/*******************************************************************************
 * Global Variables
 ******************************************************************************/

static struct pico_queue pico_6lowpan_ll_in = {
    0
};
static struct pico_queue pico_6lowpan_ll_out = {
    0
};

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

/* Tries to insert a new IPHC-context into the Context-tree */
static int ctx_insert(struct pico_ip6 addr, uint8_t id, uint8_t size, pico_time lifetime, uint8_t flags, struct pico_device *dev)
{
    struct iphc_ctx *new = PICO_ZALLOC(sizeof(struct iphc_ctx));
    if (new) {
        new->lifetime = lifetime;
        new->prefix = addr;
        new->flags = flags;
        new->size = size;
        new->dev = dev;
        new->id = id;
        if (pico_tree_insert(&CTXtree, new)) {
            PICO_FREE(new);
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

/* Function to update context table from 6LoWPAN Neighbor Discovery */
void ctx_update(struct pico_ip6 addr, uint8_t id, uint8_t size, pico_time lifetime, uint8_t flags, struct pico_device *dev)
{
    struct iphc_ctx *entry = ctx_lookup_id(id);
    if (entry && dev == entry->dev) {
        if (!lifetime) {
            pico_tree_delete(&CTXtree, entry);
            PICO_FREE(entry);
        }
        entry->prefix = addr;
        entry->size = size;
        entry->lifetime = lifetime;
        entry->flags = flags;
    } else {
        /* We don't care if it failed */
        (void)ctx_insert(addr, id, size, lifetime, flags, dev);
    }
}

/* Check whether or not particular contexts are expired and remove them if so. Contexts
 * are reconfirmed before they're lifetime expires */
static void ctx_lifetime_check(pico_time now, void *arg)
{
    struct pico_tree_node *i = NULL, *next = NULL;
    struct pico_ipv6_route *gw = NULL;
    struct iphc_ctx *key = NULL;
    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(arg);

    pico_tree_foreach_safe(i, &CTXtree, next) {
        if (i && i->keyValue) {
            key = i->keyValue;
            key->lifetime--;
            if (!key->lifetime) {
                pico_tree_delete(&CTXtree, key);
                PICO_FREE(key);
            } else if (key->lifetime == 5) {
                /* RFC6775: The host SHOULD unicast one or more RSs to the router well before the
                 * shortest of the, Router Lifetime, PIO lifetimes and the lifetime of the 6COs. */
                while ((gw = pico_ipv6_gateway_by_dev_next(gw->link->dev, gw))) {
                    pico_6lp_nd_start_solicitating(pico_ipv6_linklocal_get(key->dev), gw);
                }
            }
        }
    }

    (void)pico_timer_add(ONE_MINUTE, ctx_lifetime_check, NULL);
}

#endif

/*******************************************************************************
 *  MESH-UNDER ROUTING LAYER
 ******************************************************************************/

/* XXX: Extensible processing function for outgoing frames. Here, the mesh header
 * for a Mesh-Under topology can be prepended and the link layer source and
 * destination addresses can be updated */
static int
ll_mesh_header_process_in(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    IGNORE_PARAMETER(f);
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);
    return 0;
}

/* XXX: Extensible processing function for outgoing frames. Here, the mesh header
 * for a Mesh-Under topology can be prepended and the link layer source and
 * destination addresses can be updated */
static int
ll_mesh_header_process_out(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    IGNORE_PARAMETER(f);
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);
    return 0;
}

/* XXX: Extensible function that estimates the size of the mesh header to be
 * prepended based on the frame, the source and destination link layer address */
static int
ll_mesh_header_estimator(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    IGNORE_PARAMETER(f);
    IGNORE_PARAMETER(src);
    IGNORE_PARAMETER(dst);
    return 0;
}

/*******************************************************************************
 *  GENERIC 6LOWPAN LINK LAYER
 ******************************************************************************/

static int
ll_mac_header_process_in(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == f->dev->mode) {
        return pico_802154_process_in(f, &src->pan, &dst->pan);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
    return -1;
}

static int
ll_mac_header_process_out(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == f->dev->mode) {
        return pico_802154_process_out(f, &src->pan, &dst->pan);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
    return -1;
}

static int
ll_mac_header_estimator(struct pico_frame *f, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    if (0) {}
#if defined (PICO_SUPPORT_802154)
    else if (LL_MODE_IEEE802154 == f->dev->mode) {
        return pico_802154_estimator(f, &src->pan, &dst->pan);
    }
#elif defined (PICO_SUPPORT_FOO)
    /* XXX: Here's where we can support other link layer protocols to allow
     * general 6LoWPAN-over-foo transmission link support */
#endif
    ll_dbg("%s: FAILURE: link layer mode of device not supported.\n", __func__);
    return -1;
}

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

/* Stores the addresses derived from the network addresses inside the frame
 * so they're available and the same when they are processed further for TX */
union pico_ll_addr *frame_6lowpan_ll_store_addr(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    union pico_ll_addr **addr_p = NULL, *addr = NULL;
    uint16_t needed = (uint16_t)sizeof(union pico_ll_addr *);
    uint16_t headroom = (uint16_t)(f->net_hdr - f->buffer);
    uint32_t grow = 0;
    int ret = 0;

    /* Check if there's enough headroom available to store a pointer to the
     * heap allocated addresses */
    if (headroom < needed) {
        grow = (uint32_t)(needed - headroom);
        ret = pico_frame_grow_head(f, (uint32_t)(f->buffer_len + grow));
        if (ret) {
            pico_frame_discard(f);
            return NULL;
        }
    }

    /* Allocate room for both addresses on the heap */
    addr = (union pico_ll_addr *)PICO_ZALLOC(sizeof(union pico_ll_addr) << 1);
    if (addr) {
        addr[0] = src; // Store source on the heap
        addr[1] = dst; // Store destin on the heap

        f->datalink_hdr = f->net_hdr - needed;
        addr_p = (union pico_ll_addr **)f->datalink_hdr;
        *addr_p = addr; // Store pointer to address on the heap in the datalink_hdr
        return addr; // Return pointer to addresses on the heap
    }
    return NULL;
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

/*******************************************************************************
 *  6LOWPAN LINK LAYER PROTOCOL
 ******************************************************************************/

const extension_t exts[] = {
    {ll_mesh_header_estimator, ll_mesh_header_process_out, ll_mesh_header_process_in},
    {ll_mac_header_estimator, ll_mac_header_process_out, ll_mac_header_process_in},
};

static int
pico_6lowpan_ll_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    union pico_ll_addr *addr = *(union pico_ll_addr **)f->datalink_hdr;
    union pico_ll_addr src = addr[0], dst = addr[1];
    uint32_t datalink_len = 0;
    int ret = 0, i = 0;
    IGNORE_PARAMETER(self);
    PICO_FREE(addr); // Free addresses stored on the heap

    /* Storage of addresses isn't needed anymore, restore link_hdr to former
     * location, so processing functions can easily seek back */
    f->datalink_hdr = f->net_hdr;

    /* Call each of the outgoing processing functions */
    for (i = 0; i < NUM_LL_EXTENSIONS; i++) {
        ret = exts[i].out(f, &src, &dst);
        if (ret < 0) {
            /* Processing failed, no way to recover, discard frame */
            pico_frame_discard(f);
            return -1;
        }
        datalink_len = (uint32_t)(datalink_len + (uint32_t)ret);
    }

    /* Frame is ready for sending to the device driver */
    f->start = f->datalink_hdr;
    f->len = (uint32_t)(f->len + datalink_len);
    return (int)(pico_sendto_dev(f) <= 0);
}

static int
pico_6lowpan_ll_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    union pico_ll_addr src, dst;
    int i = 0, ret = 0;
    uint32_t len = 0;
    IGNORE_PARAMETER(self);

    /* net_hdr is the pointer that is dynamically updated by the incoming
     * processing functions to always point to right after a particular
     * header, whether it's MAC, MESH, LL_SEC, ... eventually net_hdr will
     * point to 6LoWPAN header which is exactly what we want */
    f->net_hdr = f->buffer;

    for (i = NUM_LL_EXTENSIONS - 1; i >= 0; i--) {
        ret = exts[i].in(f, &src, &dst);
        switch (ret) {
            case FRAME_6LOWPAN_LL_RELEASE:
                /* Success, frame is somewhere else now.. :( */
                break;
            case FRAME_6LOWPAN_LL_DISCARD:
                /* Something went wrong, discard the frame */
                pico_frame_discard(f);
                break;
            default:
                /* Success, update link layer header length */
                len = (uint32_t)(len + (uint32_t)ret);
        }
    }

    /* Determine size at network layer */
    f->net_len = (uint16_t)(f->len - len);
    f->len = (uint32_t)(f->len - len);
    return pico_6lowpan_pull(f, src, dst);
}

int
pico_6lowpan_ll_push(struct pico_frame *f, union pico_ll_addr src, union pico_ll_addr dst)
{
    uint16_t frame_size, pl_available = 0;
    union pico_ll_addr *addr = NULL;
    int i = 0;

    if (!f || !f->dev)
        return -1;
    frame_size = (uint16_t)(f->len);
    pl_available = (uint16_t)f->dev->mtu;

    /* Call each of the estimator functions of the additional headers to
     * determine if the frame fits inside a single 802.15.4 frame, if it doesn't
     * at some point, return the available bytes */
    for (i = 0; i < NUM_LL_EXTENSIONS; i++) {
        pl_available = (uint16_t)(pl_available - exts[i].estimate(f, &src, &dst));
    }
    if (frame_size > pl_available)
        return pl_available;

    /* Make sure these addresses are retrievable from the frame on processing */
    if ((addr = frame_6lowpan_ll_store_addr(f, src, dst))) {
        if (pico_enqueue(pico_proto_6lowpan_ll.q_out,f) > 0) {
            return 0; // Frame enqueued for later processing
        } else {
            PICO_FREE(addr);
        }
    }
    return -1; // Return ERROR
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

struct pico_protocol pico_proto_6lowpan_ll = {
    .name = "6lowpan_ll",
    .layer = PICO_LAYER_DATALINK,
    .process_in = pico_6lowpan_ll_process_in,
    .process_out = pico_6lowpan_ll_process_out,
    .q_in = &pico_6lowpan_ll_in,
    .q_out = &pico_6lowpan_ll_out
};

void pico_6lowpan_init(void)
{
    /* Don't care about failure */
    (void)pico_timer_add(60000, ctx_lifetime_check, NULL);
}

#endif /* PICO_SUPPORT_6LOWPAN */
