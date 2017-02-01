/*********************************************************************
 PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
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

/*******************************************************************************
 * Type definitions
 ******************************************************************************/

struct extension {
    int32_t (*estimate)(struct pico_frame *f);
    int32_t (*out)(struct pico_frame *f);
    int32_t (*in)(struct pico_frame *f);
};

/*******************************************************************************
 * Global Variables
 ******************************************************************************/

static const struct pico_6lowpan_ll_protocol pico_6lowpan_ll_none = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* Declare a global lookup-table for distribution of link layer specific tasks */
struct pico_6lowpan_ll_protocol pico_6lowpan_lls[PICO_6LOWPAN_LLS + 1];

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
static int32_t compare_prefix(uint8_t *a, uint8_t *b, int32_t len)
{
    uint8_t bitmask = (uint8_t)(0xff << (8 - (len % 8)));
    size_t bytes = (size_t)len / 8;
    int32_t ret = 0;
    if ((ret = memcmp(a, b, bytes)))
        return ret;
    return (int32_t)((a[bytes] & bitmask) - (b[bytes] & bitmask));
}

/* Compares 2 IPHC context entries */
static int32_t compare_ctx(void *a, void *b)
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
    struct iphc_ctx test = { NULL, addr, 0, 0, 0, 0 };
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
static int32_t ctx_insert(struct pico_ip6 addr, uint8_t id, uint8_t size, pico_time lifetime, uint8_t flags, struct pico_device *dev)
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
            return;
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
 * are reconfirmed before their lifetime expires */
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
                gw = pico_ipv6_gateway_by_dev(key->dev);
                while (gw) {
                    pico_6lp_nd_start_soliciting(pico_ipv6_linklocal_get(key->dev), gw);
                    gw = pico_ipv6_gateway_by_dev_next(key->dev, gw);
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
static int32_t
ll_mesh_header_process_in(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return 0;
}

/* XXX: Extensible processing function for outgoing frames. Here, the mesh header
 * for a Mesh-Under topology can be prepended and the link layer source and
 * destination addresses can be updated */
static int32_t
ll_mesh_header_process_out(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return 0;
}

/* XXX: Extensible function that estimates the size of the mesh header to be
 * prepended based on the frame, the source and destination link layer address */
static int32_t
ll_mesh_header_estimator(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return 0;
}

/*******************************************************************************
 *  GENERIC 6LOWPAN LINK LAYER
 ******************************************************************************/

static int32_t
ll_mac_header_process_in(struct pico_frame *f)
{
    if (f && f->dev && pico_6lowpan_lls[f->dev->mode].process_in) {
        return (int32_t)pico_6lowpan_lls[f->dev->mode].process_in(f);
    } else {
        return -1;
    }
}

static int32_t
ll_mac_header_process_out(struct pico_frame *f)
{
    if (f && f->dev && pico_6lowpan_lls[f->dev->mode].process_out) {
        return (int32_t)pico_6lowpan_lls[f->dev->mode].process_out(f);
    } else {
        return -1;
    }
}

static int32_t
ll_mac_header_estimator(struct pico_frame *f)
{
    if (f && f->dev && pico_6lowpan_lls[f->dev->mode].estimate) {
        return (int32_t)pico_6lowpan_lls[f->dev->mode].estimate(f);
    } else {
        return -1;
    }
}

/* Alloc's a frame with device's overhead and maximum IEEE802.15.4 header size */
static struct pico_frame *
pico_6lowpan_frame_alloc(struct pico_protocol *self, struct pico_device *dev, uint16_t size)
{
    IGNORE_PARAMETER(self);
    if (dev && pico_6lowpan_lls[dev->mode].alloc) {
        return pico_6lowpan_lls[dev->mode].alloc(dev, size);
    } else {
        return NULL;
    }
}

/*******************************************************************************
 *  6LOWPAN LINK LAYER PROTOCOL
 ******************************************************************************/

const struct extension exts[] = {
    {ll_mesh_header_estimator, ll_mesh_header_process_out, ll_mesh_header_process_in},
    {ll_mac_header_estimator, ll_mac_header_process_out, ll_mac_header_process_in},
};

static int32_t
pico_6lowpan_ll_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    uint32_t datalink_len = 0;
    int32_t ret = 0, i = 0;
    IGNORE_PARAMETER(self);

    /* Every link layer extension updates the datalink pointer of the frame a little bit. */
    f->datalink_hdr = f->net_hdr;

    /* Call each of the outgoing processing functions */
    for (i = 0; i < NUM_LL_EXTENSIONS; i++) {
        ret = exts[i].out(f);
        if (ret < 0)  /* Processing failed, no way to recover, discard frame */
            goto fin;
        datalink_len = (uint32_t)(datalink_len + (uint32_t)ret);
        if ((f->net_hdr - datalink_len) < f->buffer) /* Before buffer bound check */
            goto fin;
    }

    /* Frame is ready for sending to the device driver */
    f->start = f->datalink_hdr;
    f->len = (uint32_t)(f->len + datalink_len);
    return (int32_t)(pico_sendto_dev(f) <= 0);
fin:
    pico_frame_discard(f);
    return -1;
}

static int32_t
pico_6lowpan_ll_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    int32_t i = 0, ret = 0;
    uint32_t len = 0;
    IGNORE_PARAMETER(self);

    /* net_hdr is the pointer that is dynamically updated by the incoming
     * processing functions to always point to right after a particular
     * header, whether it's MAC, MESH, LL_SEC, ... eventually net_hdr will
     * point to 6LoWPAN header which is exactly what we want */
    f->net_hdr = f->buffer;

    for (i = NUM_LL_EXTENSIONS - 1; i >= 0; i--) {
        ret = exts[i].in(f);
        switch (ret) {
            case FRAME_6LOWPAN_LL_RELEASE:
                /* Success, frame is somewhere else now.. */
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
    return pico_6lowpan_pull(f);
}

/* Entry point for incoming 6LoWPAN frames, proxy for pico_stack_recv. This allows passing the link
 * layer source and destination address as well */
int32_t pico_6lowpan_stack_recv(struct pico_device *dev, uint8_t *buffer, uint32_t len, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    int32_t ret = 0;
    ll_dbg("6LoWPAN - Stack recv called!\n");
    if (PICO_DEV_IS_NOMAC(dev)) {
        struct pico_frame *f = pico_stack_recv_new_frame(dev, buffer, len);
        if (f) {
            f->src = *src;
            f->dst = *dst;
            ret = pico_enqueue(dev->q_in, f);
            if (0 >= ret)
                pico_frame_discard(f);
            return ret;
        }
    } else {
        return pico_stack_recv(dev, buffer, len);
    }
    return -1; // return ERROR
}

/* Proxy for pico_devloop_sendto_dev, 6LoWPAN-devices have a different interface with pico. This
 * allows passing the link layer source and destination address as well */
int32_t pico_6lowpan_ll_sendto_dev(struct pico_device *dev, struct pico_frame *f)
{
    /* FINAL OUTGOING POINT OF 6LOWPAN STACK */
    return ((struct pico_dev_6lowpan *)dev)->send(dev, f->start, (int32_t)f->len, f->src, f->dst);
}

/* Initialisation routine for 6LoWPAN specific devices */
int pico_dev_6lowpan_init(struct pico_dev_6lowpan *dev, const char *name, uint8_t *mac, enum pico_ll_mode ll_mode, uint16_t mtu, uint8_t nomac,
                          int (* send)(struct pico_device *dev, void *_buf, int len, union pico_ll_addr src, union pico_ll_addr dst),
                          int (* poll)(struct pico_device *dev, int loop_score))
{
    struct pico_device *picodev = (struct pico_device *)dev;
    if (!dev || !send || !poll) {
        return -1;
    }

    picodev->mode = ll_mode;
    picodev->hostvars.lowpan_flags = PICO_6LP_FLAG_LOWPAN;
    if (nomac) {
        picodev->hostvars.lowpan_flags |= PICO_6LP_FLAG_NOMAC;
    }
    picodev->mtu = mtu;
    picodev->poll = poll;
    picodev->send = NULL;
    dev->send = send;

    return pico_device_init(picodev, name, mac);
}


/* Push function for 6LoWPAN to call when it wants to try to send te frame to the device-driver */
int32_t
pico_6lowpan_ll_push(struct pico_frame *f)
{
    uint16_t frame_size, pl_available = 0;
    int32_t i = 0;

    if (!f || !f->dev)
        return -1;
    frame_size = (uint16_t)(f->len);

    /* Restrict frames to be as large as the device's MTU. */
    pl_available = (uint16_t)f->dev->mtu;

    /* Call each of the estimator functions of the additional headers to
     * determine if the frame fits inside a single 802.15.4 frame, if it doesn't
     * in the end, return the available bytes */
    for (i = 0; i < NUM_LL_EXTENSIONS; i++) {
        pl_available = (uint16_t)(pl_available - exts[i].estimate(f));
    }
    if (frame_size > pl_available)
        return pl_available;

    /* Make sure these addresses are retrievable from the frame on processing */
    if (pico_enqueue(pico_proto_6lowpan_ll.q_out,f) > 0) {
        return 0; // Frame enqueued for later processing
    }
    return -1; // Return ERROR
}

struct pico_protocol pico_proto_6lowpan_ll = {
    .name = "6lowpan_ll",
    .layer = PICO_LAYER_DATALINK,
    .alloc = pico_6lowpan_frame_alloc,
    .process_in = pico_6lowpan_ll_process_in,
    .process_out = pico_6lowpan_ll_process_out,
    .q_in = &pico_6lowpan_ll_in,
    .q_out = &pico_6lowpan_ll_out
};

void pico_6lowpan_ll_init(void)
{
    int32_t i = 0;

#ifdef PICO_6LOWPAN_IPHC_ENABLED
    /* We don't care about failure */
    (void)pico_timer_add(60000, ctx_lifetime_check, NULL);
#endif

    /* Initialize interface with 6LoWPAN link layer protocols */
    pico_6lowpan_lls[i++] = pico_6lowpan_ll_none;

#ifdef PICO_SUPPORT_802154
    pico_6lowpan_lls[i++] = pico_6lowpan_ll_802154;
#endif
}

#endif /* PICO_SUPPORT_6LOWPAN */
