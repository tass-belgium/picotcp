/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_config.h"
#include "pico_frame.h"
#include "pico_protocol.h"
#include "pico_stack.h"

#ifdef PICO_SUPPORT_DEBUG_MEMORY
static int n_frames_allocated;
#endif

/** frame alloc/dealloc/copy **/
void pico_frame_discard(struct pico_frame *f)
{
    if (!f)
        return;

    (*f->usage_count)--;
    if (*f->usage_count == 0) {
        if (f->flags & PICO_FRAME_FLAG_EXT_USAGE_COUNTER)
            PICO_FREE(f->usage_count);

#ifdef PICO_SUPPORT_DEBUG_MEMORY
        dbg("Discarded buffer @%p, caller: %p\n", f->buffer, __builtin_return_address(3));
        dbg("DEBUG MEMORY: %d frames in use.\n", --n_frames_allocated);
#endif
        if (!(f->flags & PICO_FRAME_FLAG_EXT_BUFFER))
            PICO_FREE(f->buffer);
        else if (f->notify_free)
            f->notify_free(f->buffer);

        if (f->info)
            PICO_FREE(f->info);
    }

#ifdef PICO_SUPPORT_DEBUG_MEMORY
    else {
        dbg("Removed frame @%p(copy), usage count now: %d\n", f, *f->usage_count);
    }
#endif
    PICO_FREE(f);
}

struct pico_frame *pico_frame_copy(struct pico_frame *f)
{
    struct pico_frame *new = PICO_ZALLOC(sizeof(struct pico_frame));
    if (!new)
        return NULL;

    memcpy(new, f, sizeof(struct pico_frame));
    *(new->usage_count) += 1;
#ifdef PICO_SUPPORT_DEBUG_MEMORY
    dbg("Copied frame @%p, into %p, usage count now: %d\n", f, new, *new->usage_count);
#endif
    new->next = NULL;
    return new;
}


static struct pico_frame *pico_frame_do_alloc(uint32_t size, int zerocopy, int ext_buffer)
{
    struct pico_frame *p = PICO_ZALLOC(sizeof(struct pico_frame));
    uint32_t frame_buffer_size = size;
    if (!p)
        return NULL;

    if (ext_buffer && !zerocopy) {
        /* external buffer implies zerocopy flag! */
        PICO_FREE(p);
        return NULL;
    }

    if (!zerocopy) {
        unsigned int align = size % sizeof(uint32_t);
        /* Ensure that usage_count starts on an aligned address */
        if (align) {
            frame_buffer_size += (uint32_t)sizeof(uint32_t) - align;
        }

        p->buffer = PICO_ZALLOC(frame_buffer_size + sizeof(uint32_t));
        if (!p->buffer) {
            PICO_FREE(p);
            return NULL;
        }

        p->usage_count = (uint32_t *)(((uint8_t*)p->buffer) + frame_buffer_size);
    } else {
        p->buffer = NULL;
        p->flags |= PICO_FRAME_FLAG_EXT_USAGE_COUNTER;
        p->usage_count = PICO_ZALLOC(sizeof(uint32_t));
        if (!p->usage_count) {
            PICO_FREE(p);
            return NULL;
        }
    }


    p->buffer_len = size;

    /* By default, frame content is the full buffer. */
    p->start = p->buffer;
    p->len = p->buffer_len;
    *p->usage_count = 1;

    if (ext_buffer)
        p->flags |= PICO_FRAME_FLAG_EXT_BUFFER;

#ifdef PICO_SUPPORT_DEBUG_MEMORY
    dbg("Allocated buffer @%p, len= %d caller: %p\n", p->buffer, p->buffer_len, __builtin_return_address(2));
    dbg("DEBUG MEMORY: %d frames in use.\n", ++n_frames_allocated);
#endif
    return p;
}

struct pico_frame *pico_frame_alloc(uint32_t size)
{
    return pico_frame_do_alloc(size, 0, 0);
}

int pico_frame_grow(struct pico_frame *f, uint32_t size)
{
    uint8_t *oldbuf;
    uint32_t usage_count, *p_old_usage;
    uint32_t frame_buffer_size;
    uint32_t oldsize;
    unsigned int align;
    int addr_diff = 0;

    if (!f || (size < f->buffer_len)) {
        return -1;
    }

    align = size % sizeof(uint32_t);
    frame_buffer_size = size;
    if (align) {
        frame_buffer_size += (uint32_t)sizeof(uint32_t) - align;
    }

    oldbuf = f->buffer;
    oldsize = f->buffer_len;
    usage_count = *(f->usage_count);
    p_old_usage = f->usage_count;
    f->buffer = PICO_ZALLOC(frame_buffer_size + sizeof(uint32_t));
    if (!f->buffer) {
        f->buffer = oldbuf;
        return -1;
    }

    f->usage_count = (uint32_t *)(((uint8_t*)f->buffer) + frame_buffer_size);
    *f->usage_count = usage_count;
    f->buffer_len = size;
    memcpy(f->buffer, oldbuf, oldsize);

    /* Update hdr fields to new buffer*/
    addr_diff = (int)(f->buffer - oldbuf);
    f->net_hdr += addr_diff;
    f->datalink_hdr += addr_diff;
    f->transport_hdr += addr_diff;
    f->app_hdr += addr_diff;
    f->start += addr_diff;
    f->payload += addr_diff;

    if (f->flags & PICO_FRAME_FLAG_EXT_USAGE_COUNTER)
        PICO_FREE(p_old_usage);

    if (!(f->flags & PICO_FRAME_FLAG_EXT_BUFFER))
        PICO_FREE(oldbuf);
    else if (f->notify_free)
        f->notify_free(oldbuf);

    f->flags = 0;
    /* Now, the frame is not zerocopy anymore, and the usage counter has been moved within it */
    return 0;
}

struct pico_frame *pico_frame_alloc_skeleton(uint32_t size, int ext_buffer)
{
    return pico_frame_do_alloc(size, 1, ext_buffer);
}

int pico_frame_skeleton_set_buffer(struct pico_frame *f, void *buf)
{
    if (!buf)
        return -1;

    f->buffer = (uint8_t *) buf;
    f->start = f->buffer;
    return 0;
}

struct pico_frame *pico_frame_deepcopy(struct pico_frame *f)
{
    struct pico_frame *new = pico_frame_alloc(f->buffer_len);
    int addr_diff;
    unsigned char *buf;
    uint32_t *uc;
    if (!new)
        return NULL;

    /* Save the two key pointers... */
    buf = new->buffer;
    uc  = new->usage_count;

    /* Overwrite all fields with originals */
    memcpy(new, f, sizeof(struct pico_frame));

    /* ...restore the two key pointers */
    new->buffer = buf;
    new->usage_count = uc;

    /* Update in-buffer pointers with offset */
    addr_diff = (int)(new->buffer - f->buffer);
    new->datalink_hdr += addr_diff;
    new->net_hdr += addr_diff;
    new->transport_hdr += addr_diff;
    new->app_hdr += addr_diff;
    new->start += addr_diff;
    new->payload += addr_diff;

#ifdef PICO_SUPPORT_DEBUG_MEMORY
    dbg("Deep-Copied frame @%p, into %p, usage count now: %d\n", f, new, *new->usage_count);
#endif
    new->next = NULL;
    return new;
}


static inline uint32_t pico_checksum_adder(uint32_t sum, void *data, uint32_t len)
{
    uint16_t *buf = (uint16_t *)data;
    uint16_t *stop;

    if (len & 0x01) {
        --len;
#ifdef PICO_BIGENDIAN
        sum += (((uint8_t *)data)[len]) << 8;
#else
        sum += ((uint8_t *)data)[len];
#endif
    }

    stop = (uint16_t *)(((uint8_t *)data) + len);

    while (buf < stop) {
        sum += *buf++;
    }
    return sum;
}

static inline uint16_t pico_checksum_finalize(uint32_t sum)
{
    while (sum >> 16) { /* a second carry is possible! */
        sum = (sum & 0x0000FFFF) + (sum >> 16);
    }
    return short_be((uint16_t) ~sum);
}

/**
 * Calculate checksum of a given string
 */
uint16_t pico_checksum(void *inbuf, uint32_t len)
{
    uint32_t sum;

    sum = pico_checksum_adder(0, inbuf, len);
    return pico_checksum_finalize(sum);
}

/* WARNING: len1 MUST be an EVEN number */
uint16_t pico_dualbuffer_checksum(void *inbuf1, uint32_t len1, void *inbuf2, uint32_t len2)
{
    uint32_t sum;

    sum = pico_checksum_adder(0, inbuf1, len1);
    sum = pico_checksum_adder(sum, inbuf2, len2);
    return pico_checksum_finalize(sum);
}

