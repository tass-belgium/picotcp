/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_config.h"
#include "pico_frame.h"

#ifdef PICO_SUPPORT_DEBUG_MEMORY
static int n_frames_allocated;
#endif

/** frame alloc/dealloc/copy **/
void pico_frame_discard(struct pico_frame *f)
{
    if (!f)
        return;

    (*f->usage_count)--;
    if (*f->usage_count <= 0) {
        PICO_FREE(f->usage_count);
#ifdef PICO_SUPPORT_DEBUG_MEMORY
        dbg("Discarded buffer @%p, caller: %p\n", f->buffer, __builtin_return_address(3));
        dbg("DEBUG MEMORY: %d frames in use.\n", --n_frames_allocated);
#endif
        if (! (f->flags & PICO_FRAME_FLAG_EXT_BUFFER))
            PICO_FREE(f->buffer);

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
    if (!p)
        return NULL;

    if (!zerocopy) {
        p->buffer = PICO_ZALLOC(size);
        if (!p->buffer) {
            PICO_FREE(p);
            return NULL;
        }
    } else {
        p->buffer = NULL;
    }

    p->usage_count = PICO_ZALLOC(sizeof(uint32_t));
    if (!p->usage_count) {
        if (p->buffer && !ext_buffer)
            PICO_FREE(p->buffer);

        PICO_FREE(p);
        return NULL;
    }

    p->buffer_len = size;


    /* By default, frame content is the full buffer. */
    p->start = p->buffer;
    p->len = p->buffer_len;
    *p->usage_count = 1;

    if (ext_buffer)
        p->flags = PICO_FRAME_FLAG_EXT_BUFFER;

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

/**
 * Calculate checksum of a given string
 */
uint16_t pico_checksum(void *inbuf, uint32_t len)
{
    uint8_t *buf = (uint8_t *) inbuf;
    uint32_t tmp = 0;
    uint32_t sum = 0;
    uint32_t i = 0;

    for(i = 0; i < len; i += 2u) {
        tmp = buf[i];
        sum += (tmp << 8lu);
        if (len > (i + 1u))
            sum += buf[i + 1];
    }
    while (sum >> 16) { /* a second carry is possible! */
        sum = (sum & 0x0000FFFF) + (sum >> 16);
    }
    return (uint16_t) (~sum);
}

uint16_t pico_dualbuffer_checksum(void *inbuf1, uint32_t len1, void *inbuf2, uint32_t len2)
{
    uint8_t *b1 = (uint8_t *) inbuf1;
    uint8_t *b2 = (uint8_t *) inbuf2;
    uint32_t tmp = 0;
    uint32_t sum = 0;
    uint32_t i = 0;

    for(i = 0; i < len1; i += 2u) {
        tmp = b1[i];
        sum += (tmp << 8lu);
        if (len1 > (i + 1u))
            sum += b1[i + 1];
    }
    for(i = 0; i < len2; i += 2u) {
        tmp = b2[i];
        sum += (tmp << 8lu);
        if (len2 > (i + 1u))
            sum += b2[i + 1];
    }
    while (sum >> 16) { /* a second carry is possible! */
        sum = (sum & 0x0000FFFF) + (sum >> 16);
    }
    return (uint16_t) (~sum);
}

