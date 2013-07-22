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
  (*f->usage_count)--;
  if (*f->usage_count <= 0) {
    pico_free(f->usage_count);
#ifdef PICO_SUPPORT_DEBUG_MEMORY
    dbg("Discarded buffer @%p, caller: %p\n", f->buffer, __builtin_return_address(3));
    dbg("DEBUG MEMORY: %d frames in use.\n", --n_frames_allocated);
#endif
    pico_free(f->buffer);
    if (f->info)
      pico_free(f->info);
  }
#ifdef PICO_SUPPORT_DEBUG_MEMORY
  else {
    dbg("Removed frame @%p(copy), usage count now: %d\n", f, *f->usage_count);
  }
#endif
  pico_free(f);
}

struct pico_frame *pico_frame_copy(struct pico_frame *f)
{
  struct pico_frame *new = pico_zalloc(sizeof(struct pico_frame));
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


struct pico_frame *pico_frame_alloc(int size)
{
  struct pico_frame *p = pico_zalloc(sizeof(struct pico_frame));
  if (!p)
    return NULL;
  p->buffer = pico_zalloc(size);
  if (!p->buffer) {
    pico_free(p);
    return NULL;
  }
  p->usage_count = pico_zalloc(sizeof(uint32_t));
  if (!p->usage_count) {
    pico_free(p->buffer);
    pico_free(p);
    return NULL;
  }
  p->buffer_len = size;


  /* By default, frame content is the full buffer. */
  p->start = p->buffer;
  p->len = p->buffer_len;
  *p->usage_count = 1;
#ifdef PICO_SUPPORT_DEBUG_MEMORY
    dbg("Allocated buffer @%p, len= %d caller: %p\n", p->buffer, p->buffer_len, __builtin_return_address(2));
    dbg("DEBUG MEMORY: %d frames in use.\n", ++n_frames_allocated);
#endif
  return p;
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
  addr_diff = (int)new->buffer - (int)f->buffer;
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
uint16_t pico_checksum(void *inbuf, int len)
{
  uint8_t *buf = (uint8_t *) inbuf;
  uint16_t tmp = 0;
  uint32_t sum = 0;
  int i = 0;

  for(i=0; i < len; i++) {
    if (i%2) {
      sum += buf[i];
    } else {
      tmp = buf[i];
      sum += (tmp << 8);
    }
  }

  while (sum >> 16) { /* a second carry is possible! */
    sum = (sum & 0x0000FFFF) + (sum >> 16);
  } 
  return (uint16_t) (~sum);
}

uint16_t pico_dualbuffer_checksum(void *inbuf1, int len1, void *inbuf2, int len2)
{
  uint8_t *b1 = (uint8_t *) inbuf1;
  uint8_t *b2 = (uint8_t *) inbuf2;
  uint16_t tmp = 0;
  uint32_t sum = 0;
  int i = 0, j = 0;

  for(i=0; i < len1; i++) {
    if (j%2) {
      sum += b1[i];
    } else {
      tmp = b1[i];
      sum += (tmp << 8);
    }
    j++;
  }

  j = 0; /* j has to be reset if len1 is odd */
  for(i=0; i < len2; i++) {
    if (j%2) {
      sum += b2[i];
    } else {
      tmp = b2[i];
      sum += (tmp << 8);
    }
    j++;
  }
  while (sum >> 16) { /* a second carry is possible! */
    sum = (sum & 0x0000FFFF) + (sum >> 16);
  } 
  return (uint16_t) (~sum);
}

uint16_t pico_dualbuffer_checksum_broken(void *inbuf1, int len1, void *inbuf2, int len2)
{
  uint16_t *b1 = (uint16_t *) inbuf1;
  uint16_t *b2 = (uint16_t *) inbuf2;
  uint32_t sum = 0;
  int i=0, j=0;
  for(i=0; i<(len1>>1); i++){
    sum += short_be(b1[i]);
    j++;
  }
  for(i=0; i<(len2>>1); i++){
    sum += short_be(b2[i]);
    j++;
  }
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum += (sum >> 16);
  
  // Take the bitwise complement of sum
  sum = ~sum;
  return (uint16_t) (sum)  ;
}


