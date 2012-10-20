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
    dbg("Discarded buffer @%p\n", f->buffer);
#ifdef PICO_SUPPORT_DEBUG_MEMORY
    dbg("DEBUG MEMORY: %d frames in use.\n", --n_frames_allocated);
#endif
    pico_free(f->buffer);
    pico_free(f);
  }
}

struct pico_frame *pico_frame_copy(struct pico_frame *f)
{
  struct pico_frame *new = pico_zalloc(sizeof(struct pico_frame));
  if (!new)
    return NULL;
  memcpy(new, f, sizeof(struct pico_frame));
  *(f->usage_count) += 1;
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

  dbg("Allocated buffer @%p, len= %d\n", p->buffer, p->buffer_len);

  /* By default, frame content is the full buffer. */
  p->start = p->buffer;
  p->len = p->buffer_len;
  *p->usage_count = 1;
#ifdef PICO_SUPPORT_DEBUG_MEMORY
    dbg("DEBUG MEMORY: %d frames in use.\n", ++n_frames_allocated);
#endif
  return p;
}

/**
 * Calculate checksum of a given string
 */
uint16_t pico_checksum(void *inbuf, int len)
{
  uint8_t *buf = (uint8_t *) inbuf;
  uint32_t sum = 0, carry=0;
  int i=0;
  for(i=0; i<len; i++){
    dbg("PROCESSING: [%02d] %02x\n", i, buf[i]);
    if (i%2){
      sum+=buf[i];
    }else{
      sum+=( buf[i] << 8);
    }
  }
  carry = (sum&0xFFFF0000) >>16;
  sum = (sum&0x0000FFFF);
  return (uint16_t) ~(sum + carry)  ;
}

uint16_t pico_dualbuffer_checksum(void *inbuf1, int len1, void *inbuf2, int len2)
{
  uint8_t *b1 = (uint8_t *) inbuf1;
  uint8_t *b2 = (uint8_t *) inbuf2;
  uint32_t sum = 0, carry=0;
  int i=0, j=0;
  for(i=0; i<len1; i++){
    dbg("%02x ", b1[i]);
    if (j%2){
      sum+=b1[i];
    }else{
      sum+=( b1[i] << 8);
    }
    j++;
  }

  for(i=0; i<len2; i++){
    dbg("%02x ", b2[i]);
    if (j%2){
      sum+=b2[i];
    }else{
      sum+=( b2[i] << 8);
    }
    j++;
  }
  dbg("\n");
  carry = (sum&0xFFFF0000) >>16;
  sum = (sum&0x0000FFFF);
  return (uint16_t) (~(sum + carry))  ;
}

uint16_t pico_dualbuffer_checksum_broken(void *inbuf1, int len1, void *inbuf2, int len2)
{
  uint16_t *b1 = (uint16_t *) inbuf1;
  uint16_t *b2 = (uint16_t *) inbuf2;
  uint32_t sum = 0;
  int i=0, j=0;
  for(i=0; i<(len1>>1); i++){
    dbg("%04x",  b1[i]);
    sum += short_be(b1[i]);
    j++;
  }
  for(i=0; i<(len2>>1); i++){
    dbg("%04x",  b2[i]);
    sum += short_be(b2[i]);
    j++;
  }
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum += (sum >> 16);
  dbg("\n");
  
  // Take the bitwise complement of sum
  sum = ~sum;
  return (uint16_t) (sum)  ;
}

