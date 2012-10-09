#include "pico_config.h"
#include "pico_frame.h"

/** frame alloc/dealloc/copy **/
void pico_frame_discard(struct pico_frame *f)
{
  (*f->usage_count)--;
  if (*f->usage_count <= 0) {
    pico_free(f->usage_count);
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

  /* By default, frame content is the full buffer. */
  p->start = p->buffer;
  p->len = p->buffer_len;
  *p->usage_count = 1;
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

