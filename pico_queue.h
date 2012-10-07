#ifndef _INCLUDE_PICO_QUEUE
#define _INCLUDE_PICO_QUEUE

struct pico_queue {
  uint32_t frames;
  uint32_t size;
  uint32_t max_frames;
  uint32_t max_size;
  struct pico_frame *head;
  struct pico_frame *tail;
};

static inline int pico_enqueue(struct pico_queue *q, struct pico_frame *p)
{
  if ((q->max_frames) && (q->max_frames <= q->frames))
    return -1;

  if ((q->max_size) && (q->max_size < (p->buffer_len + q->size)))
    return -1;

  if (!q->head) {
    q->head = p;
    q->tail = p;
  } else {
    q->tail->next = p;
    p->next = NULL;
  }
  q->size += p->buffer_len;
  q->frames++;
  return q->size;
}

static inline struct pico_frame *pico_dequeue(struct pico_queue *q)
{
  struct pico_frame *p = q->head;
  if (!p)
    return NULL;
  q->head = p->next;
  q->frames--;
  q->size -= p->buffer_len;
  return p;
}

#endif
