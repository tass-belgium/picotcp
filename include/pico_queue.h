/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_QUEUE
#define _INCLUDE_PICO_QUEUE
#include <stdint.h>
#include "pico_config.h"
#include "pico_frame.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

struct pico_queue {
  uint32_t frames;
  uint32_t size;
  uint32_t max_frames;
  uint32_t max_size;
  struct pico_frame *head;
  struct pico_frame *tail;
#ifdef PICO_RTOS_SUPPORT
  void * mutex;
#endif
};

#ifdef PICO_RTOS_SUPPORT
	extern void waitAndTakeMutex(void ** mutex);
	extern void giveMutexBack(void * mutex);
#endif

#ifdef PICO_SUPPORT_DEBUG_TOOLS
static void debug_q(struct pico_queue *q)
{
  struct pico_frame *p = q->head;
  dbg("%d: ", q->frames);
  while(p) {
    dbg("(%p)-->", p);
    p = p->next;
  }
  dbg("X\n");
}
#endif

static inline int pico_enqueue(struct pico_queue *q, struct pico_frame *p)
{
  if ((q->max_frames) && (q->max_frames <= q->frames))
    return -1;

  if ((q->max_size) && (q->max_size < (p->buffer_len + q->size)))
    return -1;

#ifdef PICO_RTOS_SUPPORT
	waitAndTakeMutex(&q->mutex);
#endif

  p->next = NULL;
  if (!q->head) {
    q->head = p;
    q->tail = p;
    q->size = 0;
    q->frames = 0;
  } else {
    q->tail->next = p;
    q->tail = p;
  }
  q->size += p->buffer_len;
  q->frames++;
#ifdef PICO_SUPPORT_DEBUG_TOOLS
  debug_q(q);
#endif

#ifdef PICO_RTOS_SUPPORT
	giveMutexBack(q->mutex);
#endif

  return q->size;
}

static inline struct pico_frame *pico_dequeue(struct pico_queue *q)
{
  struct pico_frame *p = q->head;
  if (q->frames < 1)
    return NULL;
#ifdef PICO_RTOS_SUPPORT
 waitAndTakeMutex(&q->mutex);
#endif

  q->head = p->next;
  q->frames--;
  q->size -= p->buffer_len;
  if (q->head == NULL)
    q->tail = NULL;
#ifdef PICO_SUPPORT_DEBUG_TOOLS
  debug_q(q);
#endif
  p->next = NULL;

#ifdef PICO_RTOS_SUPPORT
	giveMutexBack(q->mutex);
#endif

  return p;
}

static inline struct pico_frame *pico_queue_peek(struct pico_queue *q)
{
  struct pico_frame *p = q->head;
  if (q->frames < 1)
    return NULL;
#ifdef PICO_SUPPORT_DEBUG_TOOLS
  debug_q(q);
#endif
  return p;
}

static inline void pico_queue_empty(struct pico_queue *q)
{
  struct pico_frame *p = pico_dequeue(q);
  while(p) {
    pico_free(p);
    p = pico_dequeue(q);
  }
}

#endif
