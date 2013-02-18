/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Daniele Lacamera
*********************************************************************/


#include "pico_device.h"
#include "pico_dev_loop.h"
#include "pico_stack.h"


#define LOOP_MTU 1500
static uint8_t l_buf[LOOP_MTU];
static int l_bufsize = 0;


static int pico_loop_send(struct pico_device *dev, void *buf, int len)
{
  if (len > LOOP_MTU)
    return 0;

  if (l_bufsize == 0) {
    memcpy(l_buf, buf, len);
    l_bufsize+=len;
    return len;
  }
  return 0;
}

static int pico_loop_poll(struct pico_device *dev, int loop_score)
{
  if (loop_score <= 0)
    return 0;

  if (l_bufsize > 0) {
    pico_stack_recv(dev, l_buf, l_bufsize);
    l_bufsize = 0;
    loop_score--;
  }
  return loop_score;
}

/* Public interface: create/destroy. */

void pico_loop_destroy(struct pico_device *dev)
{
}

struct pico_device *pico_loop_create(void)
{
  struct pico_device *loop = pico_zalloc(sizeof(struct pico_device));
  if (!loop)
    return NULL;

  if( 0 != pico_device_init((struct pico_device *)loop, "loop", NULL)) {
    dbg ("Loop init failed.\n");
    pico_loop_destroy((struct pico_device *)loop);
    return NULL;
  }
  loop->send = pico_loop_send;
  loop->poll = pico_loop_poll;
  loop->destroy = pico_loop_destroy;
  dbg("Device %s created.\n", loop->name);
  return (struct pico_device *)loop;
}

