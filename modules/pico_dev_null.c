/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_device.h"
#include "pico_dev_null.h"
#include "pico_stack.h"

struct pico_device_null {
    struct pico_device dev;
    int statistics_frames_out;
};

#define NULL_MTU 0

static int pico_null_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_null *null = (struct pico_device_null *) dev;
    IGNORE_PARAMETER(buf);

    /* Increase the statistic count */
    null->statistics_frames_out++;

    /* Discard the frame content silently. */
    return len;
}

static int pico_null_poll(struct pico_device *dev, int loop_score)
{
    /* We never have packet to receive, no score is used. */
    IGNORE_PARAMETER(dev);
    return loop_score;
}

/* Public interface: create/destroy. */


struct pico_device *pico_null_create(char *name)
{
    struct pico_device_null *null = PICO_ZALLOC(sizeof(struct pico_device_null));

    if (!null)
        return NULL;

    if( 0 != pico_device_init((struct pico_device *)null, name, NULL)) {
        return NULL;
    }

    null->dev.overhead = 0;
    null->statistics_frames_out = 0;
    null->dev.send = pico_null_send;
    null->dev.poll = pico_null_poll;
    dbg("Device %s created.\n", null->dev.name);
    return (struct pico_device *)null;
}

