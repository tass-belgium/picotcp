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
static uint8_t l_bufsize = 0;


static uint8_t pico_loop_send(struct pico_device *dev, void *buf, uint8_t len)
{
    uint8_t retval=1;

    IGNORE_PARAMETER(dev);
    if (len > LOOP_MTU)
    {
        retval = 0;
    }

    if ((l_bufsize == 0) && (retval == 1)) {
        (void) memcpy(l_buf,buf,(size_t)len);
        l_bufsize += len;
        retval = len;
    }
    else
    {
        retval = 0;
    }
    return retval;
}

static uint8_t pico_loop_poll(struct pico_device *dev, uint8_t loop_score)
{
    uint8_t retval=1;

    if (loop_score <= 0){
        retval=0;
    }

    if ((l_bufsize > 0)&&(retval==1)) {
        (void)pico_stack_recv(dev, l_buf, (uint32_t)l_bufsize);
        l_bufsize = 0;
        loop_score--;
    }
    
    if (retval==1)
    {
        retval = loop_score;
    }
    return retval;
}


struct pico_device *pico_loop_create(void)
{
    struct pico_device *loop = PICO_ZALLOC(sizeof(struct pico_device));
    struct pico_device *retval = NULL;
    uint8_t checkflag=0; 

    if (!loop){
        checkflag=1;
    }

    if(( 0 != pico_device_init(loop, "loop", NULL))&&(checkflag==0)) {
        (void)dbg ("Loop init failed.\n");
        pico_device_destroy(loop);
        retval=NULL;
    }
    else if(checkflag==0)
    {
        loop->send = pico_loop_send;
        loop->poll = pico_loop_poll;
        (void)dbg("Device %s created.\n", loop->name);
        retval=loop;
    }
    return retval;
}

