/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_device.h"
#include "pico_dev_loop.h"
#include "pico_stack.h"


#define LOOP_MTU (uint32_t)1500

#define ZERO_U8 (uint8_t)0
#define ONE_U8 (uint8_t)1
#define ZERO_U32 (uint32_t)0

static uint8_t l_buf[LOOP_MTU];
static uint32_t l_bufsize = ZERO_U32;


static uint8_t pico_loop_send(struct pico_device *dev, void *buf, uint32_t len)
{
    uint8_t retval=ONE_U8;

    IGNORE_PARAMETER(dev);
    if (len > LOOP_MTU)
    {
        retval = ZERO_U8;
    }

    if ((l_bufsize == ZERO_U32) && (retval == ONE_U8)) {
        (void) memcpy(l_buf,buf,(size_t)len);
        l_bufsize += len;
        retval = len;
    }
    else
    {
        retval = ZERO_U8;
    }
    return retval;
}

static uint8_t pico_loop_poll(struct pico_device *dev, uint32_t loop_score)
{
    uint8_t retval=ONE_U8;

    if (loop_score <= ZERO_U32){
        retval=ZERO_U8;
    }

    if ((l_bufsize > ZERO_U32)&&(retval==ONE_U8)) {
        (void)pico_stack_recv(dev, l_buf, l_bufsize);
        l_bufsize = ZERO_U32;
        loop_score--;
    }
    
    if (retval==ONE_U8)
    {
        retval = loop_score;
    }
    return retval;
}


struct pico_device *pico_loop_create(void)
{
    struct pico_device *loop = PICO_ZALLOC(sizeof(struct pico_device));
    struct pico_device *retval = NULL;
    uint8_t checkflag=ZERO_U8; 

    if (!loop){
        checkflag=ONE_U8;
    }

    if(( 0 != pico_device_init(loop, "loop", NULL))&&(checkflag==ZERO_U8)) {
        (void)dbg ("Loop init failed.\n");
        pico_device_destroy(loop);
        retval=NULL;
    }
    else if(checkflag==ZERO_U8)
    {
        loop->send = pico_loop_send;
        loop->poll = pico_loop_poll;
        (void)dbg("Device %s created.\n", loop->name);
        retval=loop;
    }
    else{
        /*Do nothing*/
    }

    return retval;
}

