/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_device.h"
#include "pico_dev_loop.h"
#include "pico_stack.h"


#define LOOP_MTU 1500

#define ZERO (uint8_t)0
#define ONE (uint8_t)1

static uint8_t l_buf[LOOP_MTU];
static uint8_t l_bufsize = ZERO;


static uint8_t pico_loop_send(struct pico_device *dev, void *buf, uint32_t len)
{
    uint8_t retval=ONE;

    IGNORE_PARAMETER(dev);
    if (len > LOOP_MTU)
    {
        retval = ZERO;
    }

    if ((l_bufsize == ZERO) && (retval == ONE)) {
        (void) memcpy(l_buf,buf,(size_t)len);
        l_bufsize += len;
        retval = len;
    }
    else
    {
        retval = ZERO;
    }
    return retval;
}

static uint8_t pico_loop_poll(struct pico_device *dev, uint8_t loop_score)
{
    uint8_t retval=ONE;

    if (loop_score <= ZERO){
        retval=ZERO;
    }

    if ((l_bufsize > ZERO)&&(retval==ONE)) {
        (void)pico_stack_recv(dev, l_buf, (uint32_t)l_bufsize);
        l_bufsize = ZERO;
        loop_score--;
    }
    
    if (retval==ONE)
    {
        retval = loop_score;
    }
    return retval;
}


struct pico_device *pico_loop_create(void)
{
    struct pico_device *loop = PICO_ZALLOC(sizeof(struct pico_device));
    struct pico_device *retval = NULL;
    uint8_t checkflag=ZERO; 

    if (!loop){
        checkflag=ONE;
    }

    if(( 0 != pico_device_init(loop, "loop", NULL))&&(checkflag==ZERO)) {
        (void)dbg ("Loop init failed.\n");
        pico_device_destroy(loop);
        retval=NULL;
    }
    else if(checkflag==ZERO)
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

