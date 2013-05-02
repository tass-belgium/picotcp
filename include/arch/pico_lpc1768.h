/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

*********************************************************************/
#ifndef _INCLUDE_PICO_LPC
#define _INCLUDE_PICO_LPC

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_constants.h"

extern uint32_t Time_ElapsedSec(void);
extern uint32_t Time_ElapsedMili(void);
extern void *pvPortMalloc( size_t xSize );
extern void vPortFree( void *pv );


#define PICO_TIME() (Time_ElapsedSec())
#define PICO_TIME_MS() (Time_ElapsedMili())
#define PICO_IDLE()

#define pico_free(x) vPortFree(x)
#define free(x)      vPortFree(x)

static inline void * pico_zalloc(size_t size)
{
	void *ptr = pvPortMalloc(size);

	if(ptr)
		memset(ptr,0u,size);

	return ptr;
}

#define dbg(...)

#endif
