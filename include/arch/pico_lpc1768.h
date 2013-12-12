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

#ifdef PICO_SUPPORT_RTOS
#   define PICO_SUPPORT_MUTEX
extern void *pico_mutex_init(void);
extern void pico_mutex_lock(void*);
extern void pico_mutex_unlock(void*);
extern void *pvPortMalloc( size_t xSize );
extern void vPortFree( void *pv );

#define pico_free(x) vPortFree(x)
#define free(x)      vPortFree(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = pvPortMalloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

#define PICO_TIME() (Time_ElapsedSec())
#define PICO_TIME_MS() (Time_ElapsedMili())
#define PICO_IDLE()
extern uint32_t Time_ElapsedSec(void);
extern uint32_t Time_ElapsedMili(void);


#else
# define pico_free(x) free(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = malloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

#define PICO_TIME_MS() (void)
#error "You must define your clock source!\n"

#endif





#define dbg(...)

#endif
