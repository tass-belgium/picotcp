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

#define dbg(...)


extern volatile uint32_t tassTick;

#ifdef PICO_SUPPORT_RTOS
    #define PICO_SUPPORT_MUTEX
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

static inline pico_time PICO_TIME_MS()
{
    return tassTick;
}

static inline pico_time PICO_TIME()
{
    return tassTick / 1000;
}

static inline void PICO_IDLE(void)
{
    uint32_t now = PICO_TIME_MS();
    while(now == PICO_TIME_MS()) ;
}

#else /* NO RTOS SUPPORT */

#ifdef MEM_MEASURE
void *pico_zzalloc(size_t x);
void pico_ffree(void *x);

extern uint32_t max_mem;
extern uint32_t cur_mem;

struct mem_chunk_stats {
    uint32_t signature;
    void *mem;
    uint32_t size;
};

static inline void *pico_zalloc(size_t size)
{
    return pico_zzalloc(size);
}
static inline void pico_free(void *x)
{
    return pico_ffree(x);
}

#else
    #define pico_free(x) free(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = malloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

#endif

extern volatile uint32_t lpc_tick;
extern volatile pico_time full_tick;

static inline pico_time PICO_TIME_MS(void)
{
    if ((full_tick & 0xFFFFFFFF) > lpc_tick) {
        full_tick +=  0x100000000ULL;
    }

    full_tick = (full_tick & 0xFFFFFFFF00000000ULL) + lpc_tick;
    return full_tick;
}

static inline pico_time PICO_TIME(void)
{
    return PICO_TIME_MS() / 1000;
}

static inline void PICO_IDLE(void)
{
    uint32_t now = lpc_tick;
    while(now == lpc_tick) ;
}

#endif /* IFNDEF RTOS */

#endif
