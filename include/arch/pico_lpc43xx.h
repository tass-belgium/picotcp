/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_LPC43XX
#define _INCLUDE_PICO_LPC43XX

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_constants.h"

extern volatile uint32_t tassTick;

#define dbg

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

#else

    #define pico_free(x) free(x)
    static inline void *pico_zalloc(size_t size)
    {
        void *ptr = malloc(size);
    
        if(ptr)
            memset(ptr, 0u, size);
    
        return ptr;
    }
    
    extern volatile pico_time lpc_tick;
    
    static inline pico_time PICO_TIME_MS(void)
    {
        return lpc_tick;
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
