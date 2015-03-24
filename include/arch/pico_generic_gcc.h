/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_GCC
#define _INCLUDE_PICO_GCC

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_constants.h"

/* monotonically increasing tick,
 * typically incremented every millisecond in a systick interrupt */
extern volatile unsigned int tassTick;

#define dbg(...)

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

    #ifdef MEM_MEAS
        /* These functions should be implemented elsewhere */
        extern void * memmeas_zalloc(size_t size);
        extern void memmeas_free(void *);
        #define pico_free(x)    memmeas_free(x)
        #define pico_zalloc(x)  memmeas_zalloc(x)
    #else
        /* Use plain C-lib malloc and free */
        #define pico_free(x) free(x)
        static inline void *pico_zalloc(size_t size)
        {
            void *ptr = malloc(size);
            if(ptr)
                memset(ptr, 0u, size);
            return ptr;
        }
    #endif
    
    static inline pico_time PICO_TIME_MS(void)
    {
        return tassTick;
    }
    
    static inline pico_time PICO_TIME(void)
    {
        return PICO_TIME_MS() / 1000;
    }
    
    static inline void PICO_IDLE(void)
    {
        unsigned int now = tassTick;
        while(now == tassTick) ;
    }

#endif /* IFNDEF RTOS */

#endif  /* PICO_GCC */

