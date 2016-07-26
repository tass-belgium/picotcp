
/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_PIC32
#define _INCLUDE_PICO_PIC32

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_constants.h"

/* monotonically increasing tick,
 * typically incremented every millisecond in a systick interrupt */
extern volatile unsigned int pico_ms_tick;

#define dbg printf

/* Use plain C-lib malloc and free */
#define pico_free(x) free(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = malloc(size);
    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

static inline pico_time PICO_TIME_MS(void)
{
    return (pico_time)pico_ms_tick;
}

static inline pico_time PICO_TIME(void)
{
    return (pico_time)(PICO_TIME_MS() / 1000);
}

static inline void PICO_IDLE(void)
{
    unsigned int now = pico_ms_tick;
    while(now == pico_ms_tick) ;
}

#endif  /* PICO_PIC32 */

