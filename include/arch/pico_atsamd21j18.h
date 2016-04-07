/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.
 *********************************************************************/
#define dbg(...) do {} while(0)

/******************/

/*** MACHINE CONFIGURATION ***/
/* Temporary (POSIX) stuff. */
#include <string.h>
#include <unistd.h>

extern volatile uint32_t sam_tick;

#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)

static inline unsigned long PICO_TIME(void)
{
    register uint32_t tick = sam_tick;
    return tick / 1000;
}

static inline unsigned long PICO_TIME_MS(void)
{
    return sam_tick;
}

static inline void PICO_IDLE(void)
{
    unsigned long tick_now = sam_tick;
    while(tick_now == sam_tick) ;
}

