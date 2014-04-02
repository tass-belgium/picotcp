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

#define dbg

#ifdef PICO_SUPPORT_RTOS

#   define PICO_SUPPORT_MUTEX
extern void *pico_mutex_init(void);
extern void pico_mutex_lock(void*);
extern void pico_mutex_unlock(void*);
extern void *pvPortMalloc( size_t xSize );
extern void vPortFree( void *pv );

extern uint32_t max_mem;
extern uint32_t cur_mem;

struct mem_chunk_stats {
    uint32_t signature;
    void *mem;
    uint32_t size;
};


static inline void *pico_zalloc(size_t x)
{
    void *ptr;
    struct mem_chunk_stats *stats;
    if ((cur_mem + x) > (10 * 1024))
        return NULL;

    /* check for -1 malloc */
    if (x == 0xffffffff)
        while (1) ;
    /* allocated size + stats */
    stats = (struct mem_chunk_stats *)pvPortMalloc(x + sizeof(struct mem_chunk_stats));
    if(stats)
        memset(stats, 0u, x + sizeof(struct mem_chunk_stats));
    else
        return -1;

    /* fill in stats */
    stats->signature = 0xdeadbeef;
    stats->mem = ((uint8_t *)stats) + sizeof(struct mem_chunk_stats);
    stats->size = x;

    cur_mem += x;
    if (cur_mem > max_mem) {
        max_mem = cur_mem;
        /*      printf("max mem: %lu\n", max_mem); */
    }

    return (void*)(stats->mem);
}

static inline void pico_free(void *x)
{
    struct mem_chunk_stats *stats = (struct mem_chunk_stats *) ((uint8_t *)x - sizeof(struct mem_chunk_stats));

    if ((stats->signature != 0xdeadbeef) || (x != stats->mem)) {
        //printf(">> FREE ERROR: caller is %p\n", __builtin_return_address(0));
        while(1) ;
    }

    cur_mem -= stats->size;
    memset(stats, 0, sizeof(struct mem_chunk_stats));
    vPortFree(stats);
}

#else

# define pico_free(x) free(x)
static inline void *pico_zalloc(size_t size)
{
    void *ptr = malloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

#endif /* IFNDEF RTOS */

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

#endif
