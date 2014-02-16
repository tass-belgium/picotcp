/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.
   Do not redistribute without a written permission by the Copyright
   holders.
 *********************************************************************/


/* This is a test implementation, with a faulty memory manager, 
 * intended to increase test coverage 
 * Warning: not intended for production!
 * 
 */


#ifndef PICO_SUPPORT_POSIX
#define PICO_SUPPORT_POSIX

#define PICO_FAULTY

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

extern uint32_t mm_failure_count;
int pico_set_mm_failure(uint32_t nxt);

/*
   #define TIME_PRESCALE
 */
#define dbg printf

#define stack_fill_pattern(...) do {} while(0)
#define stack_count_free_words(...) do {} while(0)
#define stack_get_free_words() (0)


static inline void *pico_zalloc(uint32_t x)
{
    if (mm_failure_count > 0) {
        if (--mm_failure_count == 0) {
            fprintf(stderr, "Malloc failed, for test purposes\n");
            return NULL;
        }
    }
    return calloc(x, 1);
}

#define pico_free(x) free(x)


/* time prescaler */
#ifdef TIME_PRESCALE
extern int32_t prescale_time;
#endif

static inline uint32_t PICO_TIME(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
  #ifdef TIME_PRESCALE
    return (prescale_time < 0) ? (uint32_t)(t.tv_sec / 1000 << (-prescale_time)) : \
           (uint32_t)(t.tv_sec / 1000 >> prescale_time);
  #else
    return (uint32_t)t.tv_sec;
  #endif
}

static inline uint32_t PICO_TIME_MS(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
  #ifdef TIME_PRESCALER
    uint32_t tmp = ((t.tv_sec * 1000) + (t.tv_usec / 1000));
    return (prescale_time < 0) ? (uint32_t)(tmp / 1000 << (-prescale_time)) : \
           (uint32_t)(tmp / 1000 >> prescale_time);
  #else
    return (uint32_t)((t.tv_sec * 1000) + (t.tv_usec / 1000));
  #endif
}

static inline void PICO_IDLE(void)
{
    usleep(5000);
}

#endif  /* PICO_SUPPORT_POSIX */

