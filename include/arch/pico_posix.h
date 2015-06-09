/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.
 *********************************************************************/

#ifndef PICO_SUPPORT_POSIX
#define PICO_SUPPORT_POSIX

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

/*
   #define MEMORY_MEASURE
   #define TIME_PRESCALE
   #define PICO_SUPPORT_THREADING
 */
#define dbg printf

#define stack_fill_pattern(...) do {} while(0)
#define stack_count_free_words(...) do {} while(0)
#define stack_get_free_words() (0)

#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)


static inline uint32_t PICO_TIME(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (uint32_t)t.tv_sec;
}

static inline uint32_t PICO_TIME_MS(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (uint32_t)((t.tv_sec * 1000) + (t.tv_usec / 1000));
}

static inline void PICO_IDLE(void)
{
    usleep(5000);
}

#endif  /* PICO_SUPPORT_POSIX */

