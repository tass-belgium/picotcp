/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.
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

#define MEM_LIMIT (0)

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>

extern uint32_t mm_failure_count;
int pico_set_mm_failure(uint32_t nxt);
extern uint32_t max_mem;
extern uint32_t cur_mem;

/*
   #define TIME_PRESCALE
 */
#define dbg printf

#define stack_fill_pattern(...) do {} while(0)
#define stack_count_free_words(...) do {} while(0)
#define stack_get_free_words() (0)

static inline void mem_stat_store(void)
{
    char fname_mod[] = "/tmp/pico-mem-report-%hu.txt";
    char fname[200];
    char buffer[20];
    int fd;
    snprintf(fname, 200, fname_mod, getpid());
    fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0660);
    if (fd < 0) {
        return;
    }

    snprintf(buffer, 20, "%d\n", max_mem);
    write(fd, buffer, strlen(buffer));
    close(fd);
}


static inline void *pico_zalloc(size_t x)
{
    uint32_t *ptr;
    if (mm_failure_count > 0) {
        if (--mm_failure_count == 0) {
            fprintf(stderr, "Malloc failed, for test purposes\n");
            return NULL;
        }
    }

    ptr = (uint32_t *)calloc(x + sizeof(uint32_t), 1);
    *ptr = (uint32_t)x; /* store size of alloc */
    cur_mem += (uint32_t)x;

#ifndef DISABLE_MM_STATS
    if (cur_mem > max_mem) {
        max_mem = cur_mem;
        if ((MEM_LIMIT > 0) && (max_mem > MEM_LIMIT))
            abort();

        mem_stat_store();
    }

#endif
    return (void*)(ptr + 1);
}

static inline void pico_free(void *x)
{
    uint32_t *ptr = (uint32_t*)(((uint8_t *)x) - sizeof(uint32_t)); /* fetch size of the alloc */
    cur_mem -= *ptr;
    free(ptr);
}

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

void memory_stats(void);

#endif  /* PICO_SUPPORT_POSIX */

