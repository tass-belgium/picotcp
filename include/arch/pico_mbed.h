/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.
   Do not redistribute without a written permission by the Copyright
   holders.

   File: pico_mbed.h
   Author: Toon Peters
 *********************************************************************/

#ifndef PICO_SUPPORT_MBED
#define PICO_SUPPORT_MBED
#include <stdio.h>
/* #include "mbed.h" */
/* #include "serial_api.h" */

/* #define TIME_PRESCALE */
/* #define PICO_MEASURE_STACK */
/* #define MEMORY_MEASURE */
/*
   Debug needs initialization:
 * void serial_init       (serial_t *obj, PinName tx, PinName rx);
 * void serial_baud       (serial_t *obj, int baudrate);
 * void serial_format     (serial_t *obj, int data_bits, SerialParity parity, int stop_bits);
 */

#define dbg(...)

/* Intended for Mr. Jenkins endurance test loggings */
#ifdef JENKINS_DEBUG
#include "PicoTerm.h"
#define jenkins_dbg ptm_dbg
#endif

#ifdef PICO_MEASURE_STACK

extern int freeStack;
#define STACK_TOTAL_WORDS   1000u
#define STACK_PATTERN       (0xC0CAC01A)

void stack_fill_pattern(void *ptr);
void stack_count_free_words(void *ptr);
int stack_get_free_words(void);
#else
#define stack_fill_pattern(...) do {} while(0)
#define stack_count_free_words(...) do {} while(0)
#define stack_get_free_words() (0)
#endif

#ifdef MEMORY_MEASURE /* in case, comment out the two defines above me. */
extern uint32_t max_mem;
extern uint32_t cur_mem;

static inline void *pico_zalloc(int x)
{
    uint32_t *ptr;
    if ((cur_mem + x) > (10 * 1024))
        return NULL;

    ptr = (uint32_t *)calloc(x + 4, 1);

    /* Intended for Mr. Jenkins endurance test loggings */
    #ifdef JENKINS_DEBUG
    if (!ptr)
        jenkins_dbg(">> OUT OF MEM\n");

    #endif
    *ptr = (uint32_t)x;
    cur_mem += x;
    if (cur_mem > max_mem) {
        max_mem = cur_mem;
        /*      printf("max mem: %lu\n", max_mem); */
    }

    return (void*)(ptr + 1);
}

static inline void pico_free(void *x)
{
    uint32_t *ptr = (uint32_t*)(((uint8_t *)x) - 4);
    cur_mem -= *ptr;
    free(ptr);
}
#else

#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)

#endif

#define PICO_SUPPORT_MUTEX
extern void *pico_mutex_init(void);
extern void pico_mutex_lock(void*);
extern void pico_mutex_unlock(void*);

extern uint32_t os_time;
extern uint64_t local_time;
extern uint32_t last_os_time;

#ifdef TIME_PRESCALE
extern int32_t prescale_time;
#endif
extern uint32_t os_time;

#define UPDATE_LOCAL_TIME() do {local_time = local_time + (os_time - last_os_time);last_os_time = os_time;} while(0)

static inline uint64_t PICO_TIME(void)
{
    UPDATE_LOCAL_TIME();
  #ifdef TIME_PRESCALE
    return (prescale_time < 0) ? (uint64_t)(local_time / 1000 << (-prescale_time)) : \
           (uint64_t)(local_time / 1000 >> prescale_time);
  #else
    return (uint64_t)(local_time / 1000);
  #endif
}

static inline uint64_t PICO_TIME_MS(void)
{
    UPDATE_LOCAL_TIME();
  #ifdef TIME_PRESCALE
    return (prescale_time < 0) ? (uint64_t)(local_time << (-prescale_time)) : \
           (uint64_t)(local_time >> prescale_time);
  #else
    return (uint64_t)local_time;
  #endif
}

static inline void PICO_IDLE(void)
{
    /* TODO needs implementation */
}
/*
   static inline void PICO_DEBUG(const char * formatter, ... )
   {
   char buffer[256];
   char *ptr;
   va_list args;
   va_start(args, formatter);
   vsnprintf(buffer, 256, formatter, args);
   ptr = buffer;
   while(*ptr != '\0')
    serial_putc(serial_t *obj, (int) (*(ptr++)));
   va_end(args);
   //TODO implement serial_t
   }*/

#endif
