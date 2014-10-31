/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef _INCLUDE_PICO_ESP8266
#define _INCLUDE_PICO_ESP8266

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_constants.h"

extern pico_time esp8266_time_s(void);
extern pico_time esp8266_time_ms(void);
extern void *malloc(size_t);
extern void free(void *);


#define PICO_TIME() esp8266_time_s()
#define PICO_TIME_MS() esp8266_time_ms()
#define PICO_IDLE() do {} while(0)

#define pico_free(x) free(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = malloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

#define dbg(...)

#endif
