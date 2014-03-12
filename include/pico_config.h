/*********************************************************************
  PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
  See LICENSE and COPYING for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_CONFIG
#define INCLUDE_PICO_CONFIG
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_constants.h"
#include "pico_mm.h"

#define IGNORE_PARAMETER(x)  ((void)x)

#define PICO_MEM_DEFAULT_SLAB_SIZE 1600
#define PICO_MEM_PAGE_SIZE 4096
#define PICO_MEM_PAGE_LIFETIME 100
#define PICO_MIN_HEAP_SIZE 600
#define PICO_MIN_SLAB_SIZE 1200
#define PICO_MAX_SLAB_SIZE 1600
#define PICO_MEM_MINIMUM_OBJECT_SIZE 4


/*** *** *** *** *** *** ***
 *** PLATFORM SPECIFIC   ***
 *** *** *** *** *** *** ***/
#if defined STM32
# include "arch/pico_stm32.h"
#elif defined STM32_GC
# include "arch/pico_stm32_gc.h"
#elif defined STELLARIS
# include "arch/pico_stellaris.h"
#elif defined LPC
# include "arch/pico_lpc1768.h"
#elif defined LPC43XX
# include "arch/pico_lpc43xx.h"
#elif defined LPC18XX
# include "arch/pico_lpc18xx.h"
#elif defined PIC24
# include "arch/pico_pic24.h"
#elif defined MSP430
# include "arch/pico_msp430.h"
#elif defined MBED_TEST
# include "arch/pico_mbed.h"
#elif defined AVR
# include "arch/pico_avr.h"
#elif defined STR9
# include "arch/pico_str9.h"
#elif defined FAULTY
# include "../test/pico_faulty.h"


/* #elif defined ... */

#else
# include "arch/pico_posix.h"
#endif

#ifdef PICO_SUPPORT_MM
#define PICO_ZALLOC(x) pico_mem_zalloc(x)
#define PICO_FREE(x) pico_mem_free(x)
#else
#define PICO_ZALLOC(x) pico_zalloc(x)
#define PICO_FREE(x) pico_free(x)
#endif  /* PICO_SUPPORT_MM */


#endif
