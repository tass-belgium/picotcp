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

#define IGNORE_PARAMETER(x)  ((void)x)

/*** *** *** *** *** *** ***
 *** PLATFORM SPECIFIC   ***
 *** *** *** *** *** *** ***/
#if defined STM32
# include "arch/pico_stm32.h"
#elif defined STELLARIS
# include "arch/pico_stellaris.h"
#elif defined LPC
# include "arch/pico_lpc1768.h"
#elif defined PIC24
# include "arch/pico_pic24.h"
#elif defined MSP430
# include "arch/pico_msp430.h"
#elif defined MBED_TEST
# include "arch/pico_mbed.h"
#elif defined FAULTY
# include "../test/pico_faulty.h"
/* #elif defined ... */

#else
# include "arch/pico_posix.h"
#endif

#endif
