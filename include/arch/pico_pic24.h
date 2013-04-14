#ifndef PICO_SUPPORT_PIC24
#define PICO_SUPPORT_PIC24
#define dbg(...) do{}while(0)

/*************************/

/*** MACHINE CONFIGURATION ***/
//#include <string.h>
//#include <stdio.h>

#include "phalox_development_board.h"

#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)

extern volatile unsigned long __pic24_tick;

static inline unsigned long PICO_TIME(void)
{
  unsigned long tick;
  // Disable timer interrupts
  TIMBASE_INT_E = 0;
  tick = __pic24_tick;
  // Enable timer interrupts
  TIMBASE_INT_E = 1;
  return tick / 1000;
}

static inline unsigned long PICO_TIME_MS(void)
{
  unsigned long tick;
  // Disable timer interrupts
  TIMBASE_INT_E = 0;
  tick = __pic24_tick;
  // Enable timer interrupts
  TIMBASE_INT_E = 1;
  return tick;
}

static inline void PICO_IDLE(void)
{
  unsigned long tick_now;
  // Disable timer interrupts
  TIMBASE_INT_E = 0;
  tick_now = pico_tick;
  // Enable timer interrupts
  TIMBASE_INT_E = 1;
  // Doesn't matter that this call isn't interrupt safe,
  // we just check for the value to change
  while(tick_now == __pic24_tick);
}

#endif
