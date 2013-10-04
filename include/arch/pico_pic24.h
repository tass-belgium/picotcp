#ifndef PICO_SUPPORT_PIC24
#define PICO_SUPPORT_PIC24
#define dbg printf
//#define dbg(...)

/*************************/

/*** MACHINE CONFIGURATION ***/
#include <stdio.h>
#include <stdint.h>

//#include "phalox_development_board.h"

#ifndef __PIC24F__
#define __PIC24F__
#endif

#ifndef __PIC24FJ256GA106__
#define __PIC24FJ256GA106__
#endif

#ifndef PICO_SUPPORT_PING
#define PICO_SUPPORT_PING
#endif

#ifndef PICO_SUPPORT_IPV4
#define PICO_SUPPORT_IPV4
#endif

#ifndef PICO_SUPPORT_DHCP
//#define PICO_SUPPORT_DHCP
#endif

#ifndef PICO_SUPPORT_TCP
#define PICO_SUPPORT_TCP
#endif

#ifndef PICO_SUPPORT_ZMQ
//#define PICO_SUPPORT_ZMQ
#endif

#ifndef PICO_SUPPORT_ICMP4
#define PICO_SUPPORT_ICMP4
#endif

#ifndef PICO_SUPPORT_OLSR
#define PICO_SUPPORT_OLSR
#endif

#ifndef PICO_SUPPORT_UDP
#define PICO_SUPPORT_UDP
#endif

#ifndef PICO_MAX_SOCKET_FRAMES
#define PICO_MAX_SOCKET_FRAMES 16
#endif

/* Device header file */
#if defined(__PIC24E__)
# include <p24Exxxx.h>
#elif defined(__PIC24F__)
# include <p24Fxxxx.h>
#elif defined(__PIC24H__)
# include <p24Hxxxx.h>
#endif

#define TIMBASE_INT_E         IEC0bits.T2IE

static inline void * calloc_vnz(uint16_t size);

#define pico_zalloc(x) calloc_catch(x, __FILE__, __LINE__)
#define pico_free(x) free_catch(x, __FILE__, __LINE__)

extern void * pvPortMalloc( size_t xWantedSize );
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
