#ifndef _INCLUDE_PICO_CONFIG
#define _INCLUDE_PICO_CONFIG
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_constants.h"



/*** *** *** *** *** *** ***
 *** USER CONFIGURATION  ***
 *** *** *** *** *** *** ***/

/* Enable the following if the system is big endian */
// #define PICO_BIGENDIAN

/* Network protocols */
#define PICO_SUPPORT_IPV4
//#define PICO_SUPPORT_IPV6


/* ICMP 4: depends on IPV4 */
#define PICO_SUPPORT_ICMP4

/* Transport protocols: require at least 
   one network protocol */
#define PICO_SUPPORT_UDP
#define PICO_SUPPORT_TCP

/*** *** *** *** *** *** ***
 *** PLATFORM SPECIFIC   ***
 *** *** *** *** *** *** ***/
#include "arch/pico_posix.h"
//#include "arch/pico_stm32.h"

#endif
