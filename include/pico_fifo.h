/*********************************************************************
   PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Ewoud Van Craeynest <ewoud.van.craeynest@tass.be>
 *********************************************************************/


#ifndef __PICO_ZMTP_FIFO_H__
#define __PICO_ZMTP_FIFO_H__

#include "vector_extension.h"

/**
 * @brief Adapter header for a fifo that is actually a vector at the moment
 */

#define pico_fifo pico_vector

#define pico_fifo_init(fifo)       pico_vector_init(fifo, 10)
#define pico_fifo_push_back(fifo)  pico_vector_push_back(fifo)
#define pico_fifo_pop_front(fifo)  pico_vector_pop_front(fifo)
#define pico_fifo_clear(fifo)      pico_vector_clear(fifo)
#define pico_fifi_destroy(fifo)    pico_vector_destroy(fifo)


#endif //__PICO_ZMTP_FIFO_H__
