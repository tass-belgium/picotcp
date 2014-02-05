/*********************************************************************
   PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Ewoud Van Craeynest <ewoud.van.craeynest@tass.be>
 *********************************************************************/

#ifndef __PICO_VECTOR_EXT_H__
#define __PICO_VECTOR_EXT_H__

#include "pico_vector.h"

/**
 * @brief Header for extensions to pico_vector
 * 
 * Things like push_front, pop_front, insert, remove that are generally considered slow on vectors
 * Depending on the size of your data and your system, might still be faster than a linked list
 * But do choose the right one for your application!!!
 *
 * This can be optimized! Moves on pop_front could be avoided, but aren't at the moment ...
 * Contact <ewoud.van.craeynest@tass.be> if this is desired
 */


/**
 * @brief Copies one element of 'vector->type_size to the front of the vector
 * All current data has to be moved with sizeof(type)
 * Might cause the capacity to grow (choose your allocation_strategy wisely)
 */
int pico_vector_push_front(struct pico_vector* vector, void* element);


/**
 * @brief Copies sequence of num_elements of 'vector->type_size to the front of the vector
 * All current data has to be moved with sizeof(type)*num_elements
 * Might cause the capacity to grow (choose your allocation_strategy wisely)
 */
int pico_vector_push_front_x(struct pico_vector* vector, void* element, size_t num_elements);


/**
 * @brief Pop an element from the end of the vector of which you assume ownership
 * All data has to be moved with sizeof(type)
 * Doesn't change capacity!
 */
void* pico_vector_pop_front(struct pico_vector* vector);


/**
 * @brief Pops num_elements off the front of the vector and copies (you assume ownership)
 * All data has to be moved with sizeof(type)*num_elements
 * Doesn't change capacity!
 */
void* pico_vector_pop_front_x(struct pico_vector* vector, size_t num_elements);




#endif //__PICO_VECTOR_EXT_H__
