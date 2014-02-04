/*********************************************************************
   PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Ewoud Van Craeynest <ewoud.van.craeynest@tass.be>
 *********************************************************************/

#ifndef __PICO_VECTOR_H__
#define __PICO_VECTOR_H__

//#include <stdint.h>


/**
 * @brief Vector provides dynamic array functionality for the pico_tcp project
 *
 * Allows you to specify your own allocation_strategy by function pointer (see vector.allocation_strategy and pico_vector_allocation_strategy_times2)
 */


#define PICO_VECTOR_COMMON_DATA        \
    size_t size;                       \
    size_t capacity;                   \
    size_t type_size;                           \
    void* (*allocation_strategy)(void* data);             

struct pico_vector
{
    PICO_VECTOR_COMMON_DATA;
    void* data;
};

/**
 * @brief pico_vector for a certain type
 * Same memory layout as pico_vector, but with different type for data
 * Allows to do vector->data[x] with correct offsetting
 */
#define DECLARE_PICO_VECTOR(type) \
    struct pico_vector_##type     \
    {                             \
        PICO_VECTOR_COMMON_DATA;  \
        type* data;               \
    };


/**
 * @brief Macro to generate vector initializer function for type
 * 
 */
#define DECLARE_PICO_VECTOR_INIT_FOR_TYPE(type) \
    type * pico_vector_ ##type _init(struct pico_vector* vector, int capacity) { \
        vector.size = 0;                                                \
        vector.capacity = capacity;                                     \
        vector.allocation_strategy = pico_vector_allocation_strategy_times2;    \
        vector.type_size = sizeof(struct pico_vector_##type);                   \
        vector.data = pico_zalloc(sizeof(struct pico_vector_##type)*capacity);  \
        return vector.data;                                             \
    }                                                                   \


/**
 * @brief Gets the element at 'index' from 'vector'
 */
#define pico_vector_get(vector, index) (vector->((uint8_t*)data)[index*vector->type_size])

/**
 * @brief Gets the size of the vector
 */
#define pico_vector_size(vector) (vector->size)

/**
 * @brief Iterator type for pico_vector
 */
struct pico_vector_iterator;

/**
 * @brief Gets an iterator to the beginning of the vector
 */
pico_vector_iterator* pico_vector_begin(const struct pico_vector* vector);

/* /\** */
/*  * @brief Gets an iterator to the end of the vector */
/*  *\/ */
/* #define pico_vector_end(vector) ((pico_vector_iterator*)0) */

/**
 * @brief Gets the element at 'index' from 'vector', returns NULL if no elements left
 */
//#define pico_vector_safe_get(vector, index) (vector->((uint8_t*)data)[index*vector->type_size])
void* pico_vector_itarator_next(const pico_vector_iterator* iterator, int index);



/**
 * @brief Add one element of 'vector->type_size'
 * Might change capacity!
 */
int pico_vector_push_back(struct pico_vector* vector, void* data);


/**
 * @brief Pop an element from the end of the vector of which you assume ownership
 * Doesn't change capacity!
 */
void* pico_vector_pop_back(struct pico_vector* vector);


/**
 * @brief Clears all elements from the vector.
 * Doesn't change capacity!
 */
void pico_vector_clear(struct pico_vector* vector);


/**
 * @brief Destroys a vector
 * Will release internal memory and zero out the vector struct
 */
void pico_vector_destroy(struct pico_vector* vector);




/**
 * @brief Allocation strategy function for doubling the capacity when in need of growth
 */
void* pico_vector_allocation_strategy_times2(void *data);


#endif //__PICO_VECTOR_H__
