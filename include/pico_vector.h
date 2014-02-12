/*********************************************************************
   PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Ewoud Van Craeynest <ewoud.van.craeynest@tass.be>
 *********************************************************************/

#ifndef __PICO_VECTOR_H__
#define __PICO_VECTOR_H__

#include <stdint.h>
//#include "pico_zalloc.h" //<==== see mocking bug (sam)

/**
 * @brief Vector provides dynamic array functionality for the pico_tcp project
 *
 * Allows you to specify your own allocation_strategy by function pointer (see vector.allocation_strategy and pico_vector_allocation_strategy_times2)
 */

struct pico_vector;

#define PICO_VECTOR_COMMON_DATA        \
    size_t size;                       \
    size_t capacity;                   \
    size_t type_size;                           \
    void* (*allocation_strategy)(struct pico_vector* data);             


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
    }


/**
 * @brief Macro to generate vector initializer function for type
 * 
 */
#define DECLARE_PICO_VECTOR_INIT_FOR_TYPE(type) \
    type * pico_vector_ ##type##_init(struct pico_vector* vector, size_t capacity) { \
        vector->size = 0;                                                \
        vector->capacity = capacity;                                     \
        vector->allocation_strategy = pico_vector_allocation_strategy_times2;    \
        vector->type_size = sizeof(struct pico_vector_##type);                   \
        vector->data = pico_zalloc(sizeof(struct pico_vector_##type)*capacity);  \
        return vector->data;                                             \
    }


void*  pico_vector_init(struct pico_vector* vector, size_t capacity, size_t typesize);

/**
 * @brief Gets the element at 'index' from 'vector'
 */
#define pico_vector_get(vector, index) (vector->((uint8_t*)data)[index*vector->type_size])

/**
 * @brief Gets the size of the vector
 */
#define pico_vector_size(vector) ((vector)->size)

/**
 * @brief Iterator type for pico_vector
 */
struct pico_vector_iterator
{
    const struct pico_vector* vector;
    //void* ptr;
    void* data;
};

/**
 * @brief Gets an iterator to the beginning of the vector
 * If you don't run the iterator the end, you have to delete it yourself!
 */
struct pico_vector_iterator* pico_vector_begin(const struct pico_vector* vector);


/* /\** */
/*  * @brief Gets an iterator to the end of the vector */
/*  *\/ */
/* #define pico_vector_end(vector) ((pico_vector_iterator*)0) */

/**
 * @brief Gets the element at 'index' from 'vector', returns NULL if no elements left
 * Deletes the iterator object on return NULL. == Invalidating any pointer you have to the iterator!!!
 */
//#define pico_vector_safe_get(vector, index) (vector->((uint8_t*)data)[index*vector->type_size])
struct pico_vector_iterator* pico_vector_iterator_next(struct pico_vector_iterator* iterator);



/**
 * @brief Copy one element of 'vector->type_size' to the end of the vector
 * Might cause the capacity to grow (choose your allocation_strategy wisely)
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
 * Will invalidate any Iterators you might have kept!!
 */
void pico_vector_destroy(struct pico_vector* vector);




/**
 * @brief Allocation strategy function for doubling the capacity when in need of growth
 */
void* pico_vector_allocation_strategy_times2(struct pico_vector* vector);


#endif //__PICO_VECTOR_H__
