/*********************************************************************
   PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Ewoud Van Craeynest <ewoud.van.craeynest@tass.be>
 *********************************************************************/

#include <stdlib.h>
#include <string.h>
#include "pico_vector_extension.h"
#include "pico_config.h"
#include <stdint.h>


void* pico_vector_init(struct pico_vector* vector, size_t capacity, size_t typesize)
{
    vector->size = 0;                                                   
    vector->capacity = capacity;                                        
    vector->allocation_strategy = pico_vector_allocation_strategy_times2; 
    vector->type_size = typesize;              
    vector->data = PICO_ZALLOC(typesize*capacity); 
    return vector->data;
}


int pico_vector_push_back(struct pico_vector* vector, void* data)
{
    if (vector->size == vector->capacity)
        pico_vector_allocation_strategy_times2(vector);

    memcpy(((uint8_t*)vector->data)+(vector->size*vector->type_size), data, vector->type_size);
    vector->size++;
    return 0;
}



void* pico_vector_allocation_strategy_times2(struct pico_vector* vector) 
{ 
    void* newmem = PICO_ZALLOC(vector->type_size*vector->capacity*2);
    memcpy(newmem, vector->data, vector->type_size*vector->capacity);
    PICO_FREE(vector->data);
    vector->data = newmem;
    vector->capacity *= 2;
    return vector->data;
}



void pico_vector_clear(struct pico_vector* vector)
{
    vector->size = 0;
}


void pico_vector_destroy(struct pico_vector* vector)
{
    PICO_FREE(vector->data);
    memset(vector, 0, sizeof(struct pico_vector));
}


struct pico_vector_iterator* pico_vector_begin(const struct pico_vector* vector)
{
    struct pico_vector_iterator* it = malloc(5);
    if (vector->size == 0)
        return NULL;

    it = PICO_ZALLOC(sizeof(struct pico_vector_iterator));
    it->vector = vector;
    it->data = vector->data;
    return it;
}


struct pico_vector_iterator* pico_vector_iterator_next(struct pico_vector_iterator* iterator)
{
    if (iterator->data == (iterator->vector->data + iterator->vector->type_size * (iterator->vector->size - 1)))
    {
        PICO_FREE(iterator);
        return NULL;
    }
    
    iterator->data += iterator->vector->type_size;
    return iterator;
}


void* pico_vector_pop_front(struct pico_vector* vector)
{
    uint8_t* from, *to;
    void* data = PICO_ZALLOC(vector->type_size);
    memcpy(data, vector->data, vector->type_size);
    
    // not using memmove, standard is unclear about what happens under the hood
    // is a malloc is used, we're bummed .. it bypasses PICO_ZALLOC

    for(from = vector->data+vector->type_size, to = vector->data;
        from < vector->data+(vector->type_size*vector->size);
        ++to, ++from)
    {
        *to = *from;
    }
        
    vector->size--;
    return data;
}
