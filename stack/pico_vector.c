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
    vector->data = pico_zalloc(typesize*capacity); 
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
    void* newmem = pico_zalloc(vector->type_size*vector->capacity*2);
    memcpy(newmem, vector->data, vector->type_size*vector->capacity);
    pico_free(vector->data);
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
    pico_free(vector->data);
    memset(vector, 0, sizeof(struct pico_vector));
}


struct pico_vector_iterator* pico_vector_begin(const struct pico_vector* vector)
{
    if (vector->size == 0)
        return NULL;

    struct pico_vector_iterator* it = pico_zalloc(sizeof(struct pico_vector_iterator));
    it->vector = vector;
    it->data = vector->data;
    return it;
}


struct pico_vector_iterator* pico_vector_iterator_next(struct pico_vector_iterator* iterator)
{
    if (iterator->data == (iterator->vector->data + iterator->vector->type_size * iterator->vector->size))
    {
        pico_free(iterator);
        return NULL;
    }
    
    iterator->data += iterator->vector->type_size;
    return iterator;
}


void* pico_vector_pop_front(struct pico_vector* vector)
{
    uint8_t* from, *to;
    void* data = pico_zalloc(vector->type_size);
    memcpy(data, vector->data, vector->type_size);
    
    // not using memmove, standard is unclear about what happens under the hood
    // is a malloc is used, we're bummed .. it bypasses pico_zalloc

    for(from = vector->data+vector->type_size, to = vector->data;
        from < vector->data+(vector->type_size*vector->size);
        ++to, ++from)
    {
        *to = *from;
    }
        
    vector->size--;
    return data;
}
