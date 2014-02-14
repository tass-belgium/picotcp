
#include <stdlib.h>
#include "unity.h"
#include "pico_vector_extension.h"
#include "Mockpico_mm.h"

//TODO: remove following 2 lines if makefile is refactored!!
#include "pico_protocol.h"
volatile pico_err_t pico_err;

struct dummy {
    uint8_t a;
    uint16_t b;
    uint64_t c;
};


void* memory;
size_t defaultcapacity = 10;


void setUp(void)
{
    memory = malloc(defaultcapacity*sizeof(struct dummy));
}

void tearDown(void)
{
    free(memory);
}


void test_pico_vector_pop_front(void)
{
    struct pico_vector vector;
    void* front;
    struct dummy d = {42,44,666};
    struct dummy d2 = {22, 33, 999};
    struct dummy dummyAsIfMalloced;

    pico_mem_zalloc_ExpectAndReturn(defaultcapacity*sizeof(struct dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(struct dummy)), memory);

    pico_vector_push_back(&vector, &d);
    pico_vector_push_back(&vector, &d2);



    pico_mem_zalloc_ExpectAndReturn(sizeof(struct dummy), &dummyAsIfMalloced); 
    TEST_ASSERT_EQUAL_PTR(&dummyAsIfMalloced, front = pico_vector_pop_front(&vector));

    TEST_ASSERT_EQUAL_MEMORY(&d, front, sizeof(d));

    TEST_ASSERT_EQUAL(vector.size, 1); 
    TEST_ASSERT_EQUAL(vector.capacity, defaultcapacity); 
    TEST_ASSERT_EQUAL_MEMORY(&d2, vector.data, sizeof(d));
}


