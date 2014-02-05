
#include <stdlib.h>
#include "unity.h"
#include "pico_vector_extension.h"
#include "Mockpico_zalloc.h"

typedef struct dummy {
    uint8_t a;
    uint16_t b;
    uint64_t c;
} dummy;


void* memory;
size_t defaultcapacity = 10;


void setUp(void)
{
    memory = malloc(defaultcapacity*sizeof(dummy));
}

void tearDown(void)
{
    free(memory);
}


void test_pico_vector_pop_front(void)
{
    struct pico_vector vector;
    pico_zalloc_ExpectAndReturn(defaultcapacity*sizeof(dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(dummy)), memory);

    dummy d = {42,44,666};
    pico_vector_push_back(&vector, &d);
    dummy d2 = {22, 33, 999};
    pico_vector_push_back(&vector, &d2);

    dummy dummyAsIfMalloced;
    void* front;
    pico_zalloc_ExpectAndReturn(sizeof(dummy), &dummyAsIfMalloced); 
    TEST_ASSERT_EQUAL_PTR(&dummyAsIfMalloced, front = pico_vector_pop_front(&vector));

    TEST_ASSERT_EQUAL_MEMORY(&d, front, sizeof(d));

    TEST_ASSERT_EQUAL(vector.size, 1); 
    TEST_ASSERT_EQUAL(vector.capacity, defaultcapacity); 
    TEST_ASSERT_EQUAL_MEMORY(&d2, vector.data, sizeof(d));
}


