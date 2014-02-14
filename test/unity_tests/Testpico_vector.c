
#include <stdlib.h>
#include "unity.h"
#include "pico_vector.h"
#include "Mockpico_zalloc.h"

//DECLARE_PICO_VECTOR(int);
//DECLARE_PICO_VECTOR_INIT_FOR_TYPE(int);

typedef struct dummy {
    uint8_t a;
    uint16_t b;
    uint64_t c;
} dummy;


void* memory;
size_t defaultcapacity = 10;


void setUp()
{
    memory = malloc(defaultcapacity*sizeof(dummy));
}

void tearDown()
{
    free(memory);
}


void test_pico_vector_init(void)
{
    struct pico_vector vector;
    //void* somepointer = (void*)666;

    pico_zalloc_ExpectAndReturn(defaultcapacity*sizeof(dummy), memory);

    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(dummy)), memory);

    TEST_ASSERT_EQUAL(vector.size, 0);
    TEST_ASSERT_EQUAL(vector.capacity, defaultcapacity);
    TEST_ASSERT_EQUAL(vector.type_size, sizeof(dummy));
    TEST_ASSERT_EQUAL_PTR(vector.allocation_strategy, pico_vector_allocation_strategy_times2);
    TEST_ASSERT_EQUAL_PTR(vector.data, memory);
}


void test_pico_vector_size(void)
{
    struct pico_vector vector;
    pico_zalloc_ExpectAndReturn(defaultcapacity*sizeof(dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(dummy)), memory);

    TEST_ASSERT_EQUAL(pico_vector_size(&vector), 0);
}


void test_pico_vector_push_back(void)
{
    struct pico_vector vector;
    pico_zalloc_ExpectAndReturn(defaultcapacity*sizeof(dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(dummy)), memory);

    dummy d = {42,44,666};
    pico_vector_push_back(&vector, &d);

    TEST_ASSERT_EQUAL(pico_vector_size(&vector), 1);
    TEST_ASSERT_EQUAL_MEMORY(&d, vector.data, sizeof(d));

    pico_vector_push_back(&vector, &d);

    TEST_ASSERT_EQUAL(pico_vector_size(&vector), 2);
    TEST_ASSERT_EQUAL_MEMORY(&d, (uint8_t*)(vector.data)+sizeof(d), sizeof(d));
}


void test_pico_vector_grow(void)
{
    const size_t capacity = 2;
    struct pico_vector vector;
    pico_zalloc_ExpectAndReturn(capacity*sizeof(dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, capacity, sizeof(dummy)), memory);

    dummy d = {42,44,666};
    pico_vector_push_back(&vector, &d);
    pico_vector_push_back(&vector, &d);

    // Next push_back should "realloc"
    void* newmem = malloc(sizeof(d)*capacity*2);
    pico_zalloc_ExpectAndReturn(capacity*2*sizeof(dummy), newmem);
    pico_free_Expect(memory);

    pico_vector_push_back(&vector, &d);
    
    TEST_ASSERT_EQUAL(vector.size, 3);
    TEST_ASSERT_EQUAL(vector.capacity, capacity*2);
    TEST_ASSERT_EQUAL_PTR(vector.data, newmem);
    TEST_ASSERT_EQUAL_MEMORY(&d, (uint8_t*)(vector.data)+(sizeof(d)*2), sizeof(d));

    free(memory);
    memory = newmem; // freed on tearDown
}


void test_pico_vector_clear(void)
{
    struct pico_vector vector;
    pico_zalloc_ExpectAndReturn(defaultcapacity*sizeof(dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(dummy)), memory);

    dummy d = {42,44,666};
    pico_vector_push_back(&vector, &d);
    pico_vector_push_back(&vector, &d);

    pico_vector_clear(&vector);
    TEST_ASSERT_EQUAL(vector.size, 0);
    TEST_ASSERT_EQUAL(vector.capacity, defaultcapacity);
}


void test_pico_vector_destroy(void)
{
    struct pico_vector vector;
    pico_zalloc_ExpectAndReturn(defaultcapacity*sizeof(dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(dummy)), memory);

    dummy d = {42,44,666};
    pico_vector_push_back(&vector, &d);
    pico_vector_push_back(&vector, &d);

    pico_free_Expect(vector.data);

    pico_vector_destroy(&vector);

    TEST_ASSERT_EQUAL(vector.size, 0);
    TEST_ASSERT_EQUAL(vector.capacity, 0);
    TEST_ASSERT_EQUAL(vector.type_size, 0);
    TEST_ASSERT_EQUAL_PTR(vector.allocation_strategy, 0);
    TEST_ASSERT_EQUAL_PTR(vector.data, 0);
}


void test_pico_iterator(void)
{
    struct pico_vector_iterator* it;
    struct pico_vector_iterator actualIt;

    struct pico_vector vector;
    pico_zalloc_ExpectAndReturn(defaultcapacity*sizeof(dummy), memory);
    TEST_ASSERT_EQUAL_PTR(pico_vector_init(&vector, defaultcapacity, sizeof(dummy)), memory);

    // No allocation is expected, empty vector ...
    TEST_ASSERT_NULL((it = pico_vector_begin(&vector)));

    dummy d = {42, 44, 666};
    pico_vector_push_back(&vector, &d);
    pico_vector_push_back(&vector, &d);

    pico_zalloc_ExpectAndReturn(sizeof(actualIt), &actualIt);
    TEST_ASSERT_EQUAL_PTR((it = pico_vector_begin(&vector)), &actualIt);
    TEST_ASSERT_EQUAL_PTR(it->data, vector.data);
    TEST_ASSERT_EQUAL_PTR(it->vector, &vector);

    it = pico_vector_iterator_next(it);
    TEST_ASSERT_EQUAL_PTR(it->data, (uint8_t*)(vector.data)+vector.type_size);
    TEST_ASSERT_EQUAL_PTR(it->vector, &vector);

    //THIS SHOULD NOT BE HERE!!!!
    pico_free_Expect(it);
    TEST_ASSERT_NULL((it = pico_vector_iterator_next(it)));
}
