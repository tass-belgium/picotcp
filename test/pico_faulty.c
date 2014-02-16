#include <stdint.h>
#include <stdio.h>

#warning "COMPILING for MEMORY TESTS!"

uint32_t mm_failure_count = 0;


int pico_set_mm_failure(uint32_t nxt)
{
    mm_failure_count = nxt;
    return 0;
}
