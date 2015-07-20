#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "pico_faulty.h"

/* #warning "COMPILING for MEMORY TESTS!" */

uint32_t mm_failure_count = 0;
uint32_t cur_mem, max_mem;

static int called_atexit = 0;


void memory_stats(void)
{
    fprintf(stderr, " ################ MAX MEMORY USED in this test: %u\n", max_mem);

}

int pico_set_mm_failure(uint32_t nxt)
{
    if (!called_atexit) {
        atexit(memory_stats);
        called_atexit++;
    }

    mm_failure_count = nxt;
    return 0;
}
