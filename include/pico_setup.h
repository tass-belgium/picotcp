#ifndef PICO_SETUP_H
#define PICO_SETUP_H

/* Setup: POSIX */

/* Get numeric types from stdint.h */
#include <stdint.h>

/* Use stdlib.h */
#include <stdlib.h>
#define pico_zalloc(x) calloc(1,x)
#define pico_alloc(x) malloc(x)
#define pico_free(x) free(x)

#endif
