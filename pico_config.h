/* Temporary (POSIX) stuff. */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)
#define dbg printf
