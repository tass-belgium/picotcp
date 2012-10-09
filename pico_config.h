#ifndef _INCLUDE_PICO_CONFIG
#define _INCLUDE_PICO_CONFIG

/* Temporary (POSIX) stuff. */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)

static inline unsigned long PICO_TIME(void)
{
  struct timeval t;
  gettimeofday(&t, NULL);
  return (t.tv_sec);
}

static inline unsigned long PICO_TIME_MS(void)
{
  struct timeval t;
  gettimeofday(&t, NULL);
  return (t.tv_sec * 1000) + (t.tv_usec / 1000);
}


static inline uint32_t pico_hash(char *name)
{
  unsigned long hash = 5381;
  int c;
  while ((c = *name++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  return hash;
}

#define dbg printf
#endif
