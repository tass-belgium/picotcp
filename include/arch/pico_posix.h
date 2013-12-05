#ifndef PICO_SUPPORT_POSIX
#define PICO_SUPPORT_POSIX

#define dbg printf

/*************************/

/*** MACHINE CONFIGURATION ***/
/* Temporary (POSIX) stuff. */
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>


#ifdef PICO_SUPPORT_DEBUG_MEMORY
static inline void *pico_zalloc(int len)
{
    //dbg("%s: Alloc object of len %d, caller: %p\n", __FUNCTION__, len, __builtin_return_address(0));
    return calloc(len, 1);
}

static inline void pico_free(void *tgt)
{
    //dbg("%s: Discarded object @%p, caller: %p\n", __FUNCTION__, tgt, __builtin_return_address(0));
    free(tgt);
}
#else
# define pico_zalloc(x) calloc(x, 1)
# define pico_free(x) free(x)
#endif



static inline pico_time PICO_TIME(void)
{
  struct timeval t;
  gettimeofday(&t, NULL);
  return (pico_time)t.tv_sec;
}

static inline pico_time PICO_TIME_MS(void)
{
  struct timeval t;
  gettimeofday(&t, NULL);
  return (pico_time)((t.tv_sec * 1000) + (t.tv_usec / 1000));
}

static inline void PICO_IDLE(void)
{
  usleep(5000);
}




#endif

