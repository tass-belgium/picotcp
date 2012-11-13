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

static inline void PICO_IDLE(void)
{
  usleep(5000);
}


static inline uint32_t pico_hash(char *name)
{
  unsigned long hash = 5381;
  int c;
  while ((c = *name++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  return hash;
}



