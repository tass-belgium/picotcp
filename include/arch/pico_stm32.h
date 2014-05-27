/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.
 *********************************************************************/
#define dbg(...) do {} while(0)
/* #define dbg printf */

extern volatile uint32_t tassTick;

#ifdef PICO_SUPPORT_RTOS
    #define PICO_SUPPORT_MUTEX
extern void *pico_mutex_init(void);
extern void pico_mutex_lock(void*);
extern void pico_mutex_unlock(void*);
extern void *pvPortMalloc( size_t xSize );
extern void vPortFree( void *pv );

    #define pico_free(x) vPortFree(x)
    #define free(x)      vPortFree(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = pvPortMalloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

static inline pico_time PICO_TIME_MS()
{
    return tassTick;
}

static inline pico_time PICO_TIME()
{
    return tassTick / 1000;
}

static inline void PICO_IDLE(void)
{
    uint32_t now = PICO_TIME_MS();
    while(now == PICO_TIME_MS()) ;
}

#else /* NO RTOS SUPPORT */
    #define pico_free(x) free(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = malloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

static inline unsigned long PICO_TIME(void)
{
    register uint32_t tick = tassTick;
    return tick / 1000;
}

static inline unsigned long PICO_TIME_MS(void)
{
    return tassTick;
}

static inline void PICO_IDLE(void)
{
    uint32_t now = PICO_TIME_MS();
    while(now == PICO_TIME_MS()) ;
}

#endif /* IFNDEF RTOS */

