
/*************************/

 #define dbg(...) do {} while(0)
/* #define dbg printf */

extern volatile pico_time full_tick;
extern volatile uint32_t sys_tick_counter;
extern volatile uint32_t __stm32_tick;

#ifdef PICO_SUPPORT_RTOS
    #define PICO_SUPPORT_MUTEX
extern void *pico_mutex_init(void);
extern void pico_mutex_lock(void*);
extern void pico_mutex_unlock(void*);
extern void *pvPortMalloc( size_t xSize );
extern void vPortFree( void *pv );

    #define pico_free(x) vPortFree(x)

static inline void *pico_zalloc(size_t size)
{
    void *ptr = pvPortMalloc(size);

    if(ptr)
        memset(ptr, 0u, size);

    return ptr;
}

static inline pico_time PICO_TIME_MS(void)
{
    if ((full_tick & 0xFFFFFFFF) > sys_tick_counter) {
        full_tick +=  0x100000000ULL;
    }

    full_tick = (full_tick & 0xFFFFFFFF00000000ULL) + sys_tick_counter;
    return full_tick;
}

static inline pico_time PICO_TIME()
{
    return PICO_TIME_MS() >> 10;     /* TODO: quick-hack bc no c-lib avail */
}

static inline void PICO_IDLE(void)
{
    pico_time now = PICO_TIME_MS();
    while(now == PICO_TIME_MS()) ;
}

#else /* NO RTOS SUPPORT */
    #error Not implemented for STM32_GC
#endif /* IFNDEF RTOS */

