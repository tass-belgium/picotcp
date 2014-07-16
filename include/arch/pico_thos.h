#ifndef PICO_THOS_H
#define PICO_THOS_H



extern volatile unsigned long jiffies;

static inline void *pico_zalloc(int len)
{
    /* TODO: 
    return calloc(len, 1);
    */

    return NULL;
}

static inline void pico_free(void *tgt)
{
    /* TODO:
    free(tgt);
    */
}



static inline unsigned long PICO_TIME(void)
{
    register uint32_t tick = stellaris_tick;
    return jiffies / HZ;
}

static inline unsigned long PICO_TIME_MS(void)
{
    return jiffies * (1000 / HZ);
}

static inline void PICO_IDLE(void)
{
    /* unused in thos */
}

#endif



#endif
