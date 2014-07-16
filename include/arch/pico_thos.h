#ifndef PICO_THOS_H
#define PICO_THOS_H



extern volatile unsigned long jiffies;
#define dbg do{}while(0)

static inline void *pico_zalloc(int len)
{
    /* TODO: 
    return calloc(len, 1);
    */
    (void)len;

    return NULL;
}

static inline void pico_free(void *tgt)
{
    (void)tgt;
    /* TODO:
    free(tgt);
    */
}



static inline unsigned long PICO_TIME(void)
{
    return jiffies / 100;
}

static inline unsigned long PICO_TIME_MS(void)
{
    return jiffies * 10;
}

static inline void PICO_IDLE(void)
{
    /* unused in thos */
}


#endif

