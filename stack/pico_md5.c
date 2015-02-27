/*********************************************************************
 *    PicoTCP. Copyright (c) 2015 Altran Intelligent Systems. Some rights reserved.
 *    See LICENSE and COPYING for usage.
 *
 *    Authors: Daniele Lacamera
 *    *********************************************************************/


#include <stdint.h>

#ifdef CTAOCRYPT
#include <cyassl/ctaocrypt/md5.h>

void pico_md5sum(uint8_t *dst, uint8_t *src, int len)
{
    Md5 md5;
    InitMd5(&md5);
    Md5Update(&md5, src, len);
    Md5Final(&md5, dst);
}


#else
static void (*do_pico_md5sum)(uint8_t *dst, const uint8_t *src, int len);
void pico_md5sum(uint8_t *dst, const uint8_t *src, int len)
{
    if (do_pico_md5sum) {
        do_pico_md5sum(dst, src, len);
    }
}

void pico_register_md5sum(void (*md5)(uint8_t *, const uint8_t *, int))
{
    do_pico_md5sum = md5;
}
#endif
