/*********************************************************************
 *    PicoTCP. Copyright (c) 2015 Altran Intelligent Systems. Some rights reserved.
 *    See LICENSE and COPYING for usage.
 *
 *    Authors: Daniele Lacamera
 *    *********************************************************************/

#ifdef PICO_MD5_INCLUDE
#define PICO_MD5_INCLUDE
void pico_md5sum(uint8_t *dst, uint8_t *src, int len)
void pico_register_md5sum(void (*md5)(uint8_t *, const uint8_t *, int))
#endif
