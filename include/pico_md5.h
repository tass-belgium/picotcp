/*********************************************************************
 *    PicoTCP. Copyright (c) 2015 Altran Intelligent Systems. Some rights reserved.
 *    See LICENSE and COPYING for usage.
 *
 *    Authors: Daniele Lacamera
 *    *********************************************************************/

#ifndef PICO_MD5_INCLUDE
#define PICO_MD5_INCLUDE

#include <stdint.h>
#include <stdlib.h>

void pico_md5sum(uint8_t *dst, const uint8_t *src, size_t len);
void pico_register_md5sum(void (*md5)(uint8_t *, const uint8_t *, size_t));

#endif /* PICO_MD5_INCLUDE */
