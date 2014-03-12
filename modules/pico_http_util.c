/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Andrei Carp <andrei.carp@tass.be>
 *********************************************************************/

#include <stdint.h>
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_protocol.h"
#include "pico_http_util.h"

#if defined PICO_SUPPORT_HTTP_CLIENT || defined PICO_SUPPORT_HTTP_SERVER

int pico_itoaHex(uint16_t port, char *ptr)
{
    int size = 0;
    int index;

    /* transform to from number to string [ in backwards ] */
    while(port)
    {
        ptr[size] = (char)(((port & 0xF) < 10) ? ((port & 0xF) + '0') : ((port & 0xF) - 10 + 'a'));
        port = port >> 4u; /* divide by 16 */
        size++;
    }
    /* invert positions */
    for(index = 0; index < (size / 2); index++)
    {
        char c = ptr[index];
        ptr[index] = ptr[size - index - 1];
        ptr[size - index - 1] = c;
    }
    ptr[size] = '\0';
    return size;
}

uint32_t pico_itoa(uint32_t port, char *ptr)
{
    uint32_t size = 0;
    uint32_t index;

    /* transform to from number to string [ in backwards ] */
    while(port)
    {
        ptr[size] = (char)(port % 10 + '0');
        port = port / 10;
        size++;
    }
    /* invert positions */
    for(index = 0; index < (size >> 1u); index++)
    {
        char c = ptr[index];
        ptr[index] = ptr[size - index - 1];
        ptr[size - index - 1] = c;
    }
    ptr[size] = '\0';
    return size;
}

/*
 * The function decodes a percent-encoded url (src).
 * The result is saved to dst.
 */
void pico_http_url_decode(char *dst, const char *src)
{
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (pico_is_hex(a) && pico_is_hex(b)))
        {
            if (a >= 'a')
                a = (char)(a - 'a' - 'A');

            if (a >= 'A')
                a = (char)(a - 'A' - 10);
            else
                a = (char)(a - '0');

            if (b >= 'a')
                b = (char)(b - 'a' - 'A');

            if (b >= 'A')
                b = (char)(b - ('A' - 10));
            else
                b = (char)(b - '0');

            *dst++ = (char)(16 * a + b);
            src += 3;
        }
        else
        {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}


#endif
