/*********************************************************************
   PicoTCP. Copyright (c) 2015 Altran ISY BeNeLux. Some rights reserved.
   See LICENSE and COPYING for usage.



   Author: Michele Di Pede
 *********************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include "pico_strings.h"

char *get_string_terminator_position(char * const block, size_t len)
{
    size_t length = pico_strnlen(block, len);

    return len != length? block + length: 0;
}

int pico_strncasecmp(const char * const str1, const char * const str2, size_t n)
{
    int ch1;
    int ch2;
    size_t i;

    for (i = 0; i < n; ++i) {
        ch1 = toupper(*(str1 + i));
        ch2 = toupper(*(str2 + i));
        if (ch1 < ch2)
            return -1;
        if (ch1 > ch2)
            return 1;
        if ((!ch1) && (!ch2))
            return 0;
    }

    return 1;
}

size_t pico_strnlen(const char *str, size_t n)
{
    size_t len = 0;

    for (; len < n && *(str + len); ++len);

    return len;
}

int num2string(uint32_t num, char *buf, int len)
{
    ldiv_t res;
    int pos = 0;
    int i;

    if (num > INT32_MAX)
        return -1;

    if (len < 2)
        return -2;

    pos = len;
    buf[--pos] = '\0';
    
    res.quot = (long)num;

    do {
        if (!pos)
            return -3;
        res = ldiv(res.quot, 10);
        buf[--pos] = (char)((res.rem + '0') & 0xFF);
    } while (res.quot);

    len -= pos;
    for (i = 0; i < len; ++i)
        buf[i] = buf[i + pos];

    return len;
}
