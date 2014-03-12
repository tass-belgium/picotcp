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

#define TRUE    1
#define FALSE 0

#define HTTP_PROTO_TOK      "http://"
#define HTTP_PROTO_LEN      7u

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
 * The function returns nonzero if chr is any of:
 * 0 1 2 3 4 5 6 7 8 9 a b c d e f A B C D E F
 */
int is_digit(char chr)
{
    if(('0' <= chr && chr <= '9') || ('a' <= chr && chr <= 'z') || ('0' <= chr && chr <= 'Z')) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * The function decodes a percent-encoded url (src).
 * The result is saved to dst.
 */
void url_decode(char *dst, const char *src)
{
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (is_digit(a) && is_digit(b)))
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

int8_t pico_processURI(const char *uri, struct pico_http_uri *urikey)
{

    uint16_t lastIndex = 0, index;

    if(!uri || !urikey || uri[0] == '/')
    {
        pico_err = PICO_ERR_EINVAL;
        goto error;
    }

    /* detect protocol => search for  "colon-slash-slash" */
    if(memcmp(uri, HTTP_PROTO_TOK, HTTP_PROTO_LEN) == 0) /* could be optimized */
    { /* protocol identified, it is http */
        urikey->protoHttp = TRUE;
        lastIndex = HTTP_PROTO_LEN;
    }
    else
    {
        if(strstr(uri, "://")) /* different protocol specified */
        {
            urikey->protoHttp = FALSE;
            goto error;
        }

        /* no protocol specified, assuming by default it's http */
        urikey->protoHttp = TRUE;
    }

    /* detect hostname */
    index = lastIndex;
    while(uri[index] && uri[index] != '/' && uri[index] != ':') index++;
    if(index == lastIndex)
    {
        /* wrong format */
        urikey->host = urikey->resource = NULL;
        urikey->port = urikey->protoHttp = 0u;
        pico_err = PICO_ERR_EINVAL;
        goto error;
    }
    else
    {
        /* extract host */
        urikey->host = (char *)PICO_ZALLOC((uint32_t)(index - lastIndex + 1));

        if(!urikey->host)
        {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        memcpy(urikey->host, uri + lastIndex, (size_t)(index - lastIndex));
    }

    if(!uri[index])
    {
        /* nothing specified */
        urikey->port = 80u;
        urikey->resource = PICO_ZALLOC(2u);
        if (!urikey->resource) {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        urikey->resource[0] = '/';
        return HTTP_RETURN_OK;
    }
    else if(uri[index] == '/')
    {
        urikey->port = 80u;
    }
    else if(uri[index] == ':')
    {
        urikey->port = 0u;
        index++;
        while(uri[index] && uri[index] != '/')
        {
            /* should check if every component is a digit */
            urikey->port = (uint16_t)(urikey->port * 10 + (uri[index] - '0'));
            index++;
        }
    }

    /* extract resource */
    if(!uri[index])
    {
        urikey->resource = PICO_ZALLOC(2u);
        if (!urikey->resource) {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        urikey->resource[0] = '/';
    }
    else
    {
        lastIndex = index;
        while(uri[index] && uri[index] != '?' && uri[index] != '&' && uri[index] != '#') index++;
        urikey->resource = (char *)PICO_ZALLOC((size_t)(index - lastIndex + 1));

        if(!urikey->resource)
        {
            /* no memory */
            pico_err = PICO_ERR_ENOMEM;
            goto error;
        }

        memcpy(urikey->resource, uri + lastIndex, (size_t)(index - lastIndex));
    }

    return HTTP_RETURN_OK;

error:
    if(urikey->resource)
    {
        PICO_FREE(urikey->resource);
        urikey->resource = NULL;
    }

    if(urikey->host)
    {
        PICO_FREE(urikey->host);
        urikey->host = NULL;
    }

    return HTTP_RETURN_ERROR;
}

#endif
