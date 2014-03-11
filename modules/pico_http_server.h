/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Andrei Carp <andrei.carp@tass.be>
 *********************************************************************/

#ifndef PICO_HTTP_SERVER_H_
#define PICO_HTTP_SERVER_H_

#include <stdint.h>
#include "pico_http_util.h"

/* Response codes */
#define HTTP_RESOURCE_NOT_FOUND     1u
#define HTTP_RESOURCE_FOUND         2u
#define HTTP_STATIC_RESOURCE        4u
#define HTTP_CACHEABLE_RESOURCE      8u

/* Generic id for the server */
#define HTTP_SERVER_ID                  0u

/*
 * Server functions
 */
int8_t pico_http_server_start(uint16_t port, void (*wakeup)(uint16_t ev, uint16_t conn));
int pico_http_server_accept(void);

/*
 * Client functions
 */
char *pico_http_getResource(uint16_t conn);
int pico_http_getMethod(uint16_t conn);
char *pico_http_getBody(uint16_t conn);
int      pico_http_getProgress(uint16_t conn, uint16_t *sent, uint16_t *total);

/*
 * Handshake and data functions
 */
int      pico_http_respond(uint16_t conn, uint16_t code);
int8_t   pico_http_submitData(uint16_t conn, void *buffer, uint16_t len);
int      pico_http_close(uint16_t conn);

#endif /* PICO_HTTP_SERVER_H_ */
