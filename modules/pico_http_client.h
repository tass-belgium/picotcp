/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Andrei Carp <andrei.carp@tass.be>
 *********************************************************************/


#ifndef PICO_HTTP_CLIENT_H_
#define PICO_HTTP_CLIENT_H_

#include "pico_http_util.h"

/*
 * Transfer encodings
 */
#define HTTP_TRANSFER_CHUNKED  1u
#define HTTP_TRANSFER_FULL       0u

/*
 * Parameters for the send header function
 */
#define HTTP_HEADER_RAW                 0u
#define HTTP_HEADER_DEFAULT         1u

/*
 * Data types
 */

struct pico_http_header
{
    uint16_t responseCode;                  /* http response */
    char *location;                                     /* if redirect is reported */
    uint32_t contentLengthOrChunk;    /* size of the message */
    uint8_t transferCoding;                 /* chunked or full */

};

int pico_http_client_open(char *uri, void (*wakeup)(uint16_t ev, uint16_t conn));
int32_t pico_http_client_sendHeader(uint16_t conn, char *header, uint8_t hdr);

struct pico_http_header *pico_http_client_readHeader(uint16_t conn);
struct pico_http_uri *pico_http_client_readUriData(uint16_t conn);
char *pico_http_client_buildHeader(const struct pico_http_uri *uriData);

int32_t pico_http_client_readData(uint16_t conn, char *data, uint16_t size);
int pico_http_client_close(uint16_t conn);

#endif /* PICO_HTTP_CLIENT_H_ */
