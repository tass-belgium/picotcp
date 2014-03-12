/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Andrei Carp <andrei.carp@tass.be>
 *********************************************************************/

#ifndef PICO_HTTP_UTIL_H_
#define PICO_HTTP_UTIL_H_

/* Informational reponses */
#define HTTP_CONTINUE                       100u
#define HTTP_SWITCHING_PROTOCOLS  101u
#define HTTP_PROCESSING                   102u

/* Success */
#define HTTP_OK                                     200u
#define HTTP_CREATED                            201u
#define HTTP_ACCEPTED                           202u
#define HTTP_NON_AUTH_INFO              203u
#define HTTP_NO_CONTENT                     204u
#define HTTP_RESET_CONTENT              205u
#define HTTP_PARTIAL_CONTENT            206u
#define HTTP_MULTI_STATUS                   207u
#define HTTP_ALREADY_REPORTED           208u
#define HTTP_LOW_SPACE                      250u
#define HTTP_IM_SPACE                           226u

/* Redirection */
#define HTTP_MULTI_CHOICE                   300u
#define HTTP_MOVED_PERMANENT            301u
#define HTTP_FOUND                              302u
#define HTTP_SEE_OTHER                      303u
#define HTTP_NOT_MODIFIED                   304u
#define HTTP_USE_PROXY                      305u
#define HTTP_SWITCH_PROXY                   306u
#define HTTP_TEMP_REDIRECT              307u
#define HTTP_PERM_REDIRECT              308u

/* Client error */
#define HTTP_BAD_REQUEST                    400u
#define HTTP_UNAUTH                             401u
#define HTTP_PAYMENT_REQ                    402u
#define HTTP_FORBIDDEN                      403u
#define HTTP_NOT_FOUND                      404u
#define HTTP_METH_NOT_ALLOWED           405u
#define HTTP_NOT_ACCEPTABLE             406u
#define HTTP_PROXY_AUTH_REQ             407u
#define HTTP_REQ_TIMEOUT                    408u
#define HTTP_CONFLICT                           409u
#define HTTP_GONE                                   410u
#define HTTP_LEN_REQ                            411u
#define HTTP_PRECONDITION_FAIL      412u
#define HTTP_REQ_ENT_LARGE              413u
#define HTTP_URI_TOO_LONG                   414u
#define HTTP_UNSUPORTED_MEDIA           415u
#define HTTP_REQ_RANGE_NOK              416u
#define HTTP_EXPECT_FAILED              417u
#define HTTP_TEAPOT                             418u
#define HTTP_UNPROC_ENTITY              422u
#define HTTP_LOCKED                             423u
#define HTTP_METHOD_FAIL                    424u
#define HTTP_UNORDERED                      425u
#define HTTP_UPGRADE_REQ                    426u
#define HTTP_PRECOND_REQ                    428u
#define HTTP_TOO_MANY_REQ                   429u
#define HTTP_HEDER_FIELD_LARGE      431u

/* Server error */
#define HTTP_INTERNAL_SERVER_ERR    500u
#define HTTP_NOT_IMPLEMENTED            501u
#define HTTP_BAD_GATEWAY                    502u
#define HTTP_SERVICE_UNAVAILABLE    503u
#define HTTP_GATEWAY_TIMEOUT            504u
#define HTTP_NOT_SUPPORTED              505u
#define HTTP_SERV_LOW_STORAGE           507u
#define HTTP_LOOP_DETECTED              508u
#define HTTP_NOT_EXTENDED                   510u
#define HTTP_NETWORK_AUTH                   511u
#define HTTP_PERMISSION_DENIED      550u

/* Returns used  */
#define HTTP_RETURN_ERROR       -1
#define HTTP_RETURN_OK          0
#define HTTP_RETURN_BUSY        1
#define HTTP_RETURN_NOT_FOUND   2

/* HTTP Methods */
#define HTTP_METHOD_GET     1u
#define HTTP_METHOD_POST    2u

/* List of events - shared between client and server */
#define EV_HTTP_CON         1u
#define EV_HTTP_REQ       2u
#define EV_HTTP_PROGRESS  4u
#define EV_HTTP_SENT          8u
#define EV_HTTP_CLOSE     16u
#define EV_HTTP_ERROR     32u
#define EV_HTTP_BODY            64u
#define EV_HTTP_DNS             128u


/* used for chunks */
int pico_itoaHex(uint16_t port, char *ptr);
uint32_t pico_itoa(uint32_t port, char *ptr);
void pico_http_url_decode(char *dst, const char *src);

#endif /* PICO_HTTP_UTIL_H_ */
