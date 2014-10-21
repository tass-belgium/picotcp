
/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Toon Stegen
 *********************************************************************/

#ifndef INCLUDE_PICO_DNS_COMMON
#define INCLUDE_PICO_DNS_COMMON

#include "pico_config.h"

/* QTYPE values */
#define PICO_DNS_TYPE_A 1
#define PICO_DNS_TYPE_CNAME 5
#define PICO_DNS_TYPE_AAAA 28
#define PICO_DNS_TYPE_PTR 12
#define PICO_DNS_TYPE_ANY 255

/* QCLASS values */
#define PICO_DNS_CLASS_IN 1

#ifdef PICO_SUPPORT_IPV6
#define STRLEN_PTR_IP6 63
#endif

/* flags splitted in 2x uint8 due to endianness */
PACKED_STRUCT_DEF pico_dns_header
{
    uint16_t id;
    uint8_t rd : 1;     /* recursion desired  */
    uint8_t tc : 1;     /* truncation  */
    uint8_t aa : 1;     /* authoritative answer  */
    uint8_t opcode : 4; /* opcode  */
    uint8_t qr : 1;     /* query  */
    uint8_t rcode : 4;  /* response code */
    uint8_t z : 3;      /* zero */
    uint8_t ra : 1;     /* recursion available  */
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

PACKED_STRUCT_DEF pico_dns_query_suffix
{
    uint16_t qtype;
    uint16_t qclass;
};

PACKED_STRUCT_DEF pico_dns_answer_suffix
{
    uint16_t qtype;
    uint16_t qclass;
    uint32_t ttl;
    uint16_t rdlength;
};

enum pico_dns_arpa
{
    PICO_DNS_ARPA4,
    PICO_DNS_ARPA6,
    PICO_DNS_NO_ARPA,
};

uint16_t pico_dns_client_strlen(const char *url);
int pico_dns_client_query_domain(char *ptr);
int pico_dns_client_answer_domain(char *ptr);
int pico_dns_client_query_suffix(struct pico_dns_query_suffix *suf, uint16_t type, uint16_t qclass);
int8_t pico_dns_client_mirror(char *ptr);
void pico_dns_ipv6_set_ptr(const char *ip, char *dst);

#endif /* _INCLUDE_PICO_DNS_COMMON */
