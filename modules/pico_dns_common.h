
/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
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

/* FLAG values */
#define PICO_DNS_QR_QUERY 0
#define PICO_DNS_QR_RESPONSE 1
#define PICO_DNS_OPCODE_QUERY 0
#define PICO_DNS_OPCODE_IQUERY 1
#define PICO_DNS_OPCODE_STATUS 2
#define PICO_DNS_AA_NO_AUTHORITY 0
#define PICO_DNS_AA_IS_AUTHORITY 1
#define PICO_DNS_TC_NO_TRUNCATION 0
#define PICO_DNS_TC_IS_TRUNCATED 1
#define PICO_DNS_RD_NO_DESIRE 0
#define PICO_DNS_RD_IS_DESIRED 1
#define PICO_DNS_RA_NO_SUPPORT 0
#define PICO_DNS_RA_IS_SUPPORTED 1
#define PICO_DNS_RCODE_NO_ERROR 0
#define PICO_DNS_RCODE_EFORMAT 1
#define PICO_DNS_RCODE_ESERVER 2
#define PICO_DNS_RCODE_ENAME 3
#define PICO_DNS_RCODE_ENOIMP 4
#define PICO_DNS_RCODE_EREFUSED 5

#ifdef PICO_SUPPORT_IPV6
#define STRLEN_PTR_IP6 63
#endif

/* flags split in 2x uint8 due to endianness */
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

void pico_dns_fill_header(struct pico_dns_header *hdr, uint16_t qdcount, uint16_t ancount);
uint16_t pico_dns_client_strlen(const char *url);
int pico_dns_name_to_dns_notation(char *ptr, unsigned int maxlen);
int pico_dns_notation_to_name(char *ptr, unsigned int maxlen);
void pico_dns_fill_query_suffix(struct pico_dns_query_suffix *suf, uint16_t type, uint16_t qclass);
void pico_dns_fill_rr_suffix(struct pico_dns_answer_suffix *suf, uint16_t qtype, uint16_t qclass, uint32_t ttl, uint16_t rdlength);
int8_t pico_dns_mirror_addr(char *ptr);
void pico_dns_ipv6_set_ptr(const char *ip, char *dst);

#endif /* _INCLUDE_PICO_DNS_COMMON */
