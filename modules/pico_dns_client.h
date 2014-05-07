/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Kristof Roelants
 *********************************************************************/

#ifndef INCLUDE_PICO_DNS_CLIENT
#define INCLUDE_PICO_DNS_CLIENT

#define PICO_DNS_NS_DEL 0
#define PICO_DNS_NS_ADD 1
#include <stdint.h>
#include "pico_config.h"

/* QTYPE values */
#define PICO_DNS_TYPE_A 1
#define PICO_DNS_TYPE_AAAA 28
#define PICO_DNS_TYPE_PTR 12
#define PICO_DNS_TYPE_ANY 255

/* QCLASS values */
#define PICO_DNS_CLASS_IN 1

/* Compression values */
#define PICO_DNS_LABEL 0
#define PICO_DNS_POINTER 3

/* Label len */
#define PICO_DNS_LABEL_INITIAL 1u
#define PICO_DNS_LABEL_ROOT 1

/* TTL values */
#define PICO_DNS_MAX_TTL 604800 /* one week */

/* Len of an IPv4 address string */
#define PICO_DNS_IPV4_ADDR_LEN 16
#define PICO_DNS_IPV6_ADDR_LEN 54

#ifdef PICO_SUPPORT_IPV6
#define STRLEN_PTR_IP6 63
#endif

/* flags splitted in 2x uint8 due to endianness */
PACKED_STRUCT_DEF pico_dns_header
{
    uint16_t id;
    uint8_t rd : 1; /* recursion desired  */
    uint8_t tc : 1; /* truncation  */
    uint8_t aa : 1; /* authoritative answer  */
    uint8_t opcode : 4; /* opcode  */
    uint8_t qr : 1; /* query  */
    uint8_t rcode : 4; /* response code */
    uint8_t z : 3; /* zero */
    uint8_t ra : 1; /* recursion available  */
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

int pico_dns_client_init(void);
/* flag is PICO_DNS_NS_DEL or PICO_DNS_NS_ADD */
int pico_dns_client_nameserver(struct pico_ip4 *ns, uint8_t flag);
int pico_dns_client_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_dns_client_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg);
#ifdef PICO_SUPPORT_IPV6
int pico_dns_client_getaddr6(const char *url, void (*callback)(char *, void *), void *arg);
int pico_dns_client_getname6(const char *url, void (*callback)(char *, void *), void *arg);
#endif
/* functions used by the mdns module */
uint16_t pico_dns_client_strlen(const char *url);
int pico_dns_client_query_header(struct pico_dns_header *pre);
int pico_dns_client_query_domain(char *ptr);
int pico_dns_client_answer_domain(char *ptr);
int pico_dns_client_query_suffix(struct pico_dns_query_suffix *suf, uint16_t type, uint16_t qclass);
int pico_dns_create_message(struct pico_dns_header **header, struct pico_dns_query_suffix **qsuffix, enum pico_dns_arpa arpa, const char *url, uint16_t *urlen, uint16_t *hdrlen);
int8_t pico_dns_client_mirror(char *ptr);
void pico_dns_ipv6_set_ptr(const char *ip, char *dst);

#endif /* _INCLUDE_PICO_DNS_CLIENT */
