/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Toon Stegen
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_common.h"
#include "pico_dns_client.h"
#include "pico_tree.h"

void pico_dns_fill_header(struct pico_dns_header *hdr, uint16_t qdcount, uint16_t ancount)
{

    /* hdr->id should be filled by caller */

    if(qdcount > 0) {
        hdr->qr = PICO_DNS_QR_QUERY;
        hdr->aa = PICO_DNS_AA_NO_AUTHORITY;
    }
    else {
        hdr->qr = PICO_DNS_QR_RESPONSE;
        hdr->aa = PICO_DNS_AA_IS_AUTHORITY;
    }

    hdr->opcode = PICO_DNS_OPCODE_QUERY;
    hdr->tc = PICO_DNS_TC_NO_TRUNCATION;
    hdr->rd = PICO_DNS_RD_IS_DESIRED;
    hdr->ra = PICO_DNS_RA_NO_SUPPORT;
    hdr->z = 0; /* Z, AD, CD are 0 */
    hdr->rcode = PICO_DNS_RCODE_NO_ERROR;
    hdr->qdcount = short_be(qdcount);
    hdr->ancount = short_be(ancount);
    hdr->nscount = short_be(0);
    hdr->arcount = short_be(0);
}

/* determine len of string */
uint16_t pico_dns_client_strlen(const char *url)
{
    if (!url)
        return 0;

    return (uint16_t)strlen(url);
}

/* replace '.' in the domain name by the label length
 * f.e. www.google.be => 3www6google2be0 */
int pico_dns_name_to_dns_notation(char *ptr, unsigned int maxlen)
{
    char p = 0, *label = NULL;
    uint8_t len = 0;
    char *start = ptr;

    if (!ptr)
        return -1;

    label = ptr++;
    while ((p = *ptr++) != 0) {
        if (p == '.') {
            *label = (char)len;
            label = ptr - 1;
            len = 0;
        } else {
            len++;
        }
        if ((unsigned int)(ptr - start) > maxlen)
            break;
    }
    *label = (char)len;
    return 0;
}

/* replace the label length in the domain name by '.'
 * f.e. 3www6google2be0 => .www.google.be */
int pico_dns_notation_to_name(char *ptr, unsigned int maxlen)
{
    char p = 0, *label = NULL;
    char *start = ptr;
    if (!ptr)
        return -1;

    label = ptr;
    while ((p = *ptr++) != 0) {
        ptr += p;
        *label = '.';
        label = ptr;
        if ((unsigned int)(ptr - start) > maxlen)
            break;
    }
    return 0;
}

void pico_dns_fill_query_suffix(struct pico_dns_query_suffix *suf, uint16_t type, uint16_t qclass)
{
    suf->qtype = short_be(type);
    suf->qclass = short_be(qclass);
}

void pico_dns_fill_rr_suffix(struct pico_dns_answer_suffix *suf, uint16_t qtype, uint16_t qclass, uint32_t ttl, uint16_t rdlength)
{
    suf->qtype = short_be(qtype);
    suf->qclass = short_be(qclass);
    suf->ttl = long_be(ttl);
    suf->rdlength = short_be(rdlength);
}

/* mirror ip address numbers
 * f.e. 192.168.0.1 => 1.0.168.192 */
int8_t pico_dns_mirror_addr(char *ptr)
{
    const unsigned char *addr = NULL;
    char *m = ptr;
    uint32_t ip = 0;
    int8_t i = 0;

    if (pico_string_to_ipv4(ptr, &ip) < 0)
        return -1;

    ptr = m;
    addr = (unsigned char *)&ip;
    for (i = 3; i >= 0; i--) {
        if (addr[i] > 99) {
            *ptr++ = (char)('0' + (addr[i] / 100));
            *ptr++ = (char)('0' + ((addr[i] % 100) / 10));
            *ptr++ = (char)('0' + ((addr[i] % 100) % 10));
        } else if(addr[i] > 9) {
            *ptr++ = (char)('0' + (addr[i] / 10));
            *ptr++ = (char)('0' + (addr[i] % 10));
        } else {
            *ptr++ = (char)('0' + addr[i]);
        }

        if(i > 0)
            *ptr++ = '.';
    }
    *ptr = '\0';

    return 0;
}

#ifdef PICO_SUPPORT_IPV6
#define STRLEN_PTR_IP6 63

static inline char dns_ptr_ip6_nibble_lo(uint8_t byte)
{
    uint8_t nibble = byte & 0x0f;
    if (nibble < 10)
        return (char)(nibble + '0');
    else
        return (char)(nibble - 0xa + 'a');
}

static inline char dns_ptr_ip6_nibble_hi(uint8_t byte)
{
    uint8_t nibble = (byte & 0xf0u) >> 4u;
    if (nibble < 10u)
        return (char)(nibble + '0');
    else
        return (char)(nibble - 0xa + 'a');
}

void pico_dns_ipv6_set_ptr(const char *ip, char *dst)
{
    struct pico_ip6 ip6 = {
        .addr = {}
    };
    int i, j = 0;
    pico_string_to_ipv6(ip, ip6.addr);
    for (i = 15; i >= 0; i--) {
        dst[j++] = dns_ptr_ip6_nibble_lo(ip6.addr[i]);
        dst[j++] = '.';
        dst[j++] = dns_ptr_ip6_nibble_hi(ip6.addr[i]);
        dst[j++] = '.';
    }
}
#endif
