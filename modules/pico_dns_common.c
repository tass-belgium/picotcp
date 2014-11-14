/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Toon Stegen, Devon Kerkhove
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

//TODO remove/adjust
/* determine len of string */
uint16_t pico_dns_client_strlen(const char *url)
{
    if (!url)
        return 0;
    return (uint16_t)strlen(url);
}

/* replace '.' in the domain name by the label length
 * f.e. www.google.be => 3www6google2be0 */
char *pico_dns_name_to_dns_notation(const char *ptr)
{
    char *dns_url = NULL;
    char *temp = NULL;
    char p = 0, *label = NULL;
    uint8_t len = 0;

    if (!ptr)
        return NULL;

    dns_url = PICO_ZALLOC(strlen(ptr)+2);
    if(!dns_url)
        return NULL;
    temp = dns_url;

    strcpy(dns_url+1, ptr);

    label = dns_url++;
    while ((p = *dns_url++) != 0) {
        if (p == '.') {
            *label = (char)len;
            label = dns_url - 1;
            len = 0;
        } else {
            len++;
        }
    }
    *label = (char)len;
    return temp;
}

//TODO make const and return new char *
/* replace the label length in the domain name by '.'
 * f.e. 3www6google2be0 => .www.google.be */
int pico_dns_notation_to_name(char *ptr)
{
    char p = 0, *label = NULL;

    if (!ptr)
        return -1;

    label = ptr;
    while ((p = *ptr++) != 0) {
        ptr += p;
        *label = '.';
        label = ptr;
    }
    return 0;
}

//TODO remove
void pico_dns_fill_query_suffix(struct pico_dns_query_suffix *suf, uint16_t type, uint16_t qclass)
{
    suf->qtype = short_be(type);
    suf->qclass = short_be(qclass);
}

//TODO remove
void pico_dns_fill_rr_suffix(struct pico_dns_answer_suffix *suf, uint16_t qtype, uint16_t qclass, uint32_t ttl, uint16_t rdlength)
{
    suf->qtype = short_be(qtype);
    suf->qclass = short_be(qclass);
    suf->ttl = long_be(ttl);
    suf->rdlength = short_be(rdlength);
}

char *pico_dns_addr_to_inaddr(const char *addr, uint16_t proto)
{
    char *inaddr = NULL;
    char arpa_suf[14] = { 0 };
    uint8_t inaddr_len = 0;

    if(!addr)
        return NULL;

    if(proto == PICO_PROTO_IPV4) {
        strcpy(arpa_suf, ".in-addr.arpa");
        inaddr_len = strlen(addr);
    }
#ifdef PICO_SUPPORT_IPV6
    else if(proto == PICO_PROTO_IPV6) {
         strcpy(arpa_suf, "IP6.ARPA");
         inaddr_len = STRLEN_PTR_IP6 + 1;
    }
#endif

    inaddr = PICO_ZALLOC(inaddr_len+strlen(arpa_suf)+1);
    if(!inaddr)
        return NULL;

    memcpy(inaddr, addr, strlen(addr));
    if(proto == PICO_PROTO_IPV4)
        pico_dns_mirror_addr(inaddr);
#ifdef PICO_SUPPORT_IPV6
    else if(proto == PICO_PROTO_IPV6)
        pico_dns_ipv6_set_ptr(addr, inaddr);
#endif
    else
        return NULL;

    memcpy(inaddr + strlen(inaddr), arpa_suf, strlen(arpa_suf));

    return inaddr;
}

char *pico_dns_create_packet(uint32_t *plen, struct pico_dns_header *hdr, struct pico_dns_query *q, struct pico_dns_answer *a)
{
    char *dns_packet = NULL;
    uint16_t qlen = 0;
    uint16_t alen = 0;

    if(!plen || !hdr || (!q && !a))
        return NULL;

    *plen = (uint32_t) (sizeof(struct pico_dns_header));
        
    if(q)
        qlen = (uint16_t)(q->qnlen + sizeof(q->qtype) + sizeof(q->qclass));
    if(a)
        alen = (uint16_t)(a->anlen + sizeof(a->atype) + sizeof(a->aclass) + sizeof(a->ttl) + sizeof(a->rdlen) + short_be(a->rdlen));

    *plen += (uint32_t)(qlen + alen);

    dns_packet = PICO_ZALLOC(*plen);

    if(!dns_packet)
        return NULL;

    /* Assemble the packet */
    memcpy(dns_packet, hdr, sizeof(struct pico_dns_header));
    PICO_FREE(hdr);
    if(q) {
        memcpy(dns_packet + sizeof(struct pico_dns_header), q->qname, q->qnlen);
        memcpy(dns_packet + sizeof(struct pico_dns_header) + q->qnlen, &(q->qtype), sizeof(q->qtype));
        memcpy(dns_packet + sizeof(struct pico_dns_header) + q->qnlen + sizeof(q->qtype), &(q->qclass), sizeof(q->qclass));
    }
    if(a) {
        memcpy(dns_packet + sizeof(struct pico_dns_header) + qlen, a->aname, a->anlen);
        memcpy(dns_packet + sizeof(struct pico_dns_header) + qlen + a->anlen, &(a->atype), sizeof(a->atype));
        memcpy(dns_packet + sizeof(struct pico_dns_header) + qlen + a->anlen + sizeof(a->atype), &(a->aclass), sizeof(a->aclass));
        memcpy(dns_packet + sizeof(struct pico_dns_header) + qlen + a->anlen + sizeof(a->atype) + sizeof(a->aclass), &(a->ttl), sizeof(a->ttl));
        memcpy(dns_packet + sizeof(struct pico_dns_header) + qlen + a->anlen + sizeof(a->atype) + sizeof(a->aclass) + sizeof(a->ttl), 
                            &(a->rdlen), sizeof(a->rdlen));
        memcpy(dns_packet + sizeof(struct pico_dns_header) + qlen + a->anlen + sizeof(a->atype) + sizeof(a->aclass) + sizeof(a->ttl) + 
                            sizeof(a->rdlen), a->rdata, short_be(a->rdlen));
    }

    return dns_packet;
}

struct pico_dns_header *pico_dns_create_header(uint16_t id, uint16_t qdcount, uint16_t ancount)
{
    struct pico_dns_header *hdr = PICO_ZALLOC(sizeof(struct pico_dns_header));
    if(!hdr)
        return NULL;

    hdr->id = short_be(id);

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
    hdr->rd = PICO_DNS_RD_NO_DESIRE;
    hdr->ra = PICO_DNS_RA_NO_SUPPORT;
    hdr->z = 0; /* Z, AD, CD are 0 */
    hdr->rcode = PICO_DNS_RCODE_NO_ERROR;
    hdr->qdcount = short_be(qdcount);
    hdr->ancount = short_be(ancount);
    hdr->nscount = short_be(0);
    hdr->arcount = short_be(0);

    return hdr;
}

struct pico_dns_query *pico_dns_create_query(const char *name, uint16_t qtype, uint16_t qclass)
{
    char *qname = NULL;
    uint16_t qname_len = 0;
    struct pico_dns_query *query = NULL;

    if(!name)
        return NULL;

    qname_len = (uint16_t)(strlen(name)+1);
    qname = PICO_ZALLOC(qname_len);
    if(!qname)
        return NULL;

    query = PICO_ZALLOC(sizeof(struct pico_dns_query));
    if(!query)
        return NULL;

    qtype = short_be(qtype);
    qclass = short_be(qclass);
    strcpy(qname, name);

    query->qname = qname;
    query->qnlen = qname_len;
    query->qtype = qtype;
    query->qclass = qclass;

    return query;
}

struct pico_dns_answer *pico_dns_create_answer(const char *name, uint16_t atype, uint16_t aclass, uint32_t ttl, char *data, uint16_t rdlen)
{
    char *aname = NULL;
    uint16_t aname_len = 0;
    char *rdata = NULL;
    struct pico_dns_answer *answer = NULL;

    if(!name)
        return NULL;
    aname_len = (uint16_t)(strlen(name)+1);
    aname = PICO_ZALLOC(aname_len);
    if(!aname)
        return NULL;

    rdata = PICO_ZALLOC(rdlen);
    if(!rdata)
        return NULL;

    answer = PICO_ZALLOC(sizeof(struct pico_dns_answer));
    if(!answer)
        return NULL;

    strcpy(aname, name);
    atype = short_be(atype);
    aclass = short_be(aclass);
    ttl = long_be(ttl);
    memcpy(rdata, data, rdlen);
    rdlen = short_be(rdlen);

    answer->aname = aname;
    answer->anlen = aname_len;
    answer->atype = atype;
    answer->aclass = aclass;
    answer->ttl = ttl;
    answer->rdlen = rdlen;
    answer->rdata = rdata;

    return answer;
}

/* mirror ip address numbers
 * f.e. 192.168.0.1 => 1.0.168.192 */
int pico_dns_mirror_addr(char *ptr)
{
    const unsigned char *addr = NULL;
    char *m = ptr;
    uint32_t ip = 0;
    int i = 0;

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
    struct pico_ip6 ip6 = {.addr = {}};
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
