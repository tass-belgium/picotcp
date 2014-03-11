/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Kristof Roelants
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_DNS_CLIENT

#define dns_dbg(...) do {} while(0)
/* #define dns_dbg dbg */

/* DNS response length */
#define PICO_DNS_MAX_RESPONSE_LEN 256

/* DNS client retransmission time (msec) + frequency */
#define PICO_DNS_CLIENT_RETRANS 4000
#define PICO_DNS_CLIENT_MAX_RETRANS 3

/* Default nameservers + port */
#define PICO_DNS_NS_GOOGLE "8.8.8.8"
#define PICO_DNS_NS_PORT 53

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

/* QTYPE values */
#define PICO_DNS_TYPE_A 1
#define PICO_DNS_TYPE_AAAA 28
#define PICO_DNS_TYPE_PTR 12

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

static void pico_dns_client_callback(uint16_t ev, struct pico_socket *s);
static void pico_dns_client_retransmission(pico_time now, void *arg);

/* RFC 1035 section 4. MESSAGES */
struct __attribute__((packed)) pico_dns_name
{
    char name[0];
};

/* prefix = header + name pointer
 * flags splitted in 2x uint8 due to endianness */
struct __attribute__((packed)) pico_dns_prefix
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
    struct pico_dns_name domain;
};

struct __attribute__((packed)) pico_dns_query_suffix
{
    uint16_t qtype;
    uint16_t qclass;
};

struct __attribute__((packed)) pico_dns_answer_suffix
{
    uint16_t qtype;
    uint16_t qclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t rdata[];
};

struct pico_dns_ns
{
    struct pico_ip4 ns; /* nameserver */
};

static int dns_ns_cmp(void *ka, void *kb)
{
    struct pico_dns_ns *a = ka, *b = kb;
    if (a->ns.addr == b->ns.addr)
        return 0;

    return (a->ns.addr < b->ns.addr) ? (-1) : (1);
}
PICO_TREE_DECLARE(NSTable, dns_ns_cmp);

struct pico_dns_query
{
    char *query;
    uint16_t len;
    uint16_t id;
    uint16_t qtype;
    uint16_t qclass;
    uint8_t retrans;
    struct pico_dns_ns q_ns;
    struct pico_socket *s;
    void (*callback)(char *, void *);
    void *arg;
};

static int dns_query_cmp(void *ka, void *kb)
{
    struct pico_dns_query *a = ka, *b = kb;
    if (a->id == b->id)
        return 0;

    return (a->id < b->id) ? (-1) : (1);
}
PICO_TREE_DECLARE(DNSTable, dns_query_cmp);

static int pico_dns_client_del_ns(struct pico_ip4 *ns_addr)
{
    struct pico_dns_ns test = {{0}}, *found = NULL;

    test.ns = *ns_addr;
    found = pico_tree_findKey(&NSTable, &test);
    if (!found)
        return -1;

    pico_tree_delete(&NSTable, found);
    PICO_FREE(found);

    /* no NS left, add default NS */
    if (pico_tree_empty(&NSTable))
        pico_dns_client_init();

    return 0;
}

static struct pico_dns_ns *pico_dns_client_add_ns(struct pico_ip4 *ns_addr)
{
    struct pico_dns_ns *dns = NULL, *found = NULL, test = {{0}};

    dns = PICO_ZALLOC(sizeof(struct pico_dns_ns));
    if (!dns) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    dns->ns = *ns_addr;

    found = pico_tree_insert(&NSTable, dns);
    if (found) { /* nameserver already present */
        PICO_FREE(dns);
        return found;
    }

    /* default NS found, remove it */
    pico_string_to_ipv4(PICO_DNS_NS_GOOGLE, &test.ns.addr);
    found = pico_tree_findKey(&NSTable, &test);
    if (found && (found->ns.addr != ns_addr->addr))
        pico_dns_client_del_ns(&found->ns);

    return dns;
}

static struct pico_dns_ns pico_dns_client_next_ns(struct pico_ip4 *ns_addr)
{
    struct pico_dns_ns dns = {{0}}, *nxtdns = NULL;
    struct pico_tree_node *node = NULL, *nxtnode = NULL;

    dns.ns = *ns_addr;
    node = pico_tree_findNode(&NSTable, &dns);
    if (!node)
        return dns; /* keep using current NS */

    nxtnode = pico_tree_next(node);
    nxtdns = nxtnode->keyValue;
    if (!nxtdns)
        nxtdns = (struct pico_dns_ns *)pico_tree_first(&NSTable);

    return *nxtdns;
}

static struct pico_dns_query *pico_dns_client_add_query(struct pico_dns_prefix *hdr, uint16_t len, struct pico_dns_query_suffix *suffix,
                                                        void (*callback)(char *, void *), void *arg)
{
    struct pico_dns_query *q = NULL, *found = NULL;

    q = PICO_ZALLOC(sizeof(struct pico_dns_query));
    if (!q)
        return NULL;

    q->query = (char *)hdr;
    q->len = len;
    q->id = short_be(hdr->id);
    q->qtype = short_be(suffix->qtype);
    q->qclass = short_be(suffix->qclass);
    q->retrans = 1;
    q->q_ns = *((struct pico_dns_ns *)pico_tree_first(&NSTable));
    q->callback = callback;
    q->arg = arg;
    q->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dns_client_callback);
    if (!q->s) {
        PICO_FREE(q);
        return NULL;
    }

    found = pico_tree_insert(&DNSTable, q);
    if (found) {
        pico_err = PICO_ERR_EAGAIN;
        pico_socket_close(q->s);
        PICO_FREE(q);
        return NULL;
    }

    return q;
}

static int pico_dns_client_del_query(uint16_t id)
{
    struct pico_dns_query test = {
        0
    }, *found = NULL;

    test.id = id;
    found = pico_tree_findKey(&DNSTable, &test);
    if (!found)
        return -1;

    PICO_FREE(found->query);
    pico_socket_close(found->s);
    pico_tree_delete(&DNSTable, found);
    PICO_FREE(found);
    return 0;
}

static struct pico_dns_query *pico_dns_client_find_query(uint16_t id)
{
    struct pico_dns_query test = {
        0
    }, *found = NULL;

    test.id = id;
    found = pico_tree_findKey(&DNSTable, &test);
    if (found)
        return found;
    else
        return NULL;
}

/* determine len of string */
static uint16_t pico_dns_client_strlen(const char *url)
{
    uint16_t len;

    if (!url)
        return 0;

    for (len = 0; len < 0xFFFF; len++) {
        if (url[len] == 0)
            break;
    }
    return len;
}

/* seek end of string */
static char *pico_dns_client_seek(char *ptr)
{
    if (!ptr)
        return NULL;

    while (*ptr != 0)
        ptr++;
    return ptr + 1;
}

/* mirror ip6 */

/* mirror ip address numbers
 * f.e. 192.168.0.1 => 1.0.168.192 */
static int8_t pico_dns_client_mirror(char *ptr)
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

static struct pico_dns_query *pico_dns_client_idcheck(uint16_t id)
{
    struct pico_dns_query test = {
        0
    };

    test.id = id;
    return pico_tree_findKey(&DNSTable, &test);
}

static int pico_dns_client_query_prefix(struct pico_dns_prefix *pre)
{
    uint16_t id = 0;
    uint8_t retry = 32;

    do {
        id = (uint16_t)(pico_rand() & 0xFFFFU);
        dns_dbg("DNS: generated id %u\n", id);
    } while (retry-- && pico_dns_client_idcheck(id));
    if (!retry)
        return -1;

    pre->id = short_be(id);
    pre->qr = PICO_DNS_QR_QUERY;
    pre->opcode = PICO_DNS_OPCODE_QUERY;
    pre->aa = PICO_DNS_AA_NO_AUTHORITY;
    pre->tc = PICO_DNS_TC_NO_TRUNCATION;
    pre->rd = PICO_DNS_RD_IS_DESIRED;
    pre->ra = PICO_DNS_RA_NO_SUPPORT;
    pre->z = 0;
    pre->rcode = PICO_DNS_RCODE_NO_ERROR;
    pre->qdcount = short_be(1);
    pre->ancount = short_be(0);
    pre->nscount = short_be(0);
    pre->arcount = short_be(0);

    return 0;
}

static int pico_dns_client_query_suffix(struct pico_dns_query_suffix *suf, uint16_t type, uint16_t class)
{
    suf->qtype = short_be(type);
    suf->qclass = short_be(class);
    return 0;
}

/* replace '.' in the domain name by the label length
 * f.e. www.google.be => 3www6google2be0 */
static int pico_dns_client_query_domain(char *ptr)
{
    char p = 0, *label = NULL;
    uint8_t len = 0;

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
    }
    *label = (char)len;
    return 0;
}

/* replace the label length in the domain name by '.'
 * f.e. 3www6google2be0 => .www.google.be */
static int pico_dns_client_answer_domain(char *ptr)
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

static int pico_dns_client_check_prefix(struct pico_dns_prefix *pre)
{
    if (pre->qr != PICO_DNS_QR_RESPONSE || pre->opcode != PICO_DNS_OPCODE_QUERY || pre->rcode != PICO_DNS_RCODE_NO_ERROR) {
        dns_dbg("DNS ERROR: OPCODE %d | TC %d | RCODE %d\n", pre->opcode, pre->tc, pre->rcode);
        return -1;
    }

    if (short_be(pre->ancount) < 1) {
        dns_dbg("DNS ERROR: ancount < 1\n");
        return -1;
    }

    return 0;
}

static int pico_dns_client_check_qsuffix(struct pico_dns_query_suffix *suf, struct pico_dns_query *q)
{
    if (short_be(suf->qtype) != q->qtype || short_be(suf->qclass) != q->qclass) {
        dns_dbg("DNS ERROR: received qtype (%u) or qclass (%u) incorrect\n", short_be(suf->qtype), short_be(suf->qclass));
        return -1;
    }

    return 0;
}

static int pico_dns_client_check_asuffix(struct pico_dns_answer_suffix *suf, struct pico_dns_query *q)
{
    if (!suf) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (short_be(suf->qtype) != q->qtype || short_be(suf->qclass) != q->qclass) {
        dns_dbg("DNS WARNING: received qtype (%u) or qclass (%u) incorrect\n", short_be(suf->qtype), short_be(suf->qclass));
        return -1;
    }

    if (long_be(suf->ttl) > PICO_DNS_MAX_TTL) {
        dns_dbg("DNS WARNING: received TTL (%u) > MAX (%u)\n", short_be(suf->ttl), PICO_DNS_MAX_TTL);
        return -1;
    }

    return 0;
}

static char *pico_dns_client_seek_suffix(char *suf, struct pico_dns_prefix *pre, struct pico_dns_query *q)
{
    struct pico_dns_answer_suffix *asuffix = NULL;
    uint16_t comp = 0, compression = 0;
    uint16_t i = 0;
    char *psuffix = suf;
    if (!suf)
        return NULL;

    while (i++ < short_be(pre->ancount)) {
        comp = short_from(psuffix);
        compression = short_be(comp);
        switch (compression >> 14)
        {
        case PICO_DNS_POINTER:
            while (compression >> 14 == PICO_DNS_POINTER) {
                dns_dbg("DNS: pointer\n");
                psuffix += sizeof(uint16_t);
                comp = short_from(psuffix);
                compression = short_be(comp);
            }
            break;

        case PICO_DNS_LABEL:
            dns_dbg("DNS: label\n");
            psuffix = pico_dns_client_seek(psuffix);
            break;

        default:
            dns_dbg("DNS ERROR: incorrect compression (%u) value\n", compression);
            return NULL;
        }

        asuffix = (struct pico_dns_answer_suffix *)psuffix;
        if (!asuffix)
            break;

        if (pico_dns_client_check_asuffix(asuffix, q) < 0) {
            psuffix += (sizeof(struct pico_dns_answer_suffix) + short_be(asuffix->rdlength));
            continue;
        }

        return psuffix;
    }
    return NULL;
}

static int pico_dns_client_send(struct pico_dns_query *q)
{
    uint16_t *paramID = PICO_ZALLOC(sizeof(uint16_t));
    if (!paramID) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    dns_dbg("DNS: sending query to %08X\n", q->q_ns.ns.addr);
    if (!q->s)
        goto failure;

    if (pico_socket_connect(q->s, &q->q_ns.ns, short_be(PICO_DNS_NS_PORT)) < 0)
        goto failure;

    pico_socket_send(q->s, q->query, q->len);
    *paramID = q->id;
    pico_timer_add(PICO_DNS_CLIENT_RETRANS, pico_dns_client_retransmission, paramID);

    return 0;

failure:
    PICO_FREE(paramID);
    return -1;
}

static void pico_dns_client_retransmission(pico_time now, void *arg)
{
    struct pico_dns_query *q = NULL;
    struct pico_dns_query dummy;
    IGNORE_PARAMETER(now);

    if(!arg)
        return;

    /* search for the dns query and free used space */
    dummy.id = *(uint16_t *)arg;
    q = (struct pico_dns_query *)pico_tree_findKey(&DNSTable, &dummy);
    PICO_FREE(arg);

    /* dns query successful? */
    if (!q) {
        return;
    }

    if (q->retrans++ <= PICO_DNS_CLIENT_MAX_RETRANS) {
        q->q_ns = pico_dns_client_next_ns(&q->q_ns.ns);
        pico_dns_client_send(q);
    } else {
        pico_err = PICO_ERR_EIO;
        q->callback(NULL, q->arg);
        pico_dns_client_del_query(q->id);
    }
}

static int pico_dns_client_user_callback(struct pico_dns_answer_suffix *asuffix, struct pico_dns_query *q)
{
    uint32_t ip = 0;
    char *str = NULL;

    switch (q->qtype)
    {
    case PICO_DNS_TYPE_A:
        ip = long_from(asuffix->rdata);
        str = PICO_ZALLOC(PICO_DNS_IPV4_ADDR_LEN);
        pico_ipv4_to_string(str, ip);
        break;
#ifdef PICO_SUPPORT_IPV6
    case PICO_DNS_TYPE_AAAA:
    {
        struct pico_ip6 ip6;
        memcpy(&ip6.addr, asuffix->rdata, sizeof(struct pico_ip6));
        str = PICO_ZALLOC(PICO_DNS_IPV6_ADDR_LEN);
        pico_ipv6_to_string(str, ip6.addr);
        break;
    }
#endif
    case PICO_DNS_TYPE_PTR:
        pico_dns_client_answer_domain((char *)asuffix->rdata);
        str = PICO_ZALLOC((size_t)(asuffix->rdlength - PICO_DNS_LABEL_INITIAL));
        if (!str) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        memcpy(str, asuffix->rdata + PICO_DNS_LABEL_INITIAL, short_be(asuffix->rdlength) - PICO_DNS_LABEL_INITIAL);
        break;

    default:
        dns_dbg("DNS ERROR: incorrect qtype (%u)\n", q->qtype);
        break;
    }

    if (q->retrans) {
        q->callback(str, q->arg);
        q->retrans = 0;
        PICO_FREE(str);
        pico_dns_client_del_query(q->id);
    }

    return 0;
}

static void pico_dns_client_callback(uint16_t ev, struct pico_socket *s)
{
    struct pico_dns_prefix *prefix = NULL;
    struct pico_dns_name *domain = NULL;
    struct pico_dns_query_suffix *qsuffix = NULL;
    struct pico_dns_answer_suffix *asuffix = NULL;
    struct pico_dns_query *q = NULL;
    char *p_asuffix = NULL;
    char msg[PICO_DNS_MAX_RESPONSE_LEN] = {
        0
    };

    if (ev == PICO_SOCK_EV_ERR) {
        dns_dbg("DNS: socket error received\n");
        return;
    }

    if (ev & PICO_SOCK_EV_RD) {
        if (pico_socket_read(s, msg, PICO_DNS_MAX_RESPONSE_LEN) <= 0)
            return;
    }

    prefix = (struct pico_dns_prefix *)msg;
    domain = &prefix->domain;
    qsuffix = (struct pico_dns_query_suffix *)pico_dns_client_seek(domain->name);
    /* valid asuffix is determined dynamically later on */

    if (pico_dns_client_check_prefix(prefix) < 0)
        return;

    q = pico_dns_client_find_query(short_be(prefix->id));
    if (!q)
        return;

    if (pico_dns_client_check_qsuffix(qsuffix, q) < 0)
        return;

    p_asuffix = (char *)qsuffix + sizeof(struct pico_dns_query_suffix);
    p_asuffix = pico_dns_client_seek_suffix(p_asuffix, prefix, q);
    if (!p_asuffix)
        return;

    asuffix = (struct pico_dns_answer_suffix *)p_asuffix;
    pico_dns_client_user_callback(asuffix, q);

    return;
}

static int pico_dns_client_getaddr_init(const char *url, uint16_t proto, void (*callback)(char *, void *), void *arg)
{
    char *msg = NULL;
    struct pico_dns_prefix *prefix = NULL;
    struct pico_dns_name *domain = NULL;
    struct pico_dns_query_suffix *qsuffix = NULL;
    struct pico_dns_query *q = NULL;
    uint16_t len = 0, lblen = 0, strlen = 0;
    (void)proto;

    if (!url || !callback) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    strlen = pico_dns_client_strlen(url);
    lblen = (uint16_t)(PICO_DNS_LABEL_INITIAL + strlen + PICO_DNS_LABEL_ROOT);
    len = (uint16_t)(sizeof(struct pico_dns_prefix) + lblen + sizeof(struct pico_dns_query_suffix));
    msg = PICO_ZALLOC(len);
    if (!msg) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    prefix = (struct pico_dns_prefix *)msg;
    domain = &prefix->domain;
    qsuffix = (struct pico_dns_query_suffix *)(domain->name + lblen);
    memcpy(domain->name + PICO_DNS_LABEL_INITIAL, url, strlen);

    /* assemble dns message */
    pico_dns_client_query_prefix(prefix);
    pico_dns_client_query_domain(domain->name);

#ifdef PICO_SUPPORT_IPV6
    if (proto == PICO_PROTO_IPV6) {
        pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_AAAA, PICO_DNS_CLASS_IN);
    } else
#endif
    pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN);

    q = pico_dns_client_add_query(prefix, len, qsuffix, callback, arg);
    if (!q) {
        PICO_FREE(msg);
        return -1;
    }

    if (pico_dns_client_send(q) < 0) {
        pico_dns_client_del_query(q->id); /* frees msg */
        return -1;
    }

    return 0;
}

int pico_dns_client_getaddr(const char *url, void (*callback)(char *, void *), void *arg)
{
    return pico_dns_client_getaddr_init(url, PICO_PROTO_IPV4, callback, arg);
}

int pico_dns_client_getaddr6(const char *url, void (*callback)(char *, void *), void *arg)
{
    return pico_dns_client_getaddr_init(url, PICO_PROTO_IPV6, callback, arg);
}

int pico_dns_client_getname(const char *ip, void (*callback)(char *, void *), void *arg)
{
    const char *inaddr_arpa = ".in-addr.arpa";
    char *msg = NULL;
    struct pico_dns_prefix *prefix = NULL;
    struct pico_dns_name *domain = NULL;
    struct pico_dns_query_suffix *qsuffix = NULL;
    struct pico_dns_query *q = NULL;
    uint16_t len = 0, lblen = 0, strlen = 0, arpalen = 0;

    if (!ip || !callback) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    strlen = pico_dns_client_strlen(ip);
    arpalen = pico_dns_client_strlen(inaddr_arpa);
    lblen = (uint16_t)(PICO_DNS_LABEL_INITIAL + strlen + arpalen + PICO_DNS_LABEL_ROOT);
    len = (uint16_t)(sizeof(struct pico_dns_prefix) + lblen + sizeof(struct pico_dns_query_suffix));
    msg = PICO_ZALLOC(len);
    if (!msg) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    prefix = (struct pico_dns_prefix *)msg;
    domain = &prefix->domain;
    qsuffix = (struct pico_dns_query_suffix *)(prefix->domain.name + lblen);
    memcpy(domain->name + PICO_DNS_LABEL_INITIAL, ip, strlen);
    pico_dns_client_mirror(domain->name + PICO_DNS_LABEL_INITIAL);
    memcpy(domain->name + PICO_DNS_LABEL_INITIAL + strlen, inaddr_arpa, arpalen);
    /* assemble dns message */
    pico_dns_client_query_prefix(prefix);
    pico_dns_client_query_domain(domain->name);
    pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN);
    q = pico_dns_client_add_query(prefix, len, qsuffix, callback, arg);
    if (!q) {
        PICO_FREE(msg);
        return -1;
    }

    if (pico_dns_client_send(q) < 0) {
        pico_dns_client_del_query(q->id); /* frees msg */
        return -1;
    }

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
    uint8_t nibble = (byte & 0xf0) >> 4;
    if (nibble < 10)
        return (char)(nibble + '0');
    else
        return (char)(nibble - 0xa + 'a');
}

static void pico_dns_ipv6_set_ptr(const char *ip, char *dst)
{
    struct pico_ip6 ip6;
    int i, j = 0;
    pico_string_to_ipv6(ip, ip6.addr);
    for (i = 15; i >= 0; i--) {
        dst[j++] = dns_ptr_ip6_nibble_lo(ip6.addr[i]);
        dst[j++] = '.';
        dst[j++] = dns_ptr_ip6_nibble_hi(ip6.addr[i]);
        dst[j++] = '.';
    }
}

int pico_dns_client_getname6(const char *ip, void (*callback)(char *, void *), void *arg)
{
    const char *inaddr6_arpa = ".IP6.ARPA";
    char *msg = NULL;
    struct pico_dns_prefix *prefix = NULL;
    struct pico_dns_name *domain = NULL;
    struct pico_dns_query_suffix *qsuffix = NULL;
    struct pico_dns_query *q = NULL;
    uint16_t len = 0, lblen = 0, arpalen = 0;

    if (!ip || !callback) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    arpalen = pico_dns_client_strlen(inaddr6_arpa);
    lblen = (uint16_t)(PICO_DNS_LABEL_INITIAL + STRLEN_PTR_IP6 + arpalen + PICO_DNS_LABEL_ROOT);
    len = (uint16_t)(sizeof(struct pico_dns_prefix) + lblen + sizeof(struct pico_dns_query_suffix));
    msg = PICO_ZALLOC(len);
    if (!msg) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    prefix = (struct pico_dns_prefix *)msg;
    domain = &prefix->domain;
    qsuffix = (struct pico_dns_query_suffix *)(prefix->domain.name + lblen);
    pico_dns_ipv6_set_ptr(ip, domain->name + PICO_DNS_LABEL_INITIAL);
    memcpy(domain->name + PICO_DNS_LABEL_INITIAL + STRLEN_PTR_IP6, inaddr6_arpa, arpalen);
    /* assemble dns message */
    pico_dns_client_query_prefix(prefix);
    pico_dns_client_query_domain(domain->name);
    pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN);
    q = pico_dns_client_add_query(prefix, len, qsuffix, callback, arg);
    if (!q) {
        PICO_FREE(msg);
        return -1;
    }

    if (pico_dns_client_send(q) < 0) {
        pico_dns_client_del_query(q->id); /* frees msg */
        return -1;
    }

    return 0;
}
#endif

int pico_dns_client_nameserver(struct pico_ip4 *ns, uint8_t flag)
{
    if (!ns) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (flag)
    {
    case PICO_DNS_NS_ADD:
        if (!pico_dns_client_add_ns(ns))
            return -1;

        break;

    case PICO_DNS_NS_DEL:
        if (pico_dns_client_del_ns(ns) < 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        break;

    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    return 0;
}

int pico_dns_client_init(void)
{
    struct pico_ip4 default_ns = {
        0
    };

    if (pico_string_to_ipv4(PICO_DNS_NS_GOOGLE, &default_ns.addr) < 0)
        return -1;

    return pico_dns_client_nameserver(&default_ns, PICO_DNS_NS_ADD);
}

#endif /* PICO_SUPPORT_DNS_CLIENT */
