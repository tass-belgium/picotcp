/*********************************************************************
   PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.
   .
   Author: Toon Stegen
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_MDNS

#define PICO_MDNS_QUERY_TIMEOUT (10000) /* Ten seconds */

#define mdns_dbg(...) do {} while(0)
/* #define mdns_dbg dbg */

#define PICO_MDNS_PROBE 1
#define PICO_MDNS_NO_PROBE 0
#define PICO_MDNS_INVERT 1
#define PICO_MDNS_NO_INVERT 0
#define PICO_MDNS_CACHE_FLUSH_BIT 0x8000u
static struct pico_ip4 inaddr_any = {
    0
};

/* struct containing status of a query */
struct pico_mdns_cookie {
    struct pico_dns_header *header;     /* packet header */
    char *url;                          /* hostname being queried */
    unsigned int count;                 /* number of packets to send */
    uint16_t len;                       /* length of header */
    uint16_t qtype;
    uint16_t qclass;
    unsigned int probe;                 /* indicator for probing */
    void (*callback)(char *, void *);
    void *arg;
    struct pico_timer *timer;
};

/* Global socket and port for all mdns communication */
static struct pico_socket *mdns_sock = NULL;
static uint16_t mdns_port = 5353u;

/* only one hostname can be claimed at the time */
static char *mdns_global_host;

/* Function for comparing two queries in a tree */
static int mdns_cmp(void *ka, void *kb)
{
    struct pico_mdns_cookie *a = ka, *b = kb;
    int ret = strcmp(a->url, b->url);
    if (!ret)
        return 0;

    return (ret) ? (-1) : (1);
}

/* cache records for the mdns hosts in the network */
PICO_TREE_DECLARE(MDNSTable, mdns_cmp);

/* tree containing queries */
PICO_TREE_DECLARE(QTable, mdns_cmp);

/* sends an mdns packet on the global socket*/
static int pico_mdns_send(struct pico_dns_header *hdr, unsigned int len)
{
    struct pico_ip4 dst;
    pico_string_to_ipv4("224.0.0.251", &dst.addr);
    return pico_socket_sendto(mdns_sock, hdr, (int)len, &dst, short_be(mdns_port));
}

/* delete a cookie from the tree*/
static int pico_mdns_del_cookie(char *url)
{
    struct pico_mdns_cookie test, *found = NULL;
    char temp[256] = {
        0
    };
    strcpy(temp + 1, url);

    test.url = temp;
    pico_dns_client_query_domain(test.url);
    found = pico_tree_findKey(&QTable, &test);

    if (!found) {
        mdns_dbg("Could not find cookie to delete\n");
        return -1;
    }

    pico_tree_delete(&QTable, found);
    PICO_FREE(found->header);
    PICO_FREE(found);
    return 0;
}

static void pico_mdns_timeout(pico_time now, void *_arg)
{
    struct pico_mdns_cookie *ck = (struct pico_mdns_cookie *)_arg;
    (void)now;

    if(ck->callback)
        ck->callback(NULL, ck->arg);

    pico_mdns_del_cookie(ck->url);
}

/* populate and add cookie to the tree */
static struct pico_dns_header *pico_mdns_add_cookie(struct pico_dns_header *hdr, uint16_t len, struct pico_dns_query_suffix *suffix, unsigned int probe, void (*callback)(char *str, void *arg), void *arg)
{
    struct pico_mdns_cookie *ck = NULL, *found = NULL;

    ck = PICO_ZALLOC(sizeof(struct pico_mdns_cookie));
    if (!ck)
        return NULL;

    ck->header = hdr;
    ck->url = (char *)hdr + sizeof(struct pico_dns_header);
    pico_to_lowercase(ck->url);
    ck->len = len;
    ck->qtype = short_be(suffix->qtype);
    if (short_be(suffix->qtype) == PICO_DNS_TYPE_PTR)
        mdns_dbg("PTR\n");

    ck->qclass = short_be(suffix->qclass);
    ck->count = 3;
    ck->probe = probe;
    ck->callback = callback;
    ck->arg = arg;

    found = pico_tree_insert(&QTable, ck);
    /* cookie already in tree */
    if (found) {
        pico_err = PICO_ERR_EAGAIN;
        PICO_FREE(ck);
        PICO_FREE(hdr);
        return NULL;
    }

    ck->timer = pico_timer_add(PICO_MDNS_QUERY_TIMEOUT, pico_mdns_timeout, ck);
    return hdr;
}
static void pico_mdns_fill_header(struct pico_dns_header *hdr, uint16_t qdcount, uint16_t ancount)
{
    hdr->id = short_be(0);
    if(qdcount) {
        hdr->qr = 0;
        hdr->aa = 0;
    } else {
        hdr->qr = 1;
        hdr->aa = 1;
    }

    hdr->opcode = 0;
    hdr->tc = 0;
    hdr->rd = 0;
    hdr->ra = 0;
    hdr->z = 0;
    hdr->qdcount = short_be(qdcount);
    hdr->ancount = short_be(ancount);
    hdr->nscount = short_be(0);
    hdr->arcount = short_be(0);
}

static void pico_mdns_answer_suffix(struct pico_dns_answer_suffix *asuf, uint16_t qtype, uint16_t qclass, uint32_t ttl, uint16_t rdlength)
{
    asuf->qtype = short_be(qtype);
    asuf->qclass = short_be(qclass | (uint16_t) ~PICO_MDNS_CACHE_FLUSH_BIT);
    asuf->ttl = long_be(ttl);
    asuf->rdlength = short_be(rdlength);

}

static uint16_t mdns_get_len(uint16_t qtype, char *rdata)
{
    uint16_t len = 0;
    switch(qtype)
    {
    case PICO_DNS_TYPE_A:
        len = PICO_SIZE_IP4;
        break;
 #ifdef PICO_SUPPORT_IPV6
    case PICO_DNS_TYPE_AAAA:
        len = PICO_SIZE_IP6;
        break;
 #endif
    case PICO_DNS_TYPE_PTR:
        len = (uint16_t)(strlen(rdata) + 1u);     /* +1 for null termination */
        break;
    }
    return len;

}


/* create an mdns answer */
static struct pico_dns_header *pico_mdns_create_answer(char *url, unsigned int *len, uint16_t qtype, void *_rdata)
{
    struct pico_dns_header *header = NULL;
    char *domain = NULL;
    uint8_t *answer = NULL;
    struct pico_dns_answer_suffix *asuffix = NULL;
    uint32_t ttl = 224;
    uint16_t slen, datalen;
    char *rdata = (char*)_rdata;


    datalen = mdns_get_len(qtype, rdata);
    if (!datalen)
        return NULL;

    slen = (uint16_t)(pico_dns_client_strlen(url) + 2u);
    *len = (unsigned int)(sizeof(struct pico_dns_header) + slen + sizeof(struct pico_dns_answer_suffix) + datalen);

    header = PICO_ZALLOC(*len);
    if(!header) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    domain = (char *)header + sizeof(struct pico_dns_header);
    memcpy(domain + 1u, url, strlen(url));
    asuffix = (struct pico_dns_answer_suffix *)(domain + slen);
    answer = ((uint8_t *)asuffix + sizeof(struct pico_dns_answer_suffix));
    memcpy(answer, rdata, datalen);

    /* assemble dns message */
    pico_mdns_fill_header(header, 0, 1);
    pico_dns_client_query_domain(domain);

    pico_mdns_answer_suffix(asuffix, qtype, PICO_DNS_CLASS_IN, ttl, datalen);

    return header;
}

static int pico_mdns_perform_name_query(struct pico_dns_query_suffix *qsuffix, uint16_t proto)
{
#ifdef PICO_SUPPORT_IPV6
    if(proto == PICO_PROTO_IPV6) {
        pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_AAAA, PICO_DNS_CLASS_IN);
        return 0;
    }

#endif
    if(proto == PICO_PROTO_IPV4) {
        pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN);
        return 0;
    }

    return -1;
}


static int pico_mdns_perform_query(struct pico_dns_query_suffix *qsuffix, uint16_t proto, unsigned int probe, unsigned int inv)
{
    if(probe)
        pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_ANY, PICO_DNS_CLASS_IN);
    else if(inv)
        pico_dns_client_query_suffix(qsuffix, PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN);
    else
        return pico_mdns_perform_name_query(qsuffix, proto);

    return 0;

}

static unsigned int pico_mdns_prepare_query_string(const char *url, char *inaddr_arpa, unsigned int inverse, uint16_t proto)
{
    unsigned int slen = 0;
    if(inverse && proto == PICO_PROTO_IPV4) {
        strcpy(inaddr_arpa, ".in-addr.arpa");
        slen = (uint16_t)(pico_dns_client_strlen(url) + 2u);
    }

#ifdef PICO_SUPPORT_IPV6
    else if (inverse && proto == PICO_PROTO_IPV6) {
        strcpy(inaddr_arpa, ".IP6.ARPA");
        slen = STRLEN_PTR_IP6 + 2u;
    }
#endif
    else {
        strcpy(inaddr_arpa, "");
        slen = (uint16_t)(pico_dns_client_strlen(url) + 2u);
    }
    return slen;
}

static int pico_mdns_create_query_valid_args(const char *url, uint16_t *len, uint16_t proto, void (*callback)(char *str, void *arg))
{
    if (!url || !len || !callback)
        return -1;

    if (proto != PICO_PROTO_IPV6 && proto != PICO_PROTO_IPV4)
        return -1;

    return 0;
}


static void pico_mdns_populate_query_domain(const char *url, char *domain, char *inaddr_arpa, unsigned int arpalen, unsigned int inverse, unsigned int proto, unsigned int slen)
{

    if(inverse && proto == PICO_PROTO_IPV4) {
        memcpy(domain + 1u, url, strlen(url));
        pico_dns_client_mirror(domain + 1u);
        memcpy(domain + slen - 1, inaddr_arpa, arpalen);
    }

#ifdef PICO_SUPPORT_IPV6
    else if (inverse && proto == PICO_PROTO_IPV6) {
        pico_dns_ipv6_set_ptr(url, domain + 1u);
        memcpy(domain + 1u + STRLEN_PTR_IP6, inaddr_arpa, arpalen);
    }
#endif
    else
        memcpy(domain + 1u, url, strlen(url));
}

/* create an mdns query */
static struct pico_dns_header *pico_mdns_create_query(const char *url, uint16_t *len, uint16_t proto, unsigned int probe, unsigned int inverse, void (*callback)(char *str, void *arg), void *arg)
{
    struct pico_dns_header *header = NULL;
    char *domain = NULL;
    struct pico_dns_query_suffix *qsuffix = NULL;
    char inaddr_arpa[14];
    unsigned int slen, arpalen;

    if (pico_mdns_create_query_valid_args(url, len, proto, callback) < 0) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }


    slen = pico_mdns_prepare_query_string(url, inaddr_arpa, inverse, proto);

    arpalen = (unsigned int)strlen(inaddr_arpa);
    *len = (uint16_t)(sizeof(struct pico_dns_header) + slen + arpalen + sizeof(struct pico_dns_query_suffix));

    header = PICO_ZALLOC(*len);
    if(!header) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    domain = (char *)header + sizeof(struct pico_dns_header);
    qsuffix = (struct pico_dns_query_suffix *)(domain + slen + arpalen);

    pico_mdns_populate_query_domain(url, domain, inaddr_arpa, arpalen, inverse, proto, slen);

    /* assemble dns message */
    pico_mdns_fill_header(header, 1, 0);
    pico_dns_client_query_domain(domain);

    if (pico_mdns_perform_query(qsuffix, proto, probe, inverse) < 0)
        return NULL;

    return pico_mdns_add_cookie(header, *len, qsuffix, probe, callback, arg);
}


/* look for a cookie in the tree */
static struct pico_mdns_cookie *pico_mdns_find_cookie(char *url)
{
    struct pico_mdns_cookie test;
    char temp[256] = {
        0
    };
    strcpy(temp + 1, url);
    pico_to_lowercase(temp);
    test.url = temp;
    pico_dns_client_query_domain(test.url);
    return pico_tree_findKey(&QTable, &test);
}


#ifdef PICO_SUPPORT_IPV6
static struct pico_ip6 *pico_get_ip6_from_ip4(struct pico_ip4 *ipv4_addr)
{
    struct pico_device *dev = NULL;
    struct pico_ipv6_link *link = NULL;
    if((dev = pico_ipv4_link_find(ipv4_addr)) == NULL) {
        mdns_dbg("Could not find device!\n");
        return NULL;
    }

    if((link = pico_ipv6_link_by_dev(dev)) == NULL) {
        mdns_dbg("Could not find link!\n");
        return NULL;
    }

    return &link->address;

}
#endif

static struct pico_dns_header *pico_mdns_query_create_answer(union pico_address *local_addr, uint16_t qtype,
                                                             unsigned int *len, char *name)
{
    if(qtype == PICO_DNS_TYPE_A || qtype == PICO_DNS_TYPE_ANY) {
        return pico_mdns_create_answer(mdns_global_host, len, qtype, local_addr);
    }

#ifdef PICO_SUPPORT_IPV6
    if(qtype == PICO_DNS_TYPE_AAAA || qtype == PICO_DNS_TYPE_ANY) {
        struct pico_ip6 *ip6 = pico_get_ip6_from_ip4(&local_addr->ip4);
        return pico_mdns_create_answer(mdns_global_host, len, qtype, ip6);
    }

#endif
    /* reply to PTR records */
    if(qtype == PICO_DNS_TYPE_PTR) {
        char host_conv[255] = {
            0
        };
        mdns_dbg("Replying on PTR query...\n");
        strcpy(host_conv + 1, mdns_global_host);
        pico_dns_client_query_domain(host_conv);
        return pico_mdns_create_answer(name, len, qtype, host_conv);
    }

    return NULL;
}


/* reply on a single query */
static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer, char *name)
{
    struct pico_dns_header *header = NULL;
    union pico_address *local_addr = NULL;
    unsigned int len;

    local_addr = (union pico_address *) pico_ipv4_source_find(&peer);
    if (!local_addr) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        return -1;
    }

    header = pico_mdns_query_create_answer(local_addr, qtype, &len, name);

    if (!header)
        return -1;

    if(pico_mdns_send(header, len) != (int)len) {
        mdns_dbg("Send error occurred!\n");
        return -1;
    }

    return 0;
}

static int pico_check_query_name(char *url)
{
    char addr[29] = {
        0
    };
    if(strcmp(url, mdns_global_host) == 0)
        return 1;

    pico_ipv4_to_string(addr, mdns_sock->local_addr.ip4.addr);
    pico_dns_client_mirror(addr);
    memcpy(addr + strlen(addr), ".in-addr.arpa", 13);
    if(strcmp(url, addr) == 0)
        return 1;

    return 0;
}


/* handle a single incoming query */
static int pico_mdns_handle_query(char *name, struct pico_dns_query_suffix *suf, struct pico_ip4 peer)
{
    struct pico_mdns_cookie *ck = NULL;

    /* remove cache flush bit if set */
    suf->qclass &= short_be((uint16_t) ~PICO_MDNS_CACHE_FLUSH_BIT);

    mdns_dbg("Query type: %u, class: %u\n", short_be(suf->qtype), short_be(suf->qclass));

    if(mdns_global_host) {
        if(pico_check_query_name(name)) {
            pico_mdns_reply_query(short_be(suf->qtype), peer, name);
        } else {
            mdns_dbg("Received request for unknown hostname\n");
        }
    } else {
        ck = pico_mdns_find_cookie(name);
        if(ck && ck->count < 3) {
            /* we are probing, go probe tiebreaking */
        } else {
            mdns_dbg("Received query before init\n");
        }
    }

    return 0;
}

/* handle a single incoming answer */
static int pico_mdns_handle_answer(char *url, struct pico_dns_answer_suffix *suf, char *data)
{
    struct pico_mdns_cookie *ck = NULL;

    /* remove cache flush bit if set */
    suf->qclass &= short_be((uint16_t) ~PICO_MDNS_CACHE_FLUSH_BIT);

    mdns_dbg("Answer for record %s was received:\n", url);
    mdns_dbg("type: %u, class: %u, ttl: %lu, rdlen: %u\n", short_be(suf->qtype),
             short_be(suf->qclass), (unsigned long)long_be(suf->ttl), short_be(suf->rdlength));

    /* Check in the query tree whether a request was sent */
    ck = pico_mdns_find_cookie(url);
    if(!ck) {
        mdns_dbg("We didn't ask for this answer.\n");
    } else {
        mdns_dbg("Found a corresponding cookie!\n");
        /* if we are probing, set probe to zero so the probe timer stops the next time it goes off */
        if (ck->probe) {
            mdns_dbg("Probe set to zero\n");
            ck->probe = 0;
        } else {
            if(short_be(suf->qtype) == PICO_DNS_TYPE_A) {
                uint32_t rdata = long_from(data);
                char peer_addr[46];
                pico_ipv4_to_string(peer_addr, long_from(&rdata));
                ck->callback(peer_addr, ck->arg);
            }

#ifdef PICO_SUPPORT_IPV6
            else if(short_be(suf->qtype) == PICO_DNS_TYPE_AAAA) {
                uint8_t *rdata = (uint8_t *) data;
                char peer_addr[46];
                pico_ipv6_to_string(peer_addr, rdata);
                ck->callback(peer_addr, ck->arg);
            }
#endif
            else if(short_be(suf->qtype) == PICO_DNS_TYPE_PTR) {
                pico_dns_client_answer_domain(data);
                ck->callback(data + 1, ck->arg);    /* +1 to discard the beginning dot */
            }
            else {
                mdns_dbg("Unrecognised record type\n");
                ck->callback(NULL, ck->arg);
            }
            pico_timer_cancel(ck->timer);
            pico_mdns_del_cookie(url);
        }
    }

    return 0;
}
/* returns the compressed length of the compressed name without NULL terminator */
static unsigned int pico_mdns_namelen_comp(char *name)
{
    unsigned int len;
    char *ptr;

    ptr = name;
    while (*ptr != '\0' && !(*ptr & 0x80)) {
        ptr += (uint8_t) *ptr + 1;
    }
    len = (unsigned int) (ptr - name);
    if(*ptr != '\0') {
        len++;
    }

    return len;
}

/* returns the uncompressed length of the compressed name  without NULL terminator */
static unsigned int pico_mdns_namelen_uncomp(char *name, char *buf)
{
    unsigned int len;
    char *ptr, *begin_comp;

    len = 0;
    begin_comp = name;
    ptr = begin_comp;
    while(*ptr != '\0') {
        ptr += (uint8_t)*ptr + 1;
        if(*ptr & 0x80) {
            len += (unsigned int) (ptr - begin_comp);
            begin_comp = buf + *(ptr + 1);  /* set at beginning of compstring*/
            ptr = begin_comp;
        }
    }
    len += (unsigned int) (ptr - begin_comp);
    return len;
}

/* replace the label length in the domain name by '.'
 * f.e. 3www6google2be0 => .www.google.be
 * AND expand compressed names */
static char *pico_mdns_expand_name_comp(char *url, char *buf)
{
    unsigned int len;
    char *ptr, *begin_comp, *str = NULL, *sp;

    len = pico_mdns_namelen_uncomp(url, buf);
    mdns_dbg("Uncomp len:%u, comp len:%u.\n", len, pico_mdns_namelen_comp(url));
    if(len < pico_mdns_namelen_comp(url)) {
        mdns_dbg("BOOM compressed longer than uncompressed!\n");
        return NULL;
    }

    str = PICO_ZALLOC(len + 1);     /* + 1 for null terminator */
    if(!str) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    begin_comp = url;
    ptr = begin_comp;
    sp = str;
    *sp = '.';
    sp++;
    while(*ptr != '\0') {
        memcpy(sp, ptr + 1, *(uint8_t*)ptr);
        sp += (uint8_t)*ptr;
        *sp = '.';
        sp++;
        ptr += (uint8_t)*ptr + 1; /* jump to next occurring dot */
        if(*ptr & 0x80) {
            len += (unsigned int) (ptr - begin_comp) + 1;   /* +1 for the dot at the end of the label */
            begin_comp = buf + *(ptr + 1);  /* set at beginning of compstring*/
            ptr = begin_comp;
        }
    }
    sp--;
    *sp = '\0';

    return str;
}

/* parses an incoming packet */
static int pico_mdns_recv(void *buf, int buflen, struct pico_ip4 peer)
{
    struct pico_dns_header *header = (struct pico_dns_header *) buf;
    char *ptr = (char *)header + sizeof(struct pico_dns_header);
    struct pico_dns_query_suffix *qsuf;
    struct pico_dns_answer_suffix *asuf;
    uint16_t i, qcount, acount;
    char *data;

    qcount = short_be(header->qdcount);
    acount = short_be(header->ancount);
    mdns_dbg("\n>>>>>>> QDcount: %u, ANcount: %u\n", qcount, acount);


    /* handle queries */
    for(i = 0; i < qcount; i++) {
        qsuf = (struct pico_dns_query_suffix*) (ptr + pico_mdns_namelen_comp(ptr) + 1);
        pico_dns_client_answer_domain(ptr);
        if (!ptr)
            return -1;

        pico_mdns_handle_query(ptr + 1, qsuf, peer);
        ptr = (char *)qsuf + sizeof(struct pico_dns_query_suffix);
        if(ptr - (char *)header > buflen) {
            mdns_dbg("buffer is too short! ptr offset=%ld buflen=%d\n", ptr - (char*)header, buflen);
            return -1;
        }
    }
    /* handle answers */
    for(i = 0; i < acount; i++) {
        char *name;
        asuf = (struct pico_dns_answer_suffix*) (ptr + pico_mdns_namelen_comp(ptr) + 1);
        if((name = pico_mdns_expand_name_comp(ptr, buf)) == NULL) {
            mdns_dbg("Received a zero name pointer\n");
            return -1;
        }

        data = (char *)asuf + sizeof(struct pico_dns_answer_suffix);
        pico_mdns_handle_answer(name + 1, asuf, data);  /* +1 for starting . */
        PICO_FREE(name);
        ptr = data + short_be(asuf->rdlength);
        if(ptr - (char *)header > buflen) {
            mdns_dbg("buffer is too short! ptr offset=%ld buflen=%d\n", ptr - (char*)header, buflen);
            return -1;
        }
    }
    return 0;
}

/* callback for UDP socket events */
static void pico_mdns_wakeup(uint16_t ev, struct pico_socket *s)
{
    char recvbuf[1400];
    int pico_read = 0;
    struct pico_ip4 peer = {
        0
    };
    uint16_t port = 0;
    char host[30];

    /* process read event, data available */
    if (ev == PICO_SOCK_EV_RD) {
        mdns_dbg("READ EVENT!\n");
        /* receive while data available in socket buffer */
        while((pico_read = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port)) > 0) {
            /* if pico_socket_setoption is implemented, this check is not needed */
            pico_ipv4_to_string(host, peer.addr);
            mdns_dbg("Received data from %s:%u\n", host, short_be(port));
            pico_mdns_recv(recvbuf, pico_read, peer);
        }
    }
    /* socket is closed */
    else if(ev == PICO_SOCK_EV_CLOSE) {
        mdns_dbg("Socket is closed. Bailing out.\n");
        return;
    }
    /* process error event, socket error occured */
    else if(ev == PICO_SOCK_EV_ERR) {
        mdns_dbg("Socket Error received. Bailing out.\n");
        return;
    }
}

static void pico_mdns_announce_timer(pico_time now, void *arg)
{
    struct pico_dns_header *header = NULL;
    unsigned int len;
    (void) now;
    (void) arg;

    if(!mdns_global_host)
        return;

    header = pico_mdns_create_answer(mdns_global_host, &len, PICO_DNS_TYPE_A, &mdns_sock->local_addr);
    if(!header) {
        mdns_dbg("Could not create answer header!\n");
        return;
    }

    if(pico_mdns_send(header, len) != (int)len) {
        mdns_dbg("send error occured!\n");
        return;
    }
}

/* announce the local hostname to the network */
static int pico_mdns_announce(void)
{
    struct pico_dns_header *header = NULL;
    unsigned int len;

    if(!mdns_global_host)
        return -1;

    header = pico_mdns_create_answer(mdns_global_host, &len, PICO_DNS_TYPE_A, &mdns_sock->local_addr);
    if(!header) {
        mdns_dbg("Could not create answer header!\n");
        return -1;
    }

    if(pico_mdns_send(header, len) != (int)len) {
        mdns_dbg("send error occured!\n");
        return -1;
    }

    pico_timer_add(1000, pico_mdns_announce_timer, NULL);
    return 0;
}

/* callback function for the probe timer */
static void pico_mdns_probe_timer(pico_time now, void *arg)
{
    char *url = (char *)arg;
    struct pico_mdns_cookie *ck;
    char ok[] = "OK";
    (void) now;

    if(!arg)
        return;

    ck = pico_mdns_find_cookie(url);

    if(!ck) {
        mdns_dbg("Corresponding cookie not found!\n");
        PICO_FREE(arg);
        return;
    }

    if(ck->probe == 0) {
        mdns_dbg("Hostname already in use!\n");
        PICO_FREE(arg);
        ck->callback(NULL, ck->arg);
        return;
    }

    if(ck->count == 0) {
        mdns_global_host = url;
        mdns_dbg("count is zero! Claimed %s\n", mdns_global_host);
        pico_mdns_announce();
        ck->callback(ok, ck->arg);
        pico_mdns_del_cookie(url);
    } else {
        if(pico_mdns_send(ck->header, ck->len) != (int)ck->len) {
            mdns_dbg("Send error occurred!\n");
            PICO_FREE(arg);
            ck->callback(NULL, ck->arg);
            return;
        }

        ck->count--;
        pico_timer_add(250, pico_mdns_probe_timer, url);
    }
}

/* checks whether the given name is in use */
static int pico_mdns_probe(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg)
{
    struct pico_dns_header *header = NULL;
    uint16_t len = 0;
    char *host;
    /* QU question with unicast response bit set */
    header = pico_mdns_create_query(hostname, &len, 0, PICO_MDNS_PROBE, PICO_MDNS_NO_INVERT, cb_initialised, arg);
    if(!header || !len) {
        mdns_dbg("ERROR: mdns_create_query returned NULL\n");
        return -1;
    }

    host = PICO_ZALLOC(strlen(hostname) + 1);
    if(!host) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    strcpy(host, hostname);

    pico_timer_add(pico_rand() % 250, pico_mdns_probe_timer, host);

    return 0;
}

/* Opens the socket, probes for the usename and calls back the user when a host name is set up */
int pico_mdns_init(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg)
{
    struct pico_ip_mreq mreq;
    uint16_t proto = PICO_PROTO_IPV4, port;
    int loop = 0;
    int ttl = 255;

    if(!hostname) {
        mdns_dbg("No hostname given!\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if(!cb_initialised) {
        mdns_dbg("No callback function suplied!\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    mdns_sock = pico_socket_open(proto, PICO_PROTO_UDP, &pico_mdns_wakeup);
    if(!mdns_sock) {
        mdns_dbg("Open returned empty socket\n");
        return -1;
    }

    if(pico_string_to_ipv4("224.0.0.251", &mreq.mcast_group_addr.addr) != 0) {
        mdns_dbg("String to ipv4 error\n");
        return -1;
    }

    mreq.mcast_link_addr = inaddr_any;

    if(pico_socket_setoption(mdns_sock, PICO_IP_MULTICAST_LOOP, &loop) < 0) {
        mdns_dbg("socket_setoption PICO_IP_MULTICAST_LOOP failed\n");
        return -1;
    }

    if(pico_socket_setoption(mdns_sock, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        mdns_dbg("socket_setoption PICO_IP_ADD_MEMBERSHIP failed\n");
        return -1;
    }

    if(pico_socket_setoption(mdns_sock, PICO_IP_MULTICAST_TTL, &ttl) < 0) {
        mdns_dbg("socket_setoption PICO_IP_MULTICAST_TTL failed\n");
        return -1;
    }

    port = short_be(mdns_port);
    if (pico_socket_bind(mdns_sock, &inaddr_any, &port) != 0) {
        mdns_dbg("Bind error!\n");
        return -1;
    }

    if(pico_mdns_probe(hostname, cb_initialised, arg) != 0) {
        mdns_dbg("Probe error\n");
        return -1;
    }

    return 0;
}

static int pico_mdns_getaddr_generic(const char *url, void (*callback)(char *ip, void *arg), void *arg, uint16_t proto)
{
    struct pico_dns_header *header = NULL;
    uint16_t len = 0;
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }


    if(!mdns_sock) {
        mdns_dbg("Mdns socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }

    header = pico_mdns_create_query(url, &len, proto, PICO_MDNS_NO_PROBE, PICO_MDNS_NO_INVERT, callback, arg);
    if(!header || !len) {
        mdns_dbg("ERROR: mdns_create_query returned NULL\n");
        return -1;
    }

    if(pico_mdns_send(header, len) != (int)len) {
        mdns_dbg("Send error!\n");
        return -1;
    }

    return 0;
}

static int pico_mdns_getname_generic(const char *ip, void (*callback)(char *url, void *arg), void *arg, uint16_t proto)
{
    struct pico_dns_header *header = NULL;
    uint16_t len = 0;
    if (!ip) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if(!mdns_sock) {
        mdns_dbg("Mdns socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }

    header = pico_mdns_create_query(ip, &len, proto, PICO_MDNS_NO_PROBE, PICO_MDNS_INVERT, callback, arg);
    if(!header || !len) {
        mdns_dbg("ERROR: mdns_create_query returned NULL\n");
        return -1;
    }

    if(pico_mdns_send(header, len) != (int)len) {
        mdns_dbg("Send error!\n");
        return -1;
    }

    return 0;
}

int pico_mdns_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg)
{
    return pico_mdns_getaddr_generic(url, callback, arg, PICO_PROTO_IPV4);
}

int pico_mdns_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg)
{
    return pico_mdns_getname_generic(ip, callback, arg, PICO_PROTO_IPV4);
}

#ifdef PICO_SUPPORT_IPV6
int pico_mdns_getaddr6(const char *url, void (*callback)(char *ip, void *arg), void *arg)
{
    return pico_mdns_getaddr_generic(url, callback, arg, PICO_PROTO_IPV6);
}

int pico_mdns_getname6(const char *ip, void (*callback)(char *url, void *arg), void *arg)
{
    return pico_mdns_getname_generic(ip, callback, arg, PICO_PROTO_IPV6);
}
#endif

#endif /* PICO_SUPPORT_MDNS */
