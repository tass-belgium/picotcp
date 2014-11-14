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
#include "pico_mdns.h"
#include "pico_dns_common.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_MDNS

#define PICO_MDNS_QUERY_TIMEOUT (10000) /* Ten seconds */
#define PICO_MDNS_RR_TTL_TICK (1000) /* One second */

/* define mdns_dbg(...) do {} while(0) */
#define mdns_dbg dbg

#define PICO_MDNS_PROBE 1
#define PICO_MDNS_NO_PROBE 0
#define PICO_MDNS_INVERT 1
#define PICO_MDNS_NO_INVERT 0
#define PICO_MDNS_CACHE_FLUSH_BIT 0x8000u
#define PICO_MDNS_QU_CACHE_BIT 15
#define PICO_MDNS_PACKET_ID 0
#define PICO_MDNS_DEFAULT_TTL 224

static struct pico_ip4 inaddr_any = {
    0
};

/* struct containing status of a query */
struct pico_mdns_cookie {
    struct pico_dns_query *q;           /* pointer to query */
    unsigned int count;                 /* number of packets to send */
    unsigned int probe;                 /* indicator for probing */
    void (*callback)(char *, void *);
    void *arg;
    struct pico_timer *timer;
};

/* TODO rework similar to cookie */
struct pico_mdns_cache_rr {
    char *url;
    struct pico_dns_answer_suffix *suf;
    char *rdata;
    struct pico_timer *timer;
};

/* Global socket and port for all mdns communication */
static struct pico_socket *mdns_sock = NULL;
static uint16_t mdns_port = 5353u;

/* only one hostname can be claimed at the time */
static char *mdns_global_host;

static int mdns_cache_cmp(void *ka, void *kb)
{
    struct pico_mdns_cache_rr *a = ka, *b = kb;
    uint32_t ha = 0, hb = 0;

    /* Cache is sorted by qtype, name */
    if(a->suf->qtype < b->suf->qtype)
        return -1;
    if(b->suf->qtype < a->suf->qtype)
        return 1;

    ha = pico_hash(a->url, (uint32_t)strlen(a->url));
    hb = pico_hash(b->url, (uint32_t)strlen(b->url));

    if(ha < hb)
        return -1;
    if(hb < ha)
        return 1;

    return 0;
}

/* Function for comparing two queries in a tree */
static int mdns_cmp(void *ka, void *kb)
{
    struct pico_mdns_cookie *a = ka, *b = kb;
    uint32_t ha = 0, hb = 0;

    /* Cookie is sorted by qtype, name */
    if(a->q->qtype < b->q->qtype)
        return -1;
    if(b->q->qtype < a->q->qtype)
        return 1;

    ha = pico_hash(a->q->qname, (uint32_t)a->q->qnlen);
    hb = pico_hash(b->q->qname, (uint32_t)b->q->qnlen);

    if(ha < hb)
        return -1;
    if(hb < ha)
        return 1;

    return 0;
}

/* cache records for the mDNS hosts in the network */
PICO_TREE_DECLARE(CacheTable, mdns_cache_cmp);

/* tree containing queries */
PICO_TREE_DECLARE(QTable, mdns_cmp);

/* sends an mdns packet on the global socket*/
static int pico_mdns_send(char *packet, uint32_t plen)
{
    struct pico_ip4 dst;
    pico_string_to_ipv4(PICO_MDNS_DEST_ADDR4, &dst.addr);
    /* TODO pico ipv6 support send to ipv6 multicast addr */
    return pico_socket_sendto(mdns_sock, packet, (int)plen, &dst, short_be(mdns_port));
}

static int pico_mdns_cache_del_rr(char *url, uint16_t qtype, char *rdata)
{
    struct pico_mdns_cache_rr test, *found = NULL;

    test.suf = PICO_ZALLOC(sizeof(struct pico_dns_answer_suffix));
    if(!test.suf)
        return -1;

    test.url = url;
    test.suf->qclass = PICO_DNS_CLASS_IN; /* We only support IN */
    test.suf->qtype = qtype;
    test.rdata = rdata;

    found = pico_tree_findKey(&CacheTable, &test);
    PICO_FREE(test.suf);

    if(!found) {
        mdns_dbg("Couldn't find cache RR to delete\n");
        return -1;
    }

    mdns_dbg("Removing RR: qtype '%d' url '%s'\n", qtype, url);

    pico_tree_delete(&CacheTable, found);
    PICO_FREE(found->url);
    PICO_FREE(found->suf);
    PICO_FREE(found->rdata);
    PICO_FREE(found);
    return 0;
}

/* delete a cookie from the tree based on qtype and qname */
static int pico_mdns_del_cookie(char *qname, uint16_t qtype)
{
    struct pico_mdns_cookie test, *found = NULL;
    struct pico_dns_query *q = NULL;

    if(!qname)
        return -1;

    q = PICO_ZALLOC(sizeof(struct pico_dns_query));
    if(!q)
        return -1;
    q->qname = qname;
    q->qnlen = (uint16_t)(strlen(qname)+1);
    q->qtype = qtype;

    test.q = q;

    found = pico_tree_findKey(&QTable, &test);
    PICO_FREE(q);

    if (!found) {
        mdns_dbg("Could not find cookie '%s' to delete\n", q->qname);
        return -1;
    }

    pico_tree_delete(&QTable, found);
    PICO_FREE(found->q);
    PICO_FREE(found);

    return 0;
}

static void pico_mdns_cache_tick(pico_time now, void *_arg)
{
    struct pico_mdns_cache_rr *rr = (struct pico_mdns_cache_rr *)_arg;
    IGNORE_PARAMETER(now);

    rr->suf->ttl--;
    mdns_dbg("TTL UPDATE: '%s' - qtype: %d - TTL: %d\n", rr->url, rr->suf->qtype, rr->suf->ttl);
    if(rr->suf->ttl < 1) {
        pico_mdns_cache_del_rr(rr->url, rr->suf->qtype, rr->rdata);
    }
    else
        rr->timer = pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_cache_tick, rr);

    /* TODO continuous querying: cache refresh at 80 or 85/90/95/100 percent + 2% rnd */
}

static void pico_mdns_timeout(pico_time now, void *_arg)
{
    struct pico_mdns_cookie *ck = (struct pico_mdns_cookie *)_arg;
    IGNORE_PARAMETER(now);

    if(ck->callback)
        ck->callback(NULL, ck->arg);

    pico_mdns_del_cookie(ck->q->qname, ck->q->qtype);
}

/* populate and add cookie to the tree */
static  int pico_mdns_add_cookie(struct pico_dns_query *q, unsigned int probe, void (*callback)(char *str, void *arg), void *arg)
{
    struct pico_mdns_cookie *ck = NULL, *found = NULL;

    ck = PICO_ZALLOC(sizeof(struct pico_mdns_cookie));
    if (!ck)
        return -1;

    ck->q = q;
    ck->count = 3;
    ck->probe = probe;
    ck->callback = callback;
    ck->arg = arg;

    found = pico_tree_insert(&QTable, ck);
    /* cookie already in tree */
    if (found) {
        pico_err = PICO_ERR_EAGAIN;
        PICO_FREE(ck->q);
        PICO_FREE(ck);
        return -1;
    }

    mdns_dbg("Cookie for '%s' added to QTable\n", ck->q->qname);

    if(probe == 0)
        ck->timer = pico_timer_add(PICO_MDNS_QUERY_TIMEOUT, pico_mdns_timeout, ck);
    return 0;
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

/* Look for a RR in cache matching hostname and qtype */
static struct pico_mdns_cache_rr *pico_mdns_cache_find_rr(const char *url, uint16_t qtype)
{
    struct pico_mdns_cache_rr *rr = NULL;
    struct pico_dns_answer_suffix *suf = NULL;
    struct pico_mdns_cache_rr test;
    char temp[256] = { 0 };

    suf = PICO_ZALLOC(sizeof(struct pico_dns_answer_suffix));
    if(!suf)
        return NULL;
    test.suf = suf;
    suf->qtype = qtype;

    strcpy(temp+1, url);
    pico_to_lowercase(temp);
    test.url = temp;

    mdns_dbg("Looking for '%s' with qtype '%d' in cache\n", url, qtype);

    rr = pico_tree_findKey(&CacheTable, &test);
    PICO_FREE(suf);
    return rr;
}

static int pico_mdns_cache_add_rr(char *url, struct pico_dns_answer_suffix *suf, char *rdata)
{
    struct pico_mdns_cache_rr *rr = NULL, *found = NULL;
    struct pico_dns_answer_suffix *rr_suf = NULL;
    char *rr_url = NULL;
    char *rr_rdata = NULL;

    if(!url || !suf || !rdata)
      return -1;

    /* Don't cache PTR answers */
    if(short_be(suf->qtype) == PICO_DNS_TYPE_PTR ) {
        mdns_dbg("Not caching PTR answer\n");
        return 0;
    }

    rr = PICO_ZALLOC(sizeof(struct pico_mdns_cache_rr));
    rr_suf = PICO_ZALLOC(sizeof(struct pico_dns_answer_suffix));
    rr_url = PICO_ZALLOC(strlen(url)+1);
    rr_rdata = PICO_ZALLOC(short_be(suf->rdlength));

    if(!rr || !rr_suf || !rr_url || !rr_rdata) {
        PICO_FREE(rr);
        PICO_FREE(rr_suf);
        PICO_FREE(rr_url);
        PICO_FREE(rr_rdata);
        return -1;
    }

    memcpy(rr_url+1, url, strlen(url));
    rr->url = rr_url;
    memcpy(rr_suf, suf, sizeof(struct pico_dns_answer_suffix));
    rr->suf = rr_suf;
    rr->suf->qtype = short_be(rr->suf->qtype);
    rr->suf->qclass = short_be(rr->suf->qclass);
    rr->suf->ttl = long_be(suf->ttl);
    rr->suf->rdlength = short_be(suf->rdlength);
    memcpy(rr_rdata, rdata, rr->suf->rdlength);
    rr->rdata = rr_rdata;

    found = pico_mdns_cache_find_rr(url, rr->suf->qtype);
    if(found) {
        if(rr->suf->ttl > 0) {
            mdns_dbg("RR in cache, updating TTL (was %ds now %ds)\n", found->suf->ttl, rr->suf->ttl);
            found->suf->ttl = rr->suf->ttl;
        }
        else {
            mdns_dbg("RR scheduled for deletion\n");
            found->suf->ttl = 1;  /* TTL 0 means delete from cache but wait 1s */
        }
    }
    else {
        if(rr->suf->ttl > 0) {
            pico_tree_insert(&CacheTable, rr);
            mdns_dbg("RR cached. Starting TTL counter, TICK TACK TICK TACK..\n");
            rr->timer = pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_cache_tick, rr);
            return 0;
        }
        else {
            mdns_dbg("RR not in cache but TTL = 0\n");
        }
    }
    PICO_FREE(rr->suf);
    PICO_FREE(rr->url);
    PICO_FREE(rr->rdata);
    PICO_FREE(rr);
    return 0;
}

/* look for a cookie in the tree */
static struct pico_mdns_cookie *pico_mdns_find_cookie(const char *qname, uint16_t qtype)
{
    struct pico_mdns_cookie test, *found = NULL;
    struct pico_dns_query *q = NULL;

    if(!qname)
        return NULL;

    q = PICO_ZALLOC(sizeof(struct pico_dns_query));
    if(!q)
        return NULL;
    q->qname = strdup(qname);
    q->qnlen = (uint16_t)(strlen(qname)+1);
    q->qtype = qtype;

    test.q = q;
    found = pico_tree_findKey(&QTable, &test);
    PICO_FREE(q);
    return found;
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

/* reply on a single query */
static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer, char *name)
{
    char *dns_packet = NULL;
    uint32_t plen = 0;
    struct pico_dns_header *header = NULL;
    struct pico_dns_answer *answer = NULL;
    union pico_address *local_addr = NULL;
    uint16_t datalen = 0;
    char *dns_name = NULL;

    local_addr = (union pico_address *) pico_ipv4_source_find(&peer);
    if (!local_addr) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        return -1;
    }

    /* TODO might have multiple answers if IPv4 and IPv6 address is requested with ANY */
    header = pico_dns_create_header(PICO_MDNS_PACKET_ID, 0, 1); /* 1 answer */

    if(qtype == PICO_DNS_TYPE_A || qtype == PICO_DNS_TYPE_ANY) {
        datalen = mdns_get_len(PICO_DNS_TYPE_A, (char *)&mdns_sock->local_addr);
        answer = pico_dns_create_answer(mdns_global_host, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN, PICO_MDNS_DEFAULT_TTL, (char *)local_addr, datalen);
    }

#ifdef PICO_SUPPORT_IPV6
    if(qtype == PICO_DNS_TYPE_AAAA || qtype == PICO_DNS_TYPE_ANY) {
        struct pico_ip6 *ip6 = pico_get_ip6_from_ip4(&local_addr->ip4);
        datalen = mdns_get_len(PICO_DNS_TYPE_AAAA, (char *)ip6);
        answer = pico_dns_create_answer(mdns_global_host, PICO_DNS_TYPE_AAAA, PICO_DNS_CLASS_IN, PICO_MDNS_DEFAULT_TTL, (char *)ip6, datalen);
    }

#endif
    /* reply to PTR records */
    if(qtype == PICO_DNS_TYPE_PTR) {
        dns_name = pico_dns_name_to_dns_notation(name);
        answer = pico_dns_create_answer(dns_name, qtype, PICO_DNS_CLASS_IN, PICO_MDNS_DEFAULT_TTL, mdns_global_host, (uint16_t)(strlen(mdns_global_host)+1));
        PICO_FREE(dns_name);
    }
    if(!answer)
        return -1;

    dns_packet = pico_dns_create_packet(&plen, header, NULL, answer);

    mdns_dbg("Replying for '%s'\n", name);
    if(pico_mdns_send(dns_packet, plen) != (int)plen) {
        mdns_dbg("Send error occurred!\n");
        return -1;
    }

    return 0;
}

static void pico_mdns_flip_class_bit(uint16_t *class)
{
 /* for queries sets/clears unicast response bit
  * for answers sets/clears cache flush bit */
    *class ^= 1 << PICO_MDNS_QU_CACHE_BIT;
}

/* Check if the url is ours */
static int pico_check_query_name(char *url)
{
    char addr[29] = { 0 };
    char *inaddr = NULL;
    char *dns_url = NULL;
    dns_url = pico_dns_name_to_dns_notation(url);
    if(!dns_url)
        return 0;

    if(strcmp(dns_url, mdns_global_host) == 0) {
        PICO_FREE(dns_url);
        return 1;
    }

    pico_ipv4_to_string(addr, mdns_sock->local_addr.ip4.addr);
    inaddr = pico_dns_addr_to_inaddr(addr, PICO_PROTO_IPV4);
    if(strcmp(url, inaddr) == 0) {
        PICO_FREE(dns_url);
        PICO_FREE(inaddr);
        return 1;
    }

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
        ck = pico_mdns_find_cookie(name, suf->qtype);
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
    char *dns_url = NULL;

    /* remove cache flush bit if set */
    suf->qclass &= short_be((uint16_t) ~PICO_MDNS_CACHE_FLUSH_BIT);

    mdns_dbg("Answer for record %s was received:\n", url);
    mdns_dbg("type: %u, class: %u, ttl: %lu, rdlen: %u\n", short_be(suf->qtype),
             short_be(suf->qclass), (unsigned long)long_be(suf->ttl), short_be(suf->rdlength));

    pico_mdns_cache_add_rr(url, suf, data);

    dns_url = pico_dns_name_to_dns_notation(url);

    /* Check in the query tree whether a request was sent */
    ck = pico_mdns_find_cookie(dns_url, suf->qtype);
    if(!ck) {
        return 0;
    }

    mdns_dbg("Found a corresponding cookie!\n");
    /* if we are probing, set probe to zero so the probe timer stops the next time it goes off */
    if (ck->probe) {
        mdns_dbg("Probe set to zero\n");
        ck->probe = 0;
        return 0;
    }

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
        pico_dns_notation_to_name(data);
        ck->callback(data + 1, ck->arg);    /* +1 to discard the beginning dot */
    }
    else {
        mdns_dbg("Unrecognised record type\n");
        ck->callback(NULL, ck->arg);
    }
    pico_timer_cancel(ck->timer);
    pico_mdns_del_cookie(dns_url, suf->qtype);
    PICO_FREE(dns_url);

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

    if(qcount == 0 && acount == 0) {
        mdns_dbg("Query and answer count is 0!\n");
        return -1;
    }

    /* handle queries */
    for(i = 0; i < qcount; i++) {
        qsuf = (struct pico_dns_query_suffix*) (ptr + pico_mdns_namelen_comp(ptr) + 1);
        pico_dns_notation_to_name(ptr);
        if (!ptr)
            return -1;

        pico_mdns_handle_query(ptr + 1, qsuf, peer);
        ptr = (char *)qsuf + sizeof(struct pico_dns_query_suffix);
        if(ptr - (char *)header > buflen) {
            mdns_dbg("buffer is too short! ptr offset=%d buflen=%d\n", ptr - (char*)header, buflen);
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
            mdns_dbg("buffer is too short! ptr offset=%d buflen=%d\n", ptr - (char*)header, buflen);
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
    struct pico_dns_header *hdr = NULL;
    struct pico_dns_answer *answer = NULL;
    uint32_t ttl = PICO_MDNS_DEFAULT_TTL;
    uint16_t datalen = 0;
    char *mdns_packet = NULL;
    uint32_t plen = 0;
    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(arg);

    if(!mdns_global_host)
        return;
    datalen = mdns_get_len(PICO_DNS_TYPE_A, (char *)&mdns_sock->local_addr);
    hdr = pico_dns_create_header(PICO_MDNS_PACKET_ID, 0, 1); /* 0 questions, 1 answer */
    answer = pico_dns_create_answer(mdns_global_host, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN, ttl, (char *)&mdns_sock->local_addr, datalen);
    mdns_packet = pico_dns_create_packet(&plen, hdr, NULL, answer);

    if(!mdns_packet)
        return;
    if(pico_mdns_send(mdns_packet, plen) != (int)plen) {
        mdns_dbg("Send error!\n");
        return;
    }
}

/* announce the local hostname to the network */
static int pico_mdns_announce(void)
{
    struct pico_dns_header *hdr = NULL;
    struct pico_dns_answer *answer = NULL;
    uint32_t ttl = PICO_MDNS_DEFAULT_TTL;
    uint16_t datalen = 0;
    char *mdns_packet = NULL;
    uint32_t plen = 0;

    if(!mdns_global_host)
        return -1;

    datalen = mdns_get_len(PICO_DNS_TYPE_A, (char *)&mdns_sock->local_addr);
    hdr = pico_dns_create_header(PICO_MDNS_PACKET_ID, 0, 1); /* 0 questions, 1 answer */
    answer = pico_dns_create_answer(mdns_global_host, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN, ttl, (char *)&mdns_sock->local_addr, datalen);
    mdns_packet = pico_dns_create_packet(&plen, hdr, NULL, answer);

    if(!mdns_packet)
        return -1;
    if(pico_mdns_send(mdns_packet, plen) != (int)plen) {
        mdns_dbg("Send error!\n");
        return -1;
    }

    pico_timer_add(1000, pico_mdns_announce_timer, NULL);
    return 0;
}

/* callback function for the probe timer */
static void pico_mdns_probe_timer(pico_time now, void *arg)
{
    struct pico_dns_query *q = (struct pico_dns_query *)arg;
    struct pico_mdns_cookie *ck;
    char ok[] = "OK";

    char *mdns_packet = NULL;
    uint32_t plen = 0;
    struct pico_dns_header *hdr = NULL;

    IGNORE_PARAMETER(now);

    if(!arg)
        return;

    ck = pico_mdns_find_cookie(q->qname, q->qtype);

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
        mdns_global_host = q->qname;
        mdns_dbg("Name claimed, announcing %s\n", mdns_global_host);
        pico_mdns_announce();
        ck->callback(ok, ck->arg);
        pico_mdns_del_cookie(q->qname, q->qtype);
        return;
    }

    hdr = pico_dns_create_header(PICO_MDNS_PACKET_ID, 1, 0); /* 1 question, 0 answers */
    mdns_packet = pico_dns_create_packet(&plen, hdr, ck->q, NULL);

    if(!mdns_packet) {
        mdns_dbg("Packet error!\n");
        PICO_FREE(arg);
        ck->callback(NULL, ck->arg);
        return;
    }

    if(pico_mdns_send(mdns_packet, plen) != (int)plen) {
        mdns_dbg("Send error occurred!\n");
        PICO_FREE(arg);
        ck->callback(NULL, ck->arg);
        return;
    }

    ck->count--;
    pico_timer_add(250, pico_mdns_probe_timer, q);
}

/* checks whether the given name is in use */
static int pico_mdns_probe(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg)
{
    struct pico_dns_query *query = NULL;
    char *dns_url = NULL;
    uint16_t qclass = PICO_DNS_CLASS_IN;

    dns_url = pico_dns_name_to_dns_notation(hostname);
    pico_mdns_flip_class_bit(&qclass); /* set Unicast Reponse bit "QU" */

    query = pico_dns_create_query(dns_url, PICO_DNS_TYPE_ANY, qclass);
    PICO_FREE(dns_url);

    if(pico_mdns_add_cookie(query, PICO_MDNS_PROBE, cb_initialised, arg) == -1)
        return -1;

    pico_timer_add(pico_rand() % 250, pico_mdns_probe_timer, query);

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

    if(pico_string_to_ipv4(PICO_MDNS_DEST_ADDR4, &mreq.mcast_group_addr.addr) != 0) {
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

int pico_mdns_flush_cache(void)
{
    struct pico_mdns_cache_rr *rr = NULL;
    struct pico_tree_node *index = NULL;

    mdns_dbg("Flushing mDNS RR cache\n");
    pico_tree_foreach(index, &CacheTable) {
        rr = index->keyValue;
        mdns_dbg("Deleting '%s' (%d)\n", rr->url, rr->suf->qtype);
        pico_tree_delete(&CacheTable, rr);
        pico_timer_cancel(rr->timer);
        PICO_FREE(rr->url);
        PICO_FREE(rr->suf);
        PICO_FREE(rr->rdata);
        PICO_FREE(rr);
    }
    return 0;
}

static int pico_mdns_getaddr_generic(const char *url, void (*callback)(char *ip, void *arg), void *arg, uint16_t proto)
{
    char *mdns_packet = NULL;
    uint32_t plen = 0;
    struct pico_dns_header *hdr = NULL;
    struct pico_dns_query *query = NULL;
    char *dns_url = NULL;

    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if(!mdns_sock) {
        mdns_dbg("Mdns socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }

    dns_url = pico_dns_name_to_dns_notation(url);

    hdr = pico_dns_create_header(PICO_MDNS_PACKET_ID, 1, 0); /* 1 question, 0 answers */
#ifdef PICO_SUPPORT_IPV6
    if(proto == PICO_PROTO_IPV6)
        query = pico_dns_create_query(dns_url, PICO_DNS_TYPE_AAAA, PICO_DNS_CLASS_IN);
    else
#endif
        query = pico_dns_create_query(dns_url, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN);

    mdns_packet = pico_dns_create_packet(&plen, hdr, query, NULL);

    PICO_FREE(dns_url);

    if(!mdns_packet)
        return -1;
    if(pico_mdns_send(mdns_packet, plen) != (int)plen) {
        mdns_dbg("Send error!\n");
        return -1;
    }
    PICO_FREE(mdns_packet);

    if(pico_mdns_add_cookie(query, PICO_MDNS_NO_PROBE, callback, arg) == -1)
        return -1;

    return 0;
}

static int pico_mdns_getname_generic(const char *ip, void (*callback)(char *url, void *arg), void *arg, uint16_t proto)
{
    char *mdns_packet = NULL;
    uint32_t plen = 0;
    struct pico_dns_header *hdr = NULL;
    struct pico_dns_query *query = NULL;
    char *dns_url = NULL;
    char *inaddr = NULL;

    if (!ip) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if(!mdns_sock) {
        mdns_dbg("Mdns socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }

    inaddr = pico_dns_addr_to_inaddr(ip, proto);
    dns_url = pico_dns_name_to_dns_notation(inaddr);
    PICO_FREE(inaddr);

    hdr = pico_dns_create_header(PICO_MDNS_PACKET_ID, 1, 0); /* 1 question, 0 answers */
    query = pico_dns_create_query(dns_url, PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN);
    mdns_packet = pico_dns_create_packet(&plen, hdr, query, NULL);

    PICO_FREE(dns_url);

    if(!mdns_packet)
        return -1;
    if(pico_mdns_send(mdns_packet, plen) != (int)plen) {
        mdns_dbg("Send error!\n");
        return -1;
    }

    if(pico_mdns_add_cookie(query, PICO_MDNS_NO_PROBE, callback, arg) == -1)
        return -1;

    return 0;
}

int pico_mdns_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg)
{
    struct pico_mdns_cache_rr *rr = NULL;
    char addr[46];
    rr = pico_mdns_cache_find_rr(url, PICO_DNS_TYPE_A);
    
    if(rr && rr->rdata) {
        pico_ipv4_to_string(addr, long_from(rr->rdata));
        mdns_dbg("Cache hit! Found A record for '%s' with addr '%s'\n", url, addr);
        callback(addr, arg);
        return 0;
    }
    else {
        mdns_dbg("Cache miss for A record - url '%s'\n", url);
        return pico_mdns_getaddr_generic(url, callback, arg, PICO_PROTO_IPV4);
    }
}

int pico_mdns_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg)
{
    return pico_mdns_getname_generic(ip, callback, arg, PICO_PROTO_IPV4);
}

#ifdef PICO_SUPPORT_IPV6
int pico_mdns_getaddr6(const char *url, void (*callback)(char *ip, void *arg), void *arg)
{
    struct pico_mdns_cache_rr *rr = NULL;
    char addr[46];
    rr = pico_mdns_cache_find_rr(url, PICO_DNS_TYPE_AAAA);

    if(rr && rr->rdata) {
        pico_ipv6_to_string(addr, (uint8_t *)rr->rdata);
        mdns_dbg("Cache hit! Found AAAA record for '%s' with addr '%s'\n", url, addr);
        callback(addr, arg);
        return 0;
    }
    else {
        mdns_dbg("Cache miss for AAAA record - url '%s'\n", url);
        return pico_mdns_getaddr_generic(url, callback, arg, PICO_PROTO_IPV6);
    }
}

int pico_mdns_getname6(const char *ip, void (*callback)(char *url, void *arg), void *arg)
{
    return pico_mdns_getname_generic(ip, callback, arg, PICO_PROTO_IPV6);
}
#endif

#endif /* PICO_SUPPORT_MDNS */
