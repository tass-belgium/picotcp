#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"
#include "modules/pico_mdns.c"
#include "check.h"

void callback(char *str, void *arg)
{
    (void) str;
    (void) arg;
}
START_TEST(tc_mdns_cache_cmp)
{
    struct pico_mdns_cache_rr ka;
    struct pico_dns_answer_suffix sa;
    struct pico_mdns_cache_rr kb;
    struct pico_dns_answer_suffix sb;

    char url1[] = "test_1";
    char url2[] = "test_2";

    ka.url = url1;
    sa.qtype = PICO_DNS_TYPE_A;
    ka.suf = &sa;
    kb.url = url2;
    sb.qtype = PICO_DNS_TYPE_A;
    kb.suf = &sb;
    fail_unless(mdns_cache_cmp(&ka, &kb) != 0, "RR cmp returned equal!");

    ka.url = url1;
    kb.url = url1;
    fail_unless(mdns_cache_cmp(&ka, &kb) == 0, "RR cmp returned different!");
}
END_TEST
START_TEST(tc_mdns_cmp)
{
    struct pico_mdns_cookie ka;
    struct pico_mdns_cookie kb;

    char url1[] = "test_1";
    char url2[] = "test_2";

    ka.url = url1;
    ka.qtype = PICO_DNS_TYPE_A;
    kb.url = url2;
    kb.qtype = PICO_DNS_TYPE_A;
    fail_unless(mdns_cmp(&ka, &kb) != 0, "cmp returned equal!");

    ka.url = url1;
    kb.url = url1;
    fail_unless(mdns_cmp(&ka, &kb) == 0, "cmp returned different!");
}
END_TEST
START_TEST(tc_pico_mdns_send)
{
    struct pico_dns_header hdr = {
        0
    };
    int len = 0;
    int sentlen = 0;
    sentlen = pico_mdns_send(&hdr, (unsigned int)len);
    fail_unless(sentlen == len, "Sent %d iso expected %d bytes!\n", sentlen, len);
}
END_TEST
START_TEST(tc_pico_mdns_cache_del_rr)
{
    char url[] = "delrr.local";
    char *addr = NULL;
    uint16_t qtype = PICO_DNS_TYPE_A;
    struct pico_dns_answer_suffix suf = {
        .qtype = short_be(qtype),
        .ttl = long_be(100)
    };
    char rdata[] = "somedata";

    pico_stack_init();
    fail_unless(pico_mdns_cache_del_rr(url, qtype, rdata) == -1, "Deleted a nonexisting RR from cache!\n");
    fail_unless(pico_mdns_cache_add_rr(url, &suf, rdata) == 0, "Failed to add RR to cache\n");

    addr = PICO_ZALLOC(strlen(url)+1);
    memcpy(addr+1, url, strlen(url));
    pico_dns_name_to_dns_notation(addr);
    fail_unless(pico_mdns_cache_del_rr(addr, qtype, rdata) == 0, "Unable to delete RR from cache!\n");
    PICO_FREE(addr);
}
END_TEST
START_TEST(tc_pico_mdns_add_cookie)
{
    /* TODO: test this: static struct pico_mdns_cookie *pico_mdns_add_cookie(struct pico_dns_header *hdr, uint16_t len, struct pico_dns_query_suffix *suffix, unsigned int probe, void (*callback)(char *str, void *arg), void *arg) */
    /*char url[] = "addck.local";
    uint16_t qtype = PICO_DNS_TYPE_A;
    uint16_t len = 0;
    struct pico_dns_query_suffix suf = {
        .qtype = short_be(qtype)
    };
    unsigned int probe = 0;
    void *arg = NULL;
    struct pico_dns_header *hdr = PICO_ZALLOC(sizeof(struct pico_dns_header)+strlen(url)+1);
    char *addr = (char *)hdr + sizeof(struct pico_dns_header);
    pico_mdns_populate_query_domain(url, addr, NULL, 0, 0, PICO_PROTO_IPV4, 0);
    pico_dns_client_query_domain(addr);

    printf("First char %02x\n", addr[0]);

    pico_stack_init();
    fail_unless(pico_mdns_add_cookie(hdr, len, &suf, probe, callback, arg) != NULL, "Failed adding cookie!\n");
    fail_unless(pico_mdns_find_cookie(url, qtype) != NULL, "Cookie not found in table!\n");
    PICO_FREE(hdr);*/
}
END_TEST
START_TEST(tc_pico_mdns_fill_header)
{
    /* TODO: test this: static void pico_mdns_fill_header(struct pico_dns_header *hdr, uint16_t qdcount, uint16_t ancount) */
    struct pico_dns_header hdr = {
        0
    };
    uint16_t qdcount = 0;
    uint16_t ancount = 0;
    pico_mdns_fill_header(&hdr, qdcount, ancount);
}
END_TEST
START_TEST(tc_pico_mdns_create_answer)
{
    char url[] = "cr-ans.local";
    unsigned int len = 0;
    uint16_t qtype = PICO_DNS_TYPE_A;
    char rdata[] = "somedata";

    fail_unless(pico_mdns_create_answer(url, &len, qtype, rdata) != NULL, "Header returned is NULL!\n");
    qtype = 0;
    fail_unless(pico_mdns_create_answer(url, &len, qtype, rdata) == NULL, "Header returned is invalid!\n");
}
END_TEST
START_TEST(tc_pico_mdns_create_query)
{
    /* TODO: test this: static struct pico_dns_header *pico_mdns_create_query(const char *url, uint16_t *len, uint16_t proto, unsigned int probe, unsigned int inverse, void (*callback)(char *str, void *arg), void *arg) */
    char url[256] = {
        0
    };
    uint16_t len = 0;
    uint16_t proto = 0xFFFF;
    unsigned int probe = 0;
    unsigned int inverse = 0;
    void *arg = NULL;
    pico_stack_init();

    fail_if(pico_mdns_create_query(NULL, &len, proto, probe, inverse, callback, arg) != NULL);
    fail_if(pico_err != PICO_ERR_EINVAL);
    fail_if(pico_mdns_create_query(url, &len, proto, probe, inverse, callback, arg) != NULL);
    fail_if(pico_err != PICO_ERR_EINVAL);
    proto = PICO_PROTO_IPV4;
    fail_if(pico_mdns_create_query(url, &len, proto, probe, inverse, NULL, arg) != NULL);
    fail_if(pico_err != PICO_ERR_EINVAL);
    fail_if(pico_mdns_create_query(url, NULL, proto, probe, inverse, callback, arg) != NULL);
    fail_if(pico_err != PICO_ERR_EINVAL);

#ifdef FAULTY
    pico_set_mm_failure(1);
    fail_if(pico_mdns_create_query(url, &len, proto, probe, inverse, callback, arg) != NULL);
    fail_if(pico_err != PICO_ERR_ENOMEM);
#endif

    fail_if(pico_mdns_create_query(url, &len, proto, probe, inverse, callback, arg) == NULL);
}
END_TEST
START_TEST(tc_pico_mdns_del_cookie)
{
    char url[256] = {
        0
    };
    uint16_t qtype = PICO_DNS_TYPE_A;

    fail_unless(pico_mdns_del_cookie(url, qtype) == -1, "Deleted nonexisting cookie!\n");
    /* TODO
     * Add cookie
     * Try to delete cookie
     * Look for cookie & see if it's deleted */
}
END_TEST
START_TEST(tc_pico_mdns_cache_find_rr)
{
    char url[] = "findrr.local";
    uint16_t qtype = PICO_DNS_TYPE_A;
    struct pico_mdns_cache_rr *rr = NULL;
    struct pico_dns_answer_suffix suf = {
        .qtype = short_be(qtype),
        .ttl = long_be(100)
    };
    char rdata[] = "somedata";

    pico_stack_init();
    rr = pico_mdns_cache_find_rr(url, qtype);
    fail_unless(rr == NULL, "Found nonexistent RR in cache!\n");

    rr = NULL;
    pico_mdns_cache_add_rr(url, &suf, rdata);
    rr = pico_mdns_cache_find_rr(url, qtype);
    fail_unless(rr != NULL, "RR not found in cache!\n");
}
END_TEST
START_TEST(tc_pico_mdns_cache_add_rr)
{
    char url[] = "addrr.local";
    uint16_t qtype = PICO_DNS_TYPE_A;
    struct pico_dns_answer_suffix suf = {
        .qtype = short_be(qtype),
        .ttl = long_be(100)
    };
    char rdata[] = "somedata";

    pico_stack_init();
    fail_unless(pico_mdns_cache_add_rr(url, &suf, rdata) == 0, "Failed to add RR to cache\n");
}
END_TEST
START_TEST(tc_pico_mdns_flush_cache)
{
    char url[] = "flush.local";
    char url2[] = "flush2.local";
    uint16_t qtype = PICO_DNS_TYPE_A;
    struct pico_mdns_cache_rr *rr = NULL;
    struct pico_dns_answer_suffix suf = {
        .qtype = short_be(qtype),
        .ttl = long_be(100)
    };
    char rdata[] = "somedata";

    pico_stack_init();
    /* Add RR and find it in the cache, then flush cache and look for it again */
    fail_unless(pico_mdns_cache_add_rr(url, &suf, rdata) == 0, "Failed to add RR to cache\n");
    fail_unless(pico_mdns_cache_add_rr(url2, &suf, rdata) == 0, "Failed to add RR to cache\n");

    rr = pico_mdns_cache_find_rr(url, qtype);
    fail_unless(rr != NULL, "RR not found in cache!\n");
    fail_unless(pico_mdns_flush_cache() == 0, "RR cache flushing failure!\n");

    rr = NULL;
    rr = pico_mdns_cache_find_rr(url, qtype);
    fail_unless(rr == NULL, "RR found in cache after flush!\n");

    rr = NULL;
    rr = pico_mdns_cache_find_rr(url2, qtype);
    fail_unless(rr == NULL, "RR found in cache after flush!\n");
}
END_TEST
START_TEST(tc_pico_mdns_find_cookie)
{
    /* TODO Needs reworking! Cfr add_cookie */
    struct pico_mdns_cookie *ck = NULL;
    char *addr = NULL;
    char url[] = "findck.local";
    uint16_t qtype = PICO_DNS_TYPE_A;
    uint16_t len = 0;
    struct pico_dns_query_suffix suf = {
        .qtype = short_be(qtype)
    };
    unsigned int probe = 0;
    void *arg = NULL;
    struct pico_dns_header *hdr = PICO_ZALLOC(sizeof(struct pico_dns_header)+strlen(url)+1);
    addr = (char *)hdr + sizeof(struct pico_dns_header);
    memcpy(addr+1, url, strlen(url));
    pico_dns_name_to_dns_notation(addr);

    pico_stack_init();
    ck = pico_mdns_find_cookie(url, qtype);
    fail_unless(ck == NULL, "Found nonexisting cookie in table!\n");

    ck = NULL;
    fail_unless(pico_mdns_add_cookie(hdr, len, &suf, probe, callback, arg) != NULL, "Failed adding cookie!\n");
    ck = pico_mdns_find_cookie(url, qtype);
    fail_unless(ck != NULL, "Cookie not found in table!\n");
    PICO_FREE(hdr);
}
END_TEST
START_TEST(tc_pico_get_ip6_from_ip4)
{
    /* TODO: test this: static struct pico_ip6 *pico_get_ip6_from_ip4(struct pico_ip4 *ipv4_addr) */
    struct pico_ip4 *ipv4_addr = NULL;

    fail_unless(pico_get_ip6_from_ip4(ipv4_addr) == NULL, "Got an invalid IP!\n");
}
END_TEST
START_TEST(tc_pico_mdns_reply_query)
{
    /* TODO: test this: static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer) */
    uint16_t qtype = 0;
    struct pico_ip4 peer = {
        0
    };
    char *name = NULL;

    fail_unless(pico_mdns_reply_query(qtype, peer, name) == -1, "Replied to query with invalid arg \n");
}
END_TEST
START_TEST(tc_pico_mdns_handle_query)
{
    /* TODO: test this: static int pico_mdns_handle_query(char *url, struct pico_dns_query_suffix *suf, struct pico_ip4 peer) */
    char url[256] = {
        0
    };
    struct pico_dns_query_suffix suf = {
        0
    };
    struct pico_ip4 peer = {
        0
    };

    pico_mdns_handle_query(url, &suf, peer);
}
END_TEST
START_TEST(tc_pico_mdns_handle_answer)
{
    /* TODO: test this: static int pico_mdns_handle_answer(char *url, struct pico_dns_answer_suffix *suf, char *data) */
    char url[] = "han-ans.local";
    struct pico_dns_answer_suffix suf = {
        0
    };
    char data[] = "somedata";
    pico_mdns_handle_answer(url, &suf, data);
}
END_TEST
START_TEST(tc_pico_mdns_namelen_comp)
{
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    unsigned int ret = 0;

    /* name without compression */
    ret = pico_mdns_namelen_comp(name);
    fail_unless(ret == 12, "Namelength is wrong!\n");

    /* name with compression */
    ret = pico_mdns_namelen_comp(name_comp);
    fail_unless(ret == 13, "Namelength is wrong!\n");
}
END_TEST
START_TEST(tc_pico_mdns_namelen_uncomp)
{
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    char buf[] = "00\5index\0";
    unsigned int ret = 0;

    /* name without compression */
    ret = pico_mdns_namelen_uncomp(name, buf);
    fail_unless(ret == 12, "Namelength is wrong!\n");

    /* name with compression */
    ret = pico_mdns_namelen_uncomp(name_comp, buf);
    fail_unless(ret == 18, "Namelength is wrong!\n");
}
END_TEST
START_TEST(tc_pico_mdns_expand_name_comp)
{
    char name[] = "\3www\4tass\2be\0";
    char buf[] = "00\5index\0";
    char *ret;
    ret = pico_mdns_expand_name_comp(name, buf);
    fail_unless(ret != NULL, "Name ptr returned is NULL");
}
END_TEST
START_TEST(tc_pico_mdns_recv)
{
    /* TODO: test this: static int pico_mdns_recv(void *buf, int buflen, struct pico_ip4 peer) */
    char buf[256] = { 0 };
    int buflen = 0;
    struct pico_ip4 peer = {
        0
    };

    fail_unless(pico_mdns_recv(buf, buflen, peer) == -1, "No error with invalid args!\n");
}
END_TEST
START_TEST(tc_pico_mdns_wakeup)
{
    /* TODO: test this: static void pico_mdns_wakeup(uint16_t ev, struct pico_socket *s) */
    uint16_t ev = 0;
    struct pico_socket *s = NULL;

    pico_mdns_wakeup(ev, s);
}
END_TEST
START_TEST(tc_pico_mdns_announce_timer)
{
    /* TODO: test this: static void pico_mdns_announce_timer(pico_time now, void *arg) */
    pico_time now = 0;
    void *arg = NULL;

    pico_mdns_announce_timer(now, arg);
}
END_TEST
START_TEST(tc_pico_mdns_announce)
{
    /* TODO: test this: static int pico_mdns_announce() */
    pico_mdns_announce();
}
END_TEST
START_TEST(tc_pico_mdns_probe_timer)
{
    /* TODO: test this: static void pico_mdns_probe_timer(pico_time now, void *arg) */
    pico_time now = 0;
    void *arg = NULL;

    pico_mdns_probe_timer(now, arg);
}
END_TEST
START_TEST(tc_pico_mdns_probe)
{
    /* TODO: test this: static int pico_mdns_probe(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg) */
    char hostname[256] = {
        0
    };
    void *arg = NULL;
    pico_stack_init();
    pico_mdns_probe(hostname, callback, arg);
}
END_TEST
START_TEST(tc_pico_mdns_getaddr_generic)
{
    /* TODO: test this: static int pico_mdns_getaddr_generic(const char *url, void (*callback)(char *ip, void *arg), void *arg, uint16_t proto) */
    const char *url = NULL;
    void *arg = NULL;
    uint16_t proto = 0;
    pico_mdns_getaddr_generic(url, callback, arg, proto);
}
END_TEST
START_TEST(tc_pico_mdns_getname_generic)
{
    /* TODO: test this: static int pico_mdns_getname_generic(const char *ip, void (*callback)(char *url, void *arg), void *arg, uint16_t proto) */
    const char *ip = NULL;
    void *arg = NULL;
    uint16_t proto = 0;

    pico_mdns_getname_generic(ip, callback, arg, proto);
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");


    TCase *TCase_mdns_cache_cmp = tcase_create("Unit test for mdns_cache_cmp");
    TCase *TCase_mdns_cmp = tcase_create("Unit test for mdns_cmp");
    TCase *TCase_pico_mdns_send = tcase_create("Unit test for pico_mdns_send");
    TCase *TCase_pico_mdns_cache_del_rr = tcase_create("Unit test for pico_mdns_cache_del_rr");
    TCase *TCase_pico_mdns_add_cookie = tcase_create("Unit test for pico_mdns_add_cookie");
    TCase *TCase_pico_mdns_fill_header = tcase_create("Unit test for pico_mdns_fill_header");
    TCase *TCase_pico_mdns_create_answer = tcase_create("Unit test for pico_mdns_create_answer");
    TCase *TCase_pico_mdns_create_query = tcase_create("Unit test for pico_mdns_create_query");
    TCase *TCase_pico_mdns_del_cookie = tcase_create("Unit test for pico_mdns_del_cookie");
    TCase *TCase_pico_mdns_cache_find_rr = tcase_create("Unit test for pico_mdns_cache_find_rr");
    TCase *TCase_pico_mdns_cache_add_rr = tcase_create("Unit test for pico_mdns_cache_add_rr");
    TCase *TCase_pico_mdns_flush_cache = tcase_create("Unit test for pico_mdns_flush_cache");
    TCase *TCase_pico_mdns_find_cookie = tcase_create("Unit test for pico_mdns_find_cookie");
    TCase *TCase_pico_get_ip6_from_ip4 = tcase_create("Unit test for pico_get_ip6_from_ip4");
    TCase *TCase_pico_mdns_reply_query = tcase_create("Unit test for pico_mdns_reply_query");
    TCase *TCase_pico_mdns_handle_query = tcase_create("Unit test for pico_mdns_handle_query");
    TCase *TCase_pico_mdns_handle_answer = tcase_create("Unit test for pico_mdns_handle_answer");

    TCase *TCase_pico_mdns_namelen_comp = tcase_create("Unit test for pico_mdns_namelen_comp");
    TCase *TCase_pico_mdns_namelen_uncomp = tcase_create("Unit test for pico_mdns_namelen_uncomp");
    TCase *TCase_pico_mdns_expand_name_comp = tcase_create("Unit test for pico_mdns_expand_name_comp");

    TCase *TCase_pico_mdns_recv = tcase_create("Unit test for pico_mdns_recv");
    TCase *TCase_pico_mdns_wakeup = tcase_create("Unit test for pico_mdns_wakeup");
    TCase *TCase_pico_mdns_announce_timer = tcase_create("Unit test for pico_mdns_announce_timer");
    TCase *TCase_pico_mdns_announce = tcase_create("Unit test for pico_mdns_announce");
    TCase *TCase_pico_mdns_probe_timer = tcase_create("Unit test for pico_mdns_probe_timer");
    TCase *TCase_pico_mdns_probe = tcase_create("Unit test for pico_mdns_probe");
    TCase *TCase_pico_mdns_getaddr_generic = tcase_create("Unit test for pico_mdns_getaddr_generic");
    TCase *TCase_pico_mdns_getname_generic = tcase_create("Unit test for pico_mdns_getname_generic");

    tcase_add_test(TCase_mdns_cache_cmp, tc_mdns_cache_cmp);
    suite_add_tcase(s, TCase_mdns_cache_cmp);
    tcase_add_test(TCase_mdns_cmp, tc_mdns_cmp);
    suite_add_tcase(s, TCase_mdns_cmp);
    tcase_add_test(TCase_pico_mdns_send, tc_pico_mdns_send);
    suite_add_tcase(s, TCase_pico_mdns_send);
    tcase_add_test(TCase_pico_mdns_cache_del_rr, tc_pico_mdns_cache_del_rr);
    suite_add_tcase(s, TCase_pico_mdns_cache_del_rr);
    tcase_add_test(TCase_pico_mdns_add_cookie, tc_pico_mdns_add_cookie);
    suite_add_tcase(s, TCase_pico_mdns_add_cookie);
    tcase_add_test(TCase_pico_mdns_fill_header, tc_pico_mdns_fill_header);
    suite_add_tcase(s, TCase_pico_mdns_fill_header);
    tcase_add_test(TCase_pico_mdns_create_answer, tc_pico_mdns_create_answer);
    suite_add_tcase(s, TCase_pico_mdns_create_answer);
    tcase_add_test(TCase_pico_mdns_create_query, tc_pico_mdns_create_query);
    suite_add_tcase(s, TCase_pico_mdns_create_query);
    tcase_add_test(TCase_pico_mdns_del_cookie, tc_pico_mdns_del_cookie);
    suite_add_tcase(s, TCase_pico_mdns_del_cookie);
    tcase_add_test(TCase_pico_mdns_cache_find_rr, tc_pico_mdns_cache_find_rr);
    suite_add_tcase(s, TCase_pico_mdns_cache_find_rr);
    tcase_add_test(TCase_pico_mdns_cache_add_rr, tc_pico_mdns_cache_add_rr);
    suite_add_tcase(s, TCase_pico_mdns_cache_add_rr);
    tcase_add_test(TCase_pico_mdns_flush_cache, tc_pico_mdns_flush_cache);
    suite_add_tcase(s, TCase_pico_mdns_flush_cache);
    tcase_add_test(TCase_pico_mdns_find_cookie, tc_pico_mdns_find_cookie);
    suite_add_tcase(s, TCase_pico_mdns_find_cookie);
    tcase_add_test(TCase_pico_get_ip6_from_ip4, tc_pico_get_ip6_from_ip4);
    suite_add_tcase(s, TCase_pico_get_ip6_from_ip4);
    tcase_add_test(TCase_pico_mdns_reply_query, tc_pico_mdns_reply_query);
    suite_add_tcase(s, TCase_pico_mdns_reply_query);
    tcase_add_test(TCase_pico_mdns_handle_query, tc_pico_mdns_handle_query);
    suite_add_tcase(s, TCase_pico_mdns_handle_query);
    tcase_add_test(TCase_pico_mdns_handle_answer, tc_pico_mdns_handle_answer);
    suite_add_tcase(s, TCase_pico_mdns_handle_answer);

    tcase_add_test(TCase_pico_mdns_namelen_comp, tc_pico_mdns_namelen_comp);
    suite_add_tcase(s, TCase_pico_mdns_namelen_comp);
    tcase_add_test(TCase_pico_mdns_namelen_uncomp, tc_pico_mdns_namelen_uncomp);
    suite_add_tcase(s, TCase_pico_mdns_namelen_uncomp);
    tcase_add_test(TCase_pico_mdns_expand_name_comp, tc_pico_mdns_expand_name_comp);
    suite_add_tcase(s, TCase_pico_mdns_expand_name_comp);

    tcase_add_test(TCase_pico_mdns_recv, tc_pico_mdns_recv);
    suite_add_tcase(s, TCase_pico_mdns_recv);
    tcase_add_test(TCase_pico_mdns_wakeup, tc_pico_mdns_wakeup);
    suite_add_tcase(s, TCase_pico_mdns_wakeup);
    tcase_add_test(TCase_pico_mdns_announce_timer, tc_pico_mdns_announce_timer);
    suite_add_tcase(s, TCase_pico_mdns_announce_timer);
    tcase_add_test(TCase_pico_mdns_announce, tc_pico_mdns_announce);
    suite_add_tcase(s, TCase_pico_mdns_announce);
    tcase_add_test(TCase_pico_mdns_probe_timer, tc_pico_mdns_probe_timer);
    suite_add_tcase(s, TCase_pico_mdns_probe_timer);
    tcase_add_test(TCase_pico_mdns_probe, tc_pico_mdns_probe);
    suite_add_tcase(s, TCase_pico_mdns_probe);
    tcase_add_test(TCase_pico_mdns_getaddr_generic, tc_pico_mdns_getaddr_generic);
    suite_add_tcase(s, TCase_pico_mdns_getaddr_generic);
    tcase_add_test(TCase_pico_mdns_getname_generic, tc_pico_mdns_getname_generic);
    suite_add_tcase(s, TCase_pico_mdns_getname_generic);
    return s;
}

int main(void)
{
    int fails;
    Suite *s = pico_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);
    return fails;
}
