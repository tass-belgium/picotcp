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

START_TEST(tc_mdns_cmp)
{
    /* TODO: test this: static int mdns_cmp(void *ka, void *kb) */
    struct pico_mdns_cookie ka;
    struct pico_mdns_cookie kb;
    ka.url = strdup("test1");
    kb.url = strdup("test2");
    mdns_cmp(&ka, &kb);
}
END_TEST
START_TEST(tc_pico_mdns_send)
{
    /* TODO: test this: static int pico_mdns_send(struct pico_dns_header *hdr, uint16_t len) */
    struct pico_dns_header hdr = {
        0
    };
    uint16_t len = 0;
    pico_mdns_send(&hdr, len);
}
END_TEST
START_TEST(tc_pico_mdns_add_cookie)
{
    /* TODO: test this: static struct pico_mdns_cookie *pico_mdns_add_cookie(struct pico_dns_header *hdr, uint16_t len, struct pico_dns_query_suffix *suffix, unsigned int probe, void (*callback)(char *str, void *arg), void *arg) */
    struct pico_dns_header hdr = {
        0
    };
    uint16_t len = 0;
    struct pico_dns_query_suffix suf = {
        0
    };
    unsigned int probe = 0;
    void *arg = NULL;
    pico_stack_init();
    pico_mdns_add_cookie(&hdr, len, &suf, probe, callback, arg);
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
START_TEST(tc_pico_mdns_answer_suffix)
{
    /* TODO: test this: static void pico_mdns_answer_suffix(struct pico_dns_answer_suffix *asuf, uint16_t qtype, uint16_t qclass, uint32_t ttl, uint16_t rdlength) */
    struct pico_dns_answer_suffix asuf = {
        0
    };
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    uint32_t ttl = 0;
    uint16_t rdlength = 0;

    pico_mdns_answer_suffix(&asuf, qtype, qclass, ttl, rdlength);
}
END_TEST
START_TEST(tc_pico_mdns_create_answer)
{
    /* TODO: test this: static struct pico_dns_header *pico_mdns_create_answer(char *url, uint16_t *len, uint16_t qtype, union pico_address *rdata) */
    char *url = NULL;
    uint16_t len = 0;
    uint16_t qtype = 0;
    union pico_address *rdata = NULL;

    pico_mdns_create_answer(url, &len, qtype, rdata);
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
    /* TODO: test this: static int pico_mdns_del_cookie(char *url) */
    char url[256] = {
        0
    };

    pico_mdns_del_cookie(url);
}
END_TEST
START_TEST(tc_pico_mdns_find_cookie)
{
    /* TODO: test this: static struct pico_mdns_cookie *pico_mdns_find_cookie(char *url) */
    char url[256] = {
        0
    };

    pico_mdns_find_cookie(url);
}
END_TEST
START_TEST(tc_pico_get_ip6_from_ip4)
{
    /* TODO: test this: static struct pico_ip6 *pico_get_ip6_from_ip4(struct pico_ip4 *ipv4_addr) */
    struct pico_ip4 *ipv4_addr = NULL;

    pico_get_ip6_from_ip4(ipv4_addr);
}
END_TEST
START_TEST(tc_pico_mdns_reply_query)
{
    /* TODO: test this: static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer) */
    uint16_t qtype = 0;
    struct pico_ip4 peer = {
        0
    };
    char *name;

    pico_mdns_reply_query(qtype, peer, name);
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
    char *url;
    struct pico_dns_answer_suffix suf = {
        0
    };
    char *data = NULL;

    url = PICO_ZALLOC(sizeof(char));
    pico_mdns_handle_answer(url, &suf, data);
}
END_TEST
START_TEST(tc_pico_mdns_namelen_comp)
{
    /* TODO: test this: static unsigned int pico_mdns_namelen_comp(char *name) */
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    unsigned int ret = 0;

    /* name without compression */
    ret = pico_mdns_namelen_comp(name);
    ck_assert(ret == 12);

    /* name with compression */
    ret = pico_mdns_namelen_comp(name_comp);
    ck_assert(ret == 13);
}
END_TEST
START_TEST(tc_pico_mdns_namelen_uncomp)
{
    /* TODO: test this: static unsigned int pico_mdns_namelen_uncomp(char *name, char *buf) */
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    char buf[] = "00\5index\0";
    unsigned int ret = 0;

    /* name without compression */
    ret = pico_mdns_namelen_uncomp(name, buf);
    printf("ret: %u\n", ret);
    ck_assert(ret == 12);

    /* name with compression */
    ret = pico_mdns_namelen_uncomp(name_comp, buf);
    printf("ret: %u\n", ret);
    ck_assert(ret == 18);
}
END_TEST
START_TEST(tc_pico_mdns_expand_name_comp)
{
    /* TODO: test this: static char *pico_mdns_expand_name_comp(char *url, char *buf) */
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    char buf[] = "00\5index\0";
    char *ret;
    ret = pico_mdns_expand_name_comp(name, buf);
    ck_assert(ret != NULL);
}
END_TEST
START_TEST(tc_pico_mdns_recv)
{
    /* TODO: test this: static int pico_mdns_recv(void *buf, int buflen, struct pico_ip4 peer) */
    char buf[256];
    int buflen = 0;
    struct pico_ip4 peer = {
        0
    };

    pico_mdns_recv(buf, buflen, peer);
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

    TCase *TCase_mdns_cmp = tcase_create("Unit test for mdns_cmp");
    TCase *TCase_pico_mdns_send = tcase_create("Unit test for pico_mdns_send");
    TCase *TCase_pico_mdns_add_cookie = tcase_create("Unit test for pico_mdns_add_cookie");
    TCase *TCase_pico_mdns_fill_header = tcase_create("Unit test for pico_mdns_fill_header");
    TCase *TCase_pico_mdns_answer_suffix = tcase_create("Unit test for pico_mdns_answer_suffix");
    TCase *TCase_pico_mdns_create_answer = tcase_create("Unit test for pico_mdns_create_answer");
    TCase *TCase_pico_mdns_create_query = tcase_create("Unit test for pico_mdns_create_query");
    TCase *TCase_pico_mdns_del_cookie = tcase_create("Unit test for pico_mdns_del_cookie");
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


    tcase_add_test(TCase_mdns_cmp, tc_mdns_cmp);
    suite_add_tcase(s, TCase_mdns_cmp);
    tcase_add_test(TCase_pico_mdns_send, tc_pico_mdns_send);
    suite_add_tcase(s, TCase_pico_mdns_send);
    tcase_add_test(TCase_pico_mdns_add_cookie, tc_pico_mdns_add_cookie);
    suite_add_tcase(s, TCase_pico_mdns_add_cookie);
    tcase_add_test(TCase_pico_mdns_fill_header, tc_pico_mdns_fill_header);
    suite_add_tcase(s, TCase_pico_mdns_fill_header);
    tcase_add_test(TCase_pico_mdns_answer_suffix, tc_pico_mdns_answer_suffix);
    suite_add_tcase(s, TCase_pico_mdns_answer_suffix);
    tcase_add_test(TCase_pico_mdns_create_answer, tc_pico_mdns_create_answer);
    suite_add_tcase(s, TCase_pico_mdns_create_answer);
    tcase_add_test(TCase_pico_mdns_create_query, tc_pico_mdns_create_query);
    suite_add_tcase(s, TCase_pico_mdns_create_query);
    tcase_add_test(TCase_pico_mdns_del_cookie, tc_pico_mdns_del_cookie);
    suite_add_tcase(s, TCase_pico_mdns_del_cookie);
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
