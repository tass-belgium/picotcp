#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"
#include "pico_udp.h"
#include "modules/pico_dns_client.c"
#include "check.h"

Suite *pico_suite(void);

START_TEST(tc_pico_dns_client_callback)
{
    struct pico_socket *s = pico_udp_open();
    s->proto = &pico_proto_udp;

    fail_if(!s);

    /* Test with ERR */
    pico_dns_client_callback(PICO_SOCK_EV_ERR, s);

    /* Test with failing RD */
    pico_dns_client_callback(PICO_SOCK_EV_RD, s);

}
END_TEST
START_TEST(tc_pico_dns_client_retransmission)
{
    /* TODO: test this: static void pico_dns_client_retransmission(pico_time now, void *arg); */
}
END_TEST
START_TEST(tc_dns_ns_cmp)
{
    /* TODO: test this: static int dns_ns_cmp(void *ka, void *kb) */
}
END_TEST
START_TEST(tc_dns_query_cmp)
{
    /* TODO: test this: static int dns_query_cmp(void *ka, void *kb) */
}
END_TEST
START_TEST(tc_pico_dns_client_del_ns)
{
    /* TODO: test this: static int pico_dns_client_del_ns(struct pico_ip4 *ns_addr) */
}
END_TEST
START_TEST(tc_pico_dns_ns)
{
    /* TODO: test this: static struct pico_dns_ns *pico_dns_client_add_ns(struct pico_ip4 *ns_addr) */
}
END_TEST
START_TEST(tc_pico_dns_client_del_query)
{
    /* TODO: test this: static int pico_dns_client_del_query(uint16_t id) */
}
END_TEST
START_TEST(tc_pico_dns_query)
{
    /* TODO: test this: static struct pico_dns_query *pico_dns_client_find_query(uint16_t id) */
}
END_TEST
START_TEST(tc_pico_dns_client_strlen)
{
    /* TODO: test this: static uint16_t pico_dns_client_strlen(const char *url) */
}
END_TEST
START_TEST(tc_pico_dns_client_seek)
{
    /* TODO: test this: static char *pico_dns_client_seek(char *ptr) */
}
END_TEST
START_TEST(tc_pico_dns_client_mirror)
{
    /* TODO: test this: static int8_t pico_dns_client_mirror(char *ptr) */
}
END_TEST
START_TEST(tc_pico_dns_client_query_prefix)
{
    /* TODO: test this: static int pico_dns_client_query_prefix(struct pico_dns_prefix *pre) */
}
END_TEST
START_TEST(tc_pico_dns_client_query_suffix)
{
    /* TODO: test this: static int pico_dns_client_query_suffix(struct pico_dns_query_suffix *suf, uint16_t type, uint16_t class) */
}
END_TEST
START_TEST(tc_pico_dns_client_query_domain)
{
    /* TODO: test this: static int pico_dns_client_query_domain(char *ptr) */
}
END_TEST
START_TEST(tc_pico_dns_client_answer_domain)
{
    /* TODO: test this: static int pico_dns_client_answer_domain(char *ptr) */
}
END_TEST
START_TEST(tc_pico_dns_client_check_prefix)
{
    /* TODO: test this: static int pico_dns_client_check_prefix(struct pico_dns_prefix *pre) */
}
END_TEST
START_TEST(tc_pico_dns_client_check_qsuffix)
{
    /* TODO: test this: static int pico_dns_client_check_qsuffix(struct pico_dns_query_suffix *suf, struct pico_dns_query *q) */
}
END_TEST
START_TEST(tc_pico_dns_client_check_asuffix)
{
    /* TODO: test this: static int pico_dns_client_check_asuffix(struct pico_dns_answer_suffix *suf, struct pico_dns_query *q) */
}
END_TEST
START_TEST(tc_pico_dns_client_seek_suffix)
{
    /* TODO: test this: static char *pico_dns_client_seek_suffix(char *suf, struct pico_dns_prefix *pre, struct pico_dns_query *q) */
}
END_TEST
START_TEST(tc_pico_dns_client_send)
{
    /* TODO: test this: static int pico_dns_client_send(struct pico_dns_query *q) */
}
END_TEST
START_TEST(tc_pico_dns_client_user_callback)
{
    /* TODO: test this: static int pico_dns_client_user_callback(struct pico_dns_answer_suffix *asuffix, struct pico_dns_query *q) */
}
END_TEST
START_TEST(tc_pico_dns_client_getaddr_init)
{
    /* TODO: test this: static int pico_dns_client_getaddr_init(const char *url, uint16_t proto, void (*callback)(char *, void *), void *arg) */
}
END_TEST
START_TEST(tc_pico_dns_ipv6_set_ptr)
{
    /* TODO: test this: static void pico_dns_ipv6_set_ptr(const char *ip, char *dst) */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_dns_client_callback = tcase_create("Unit test for pico_dns_client_callback");
    TCase *TCase_pico_dns_client_retransmission = tcase_create("Unit test for pico_dns_client_retransmission");
    TCase *TCase_dns_ns_cmp = tcase_create("Unit test for dns_ns_cmp");
    TCase *TCase_dns_query_cmp = tcase_create("Unit test for dns_query_cmp");
    TCase *TCase_pico_dns_client_del_ns = tcase_create("Unit test for pico_dns_client_del_ns");
    TCase *TCase_pico_dns_ns = tcase_create("Unit test for pico_dns_ns");
    TCase *TCase_pico_dns_client_del_query = tcase_create("Unit test for pico_dns_client_del_query");
    TCase *TCase_pico_dns_query = tcase_create("Unit test for pico_dns_query");
    TCase *TCase_pico_dns_client_strlen = tcase_create("Unit test for pico_dns_client_strlen");
    TCase *TCase_pico_dns_client_seek = tcase_create("Unit test for pico_dns_client_seek");
    TCase *TCase_pico_dns_client_mirror = tcase_create("Unit test for pico_dns_client_mirror");
    TCase *TCase_pico_dns_client_query_prefix = tcase_create("Unit test for pico_dns_client_query_prefix");
    TCase *TCase_pico_dns_client_query_suffix = tcase_create("Unit test for pico_dns_client_query_suffix");
    TCase *TCase_pico_dns_client_query_domain = tcase_create("Unit test for pico_dns_client_query_domain");
    TCase *TCase_pico_dns_client_answer_domain = tcase_create("Unit test for pico_dns_client_answer_domain");
    TCase *TCase_pico_dns_client_check_prefix = tcase_create("Unit test for pico_dns_client_check_prefix");
    TCase *TCase_pico_dns_client_check_qsuffix = tcase_create("Unit test for pico_dns_client_check_qsuffix");
    TCase *TCase_pico_dns_client_check_asuffix = tcase_create("Unit test for pico_dns_client_check_asuffix");
    TCase *TCase_pico_dns_client_seek_suffix = tcase_create("Unit test for pico_dns_client_seek_suffix");
    TCase *TCase_pico_dns_client_send = tcase_create("Unit test for pico_dns_client_send");
    TCase *TCase_pico_dns_client_user_callback = tcase_create("Unit test for pico_dns_client_user_callback");
    TCase *TCase_pico_dns_client_getaddr_init = tcase_create("Unit test for pico_dns_client_getaddr_init");
    TCase *TCase_pico_dns_ipv6_set_ptr = tcase_create("Unit test for pico_dns_ipv6_set_ptr");


    tcase_add_test(TCase_pico_dns_client_callback, tc_pico_dns_client_callback);
    suite_add_tcase(s, TCase_pico_dns_client_callback);
    tcase_add_test(TCase_pico_dns_client_retransmission, tc_pico_dns_client_retransmission);
    suite_add_tcase(s, TCase_pico_dns_client_retransmission);
    tcase_add_test(TCase_dns_ns_cmp, tc_dns_ns_cmp);
    suite_add_tcase(s, TCase_dns_ns_cmp);
    tcase_add_test(TCase_dns_query_cmp, tc_dns_query_cmp);
    suite_add_tcase(s, TCase_dns_query_cmp);
    tcase_add_test(TCase_pico_dns_client_del_ns, tc_pico_dns_client_del_ns);
    suite_add_tcase(s, TCase_pico_dns_client_del_ns);
    tcase_add_test(TCase_pico_dns_ns, tc_pico_dns_ns);
    suite_add_tcase(s, TCase_pico_dns_ns);
    tcase_add_test(TCase_pico_dns_client_del_query, tc_pico_dns_client_del_query);
    suite_add_tcase(s, TCase_pico_dns_client_del_query);
    tcase_add_test(TCase_pico_dns_query, tc_pico_dns_query);
    suite_add_tcase(s, TCase_pico_dns_query);
    tcase_add_test(TCase_pico_dns_client_strlen, tc_pico_dns_client_strlen);
    suite_add_tcase(s, TCase_pico_dns_client_strlen);
    tcase_add_test(TCase_pico_dns_client_seek, tc_pico_dns_client_seek);
    suite_add_tcase(s, TCase_pico_dns_client_seek);
    tcase_add_test(TCase_pico_dns_client_mirror, tc_pico_dns_client_mirror);
    suite_add_tcase(s, TCase_pico_dns_client_mirror);
    tcase_add_test(TCase_pico_dns_client_query_prefix, tc_pico_dns_client_query_prefix);
    suite_add_tcase(s, TCase_pico_dns_client_query_prefix);
    tcase_add_test(TCase_pico_dns_client_query_suffix, tc_pico_dns_client_query_suffix);
    suite_add_tcase(s, TCase_pico_dns_client_query_suffix);
    tcase_add_test(TCase_pico_dns_client_query_domain, tc_pico_dns_client_query_domain);
    suite_add_tcase(s, TCase_pico_dns_client_query_domain);
    tcase_add_test(TCase_pico_dns_client_answer_domain, tc_pico_dns_client_answer_domain);
    suite_add_tcase(s, TCase_pico_dns_client_answer_domain);
    tcase_add_test(TCase_pico_dns_client_check_prefix, tc_pico_dns_client_check_prefix);
    suite_add_tcase(s, TCase_pico_dns_client_check_prefix);
    tcase_add_test(TCase_pico_dns_client_check_qsuffix, tc_pico_dns_client_check_qsuffix);
    suite_add_tcase(s, TCase_pico_dns_client_check_qsuffix);
    tcase_add_test(TCase_pico_dns_client_check_asuffix, tc_pico_dns_client_check_asuffix);
    suite_add_tcase(s, TCase_pico_dns_client_check_asuffix);
    tcase_add_test(TCase_pico_dns_client_seek_suffix, tc_pico_dns_client_seek_suffix);
    suite_add_tcase(s, TCase_pico_dns_client_seek_suffix);
    tcase_add_test(TCase_pico_dns_client_send, tc_pico_dns_client_send);
    suite_add_tcase(s, TCase_pico_dns_client_send);
    tcase_add_test(TCase_pico_dns_client_user_callback, tc_pico_dns_client_user_callback);
    suite_add_tcase(s, TCase_pico_dns_client_user_callback);
    tcase_add_test(TCase_pico_dns_client_getaddr_init, tc_pico_dns_client_getaddr_init);
    suite_add_tcase(s, TCase_pico_dns_client_getaddr_init);
    tcase_add_test(TCase_pico_dns_ipv6_set_ptr, tc_pico_dns_ipv6_set_ptr);
    suite_add_tcase(s, TCase_pico_dns_ipv6_set_ptr);
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
