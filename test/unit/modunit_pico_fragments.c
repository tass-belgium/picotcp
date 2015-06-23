#include "pico_config.h"
#include "pico_ipv6.h"
#include "pico_icmp6.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_tree.h"
#include "pico_constants.h"
#include "pico_fragments.h"
#include "./modules/pico_fragments.c"
#include "check.h"


START_TEST(tc_pico_ipv6_frag_compare)
{
   /* TODO: test this: static int pico_ipv6_frag_compare(void *ka, void *kb) */
}
END_TEST
START_TEST(tc_pico_ipv4_frag_compare)
{
   /* TODO: test this: static int pico_ipv4_frag_compare(void *ka, void *kb) */
}
END_TEST
START_TEST(tc_pico_ipv6_fragments_complete)
{
   /* TODO: test this: static void pico_ipv6_fragments_complete(unsigned int len, uint8_t proto) */
}
END_TEST
START_TEST(tc_pico_ipv4_fragments_complete)
{
   /* TODO: test this: static void pico_ipv4_fragments_complete(unsigned int len, uint8_t proto) */
}
END_TEST
START_TEST(tc_pico_fragments_complete)
{
   /* TODO: test this: static void pico_fragments_complete(unsigned int bookmark, uint8_t proto, uint8_t net) */
}
END_TEST
START_TEST(tc_pico_fragments_check_complete)
{
   /* TODO: test this: static void pico_fragments_check_complete(uint8_t proto, uint8_t net) */
}
END_TEST
START_TEST(tc_pico_frag_expire)
{
   /* TODO: test this: static void pico_frag_expire(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_ipv6_frag_timer_on)
{
   /* TODO: test this: static void pico_ipv6_frag_timer_on(void) */
}
END_TEST
START_TEST(tc_pico_ipv4_frag_timer_on)
{
   /* TODO: test this: static void pico_ipv4_frag_timer_on(void) */
}
END_TEST
START_TEST(tc_pico_ipv6_frag_match)
{
   /* TODO: test this: static int pico_ipv6_frag_match(struct pico_frame *a, struct pico_frame *b) */
}
END_TEST
START_TEST(tc_pico_ipv4_frag_match)
{
   /* TODO: test this: static int pico_ipv4_frag_match(struct pico_frame *a, struct pico_frame *b) */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_ipv6_frag_compare = tcase_create("Unit test for pico_ipv6_frag_compare");
    TCase *TCase_pico_ipv4_frag_compare = tcase_create("Unit test for pico_ipv4_frag_compare");
    TCase *TCase_pico_ipv6_fragments_complete = tcase_create("Unit test for pico_ipv6_fragments_complete");
    TCase *TCase_pico_ipv4_fragments_complete = tcase_create("Unit test for pico_ipv4_fragments_complete");
    TCase *TCase_pico_fragments_complete = tcase_create("Unit test for pico_fragments_complete");
    TCase *TCase_pico_fragments_check_complete = tcase_create("Unit test for pico_fragments_check_complete");
    TCase *TCase_pico_frag_expire = tcase_create("Unit test for pico_frag_expire");
    TCase *TCase_pico_ipv6_frag_timer_on = tcase_create("Unit test for pico_ipv6_frag_timer_on");
    TCase *TCase_pico_ipv4_frag_timer_on = tcase_create("Unit test for pico_ipv4_frag_timer_on");
    TCase *TCase_pico_ipv6_frag_match = tcase_create("Unit test for pico_ipv6_frag_match");
    TCase *TCase_pico_ipv4_frag_match = tcase_create("Unit test for pico_ipv4_frag_match");


    tcase_add_test(TCase_pico_ipv6_frag_compare, tc_pico_ipv6_frag_compare);
    suite_add_tcase(s, TCase_pico_ipv6_frag_compare);
    tcase_add_test(TCase_pico_ipv4_frag_compare, tc_pico_ipv4_frag_compare);
    suite_add_tcase(s, TCase_pico_ipv4_frag_compare);
    tcase_add_test(TCase_pico_ipv6_fragments_complete, tc_pico_ipv6_fragments_complete);
    suite_add_tcase(s, TCase_pico_ipv6_fragments_complete);
    tcase_add_test(TCase_pico_ipv4_fragments_complete, tc_pico_ipv4_fragments_complete);
    suite_add_tcase(s, TCase_pico_ipv4_fragments_complete);
    tcase_add_test(TCase_pico_fragments_complete, tc_pico_fragments_complete);
    suite_add_tcase(s, TCase_pico_fragments_complete);
    tcase_add_test(TCase_pico_fragments_check_complete, tc_pico_fragments_check_complete);
    suite_add_tcase(s, TCase_pico_fragments_check_complete);
    tcase_add_test(TCase_pico_frag_expire, tc_pico_frag_expire);
    suite_add_tcase(s, TCase_pico_frag_expire);
    tcase_add_test(TCase_pico_ipv6_frag_timer_on, tc_pico_ipv6_frag_timer_on);
    suite_add_tcase(s, TCase_pico_ipv6_frag_timer_on);
    tcase_add_test(TCase_pico_ipv4_frag_timer_on, tc_pico_ipv4_frag_timer_on);
    suite_add_tcase(s, TCase_pico_ipv4_frag_timer_on);
    tcase_add_test(TCase_pico_ipv6_frag_match, tc_pico_ipv6_frag_match);
    suite_add_tcase(s, TCase_pico_ipv6_frag_match);
    tcase_add_test(TCase_pico_ipv4_frag_match, tc_pico_ipv4_frag_match);
    suite_add_tcase(s, TCase_pico_ipv4_frag_match);
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
