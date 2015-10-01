#include "pico_config.h"
#include "pico_frame.h"
#include "pico_device.h"
#include "pico_protocol.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_dns_client.h"
#include "pico_eth.h"
#include "pico_arp.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_icmp4.h"
#include "pico_igmp.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "heap.h"
#include "stack/pico_stack.c"
#include "check.h"


Suite *pico_suite(void);
void fake_timer(pico_time __attribute__((unused)) now, void __attribute__((unused)) *n);
START_TEST(tc_pico_ll_receive)
{
    /* TODO: test this: static int32_t pico_ll_receive(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ll_check_bcast)
{
    /* TODO: test this: static void pico_ll_check_bcast(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_destination_is_bcast)
{
    /* TODO: test this: static int destination_is_bcast(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_destination_is_mcast)
{
    /* TODO: test this: static int destination_is_mcast(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_eth)
{
    /* TODO: test this: static struct pico_eth *pico_ethernet_mcast_translate(struct pico_frame *f, uint8_t *pico_mcast_mac) */
}
END_TEST
START_TEST(tc_pico_ethsend_local)
{
    /* TODO: test this: static int32_t pico_ethsend_local(struct pico_frame *f, struct pico_eth_hdr *hdr, int *ret) */
}
END_TEST
START_TEST(tc_pico_ethsend_bcast)
{
    /* TODO: test this: static int32_t pico_ethsend_bcast(struct pico_frame *f, int *ret) */
}
END_TEST
START_TEST(tc_pico_ethsend_dispatch)
{
    /* TODO: test this: static int32_t pico_ethsend_dispatch(struct pico_frame *f, int *ret) */
}
END_TEST
START_TEST(tc_calc_score)
{
    /* TODO: test this: static int calc_score(int *score, int *index, int avg[][PROTO_DEF_AVG_NR], int *ret) */
}
END_TEST

#ifdef PICO_FAULTY
void fake_timer(pico_time __attribute__((unused)) now, void __attribute__((unused)) *n)
{

}
#endif

START_TEST(tc_stack_generic)
{
#ifdef PICO_FAULTY
    printf("Testing with faulty memory in pico_stack_init (10)\n");
    pico_set_mm_failure(10);
    fail_if(pico_stack_init() != -1);
#endif
    pico_stack_init();
#ifdef PICO_FAULTY
    printf("Testing with faulty memory in pico_timer_add (1)\n");
    pico_set_mm_failure(1);
    fail_if(pico_timer_add(0, fake_timer, NULL) != NULL);
#endif


}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_ll_receive = tcase_create("Unit test for pico_ll_receive");
    TCase *TCase_pico_ll_check_bcast = tcase_create("Unit test for pico_ll_check_bcast");
    TCase *TCase_destination_is_bcast = tcase_create("Unit test for destination_is_bcast");
    TCase *TCase_destination_is_mcast = tcase_create("Unit test for destination_is_mcast");
    TCase *TCase_pico_eth = tcase_create("Unit test for pico_eth");
    TCase *TCase_pico_ethsend_local = tcase_create("Unit test for pico_ethsend_local");
    TCase *TCase_pico_ethsend_bcast = tcase_create("Unit test for pico_ethsend_bcast");
    TCase *TCase_pico_ethsend_dispatch = tcase_create("Unit test for pico_ethsend_dispatch");
    TCase *TCase_calc_score = tcase_create("Unit test for calc_score");
    TCase *TCase_stack_generic = tcase_create("GENERIC stack initialization unit test");


    tcase_add_test(TCase_pico_ll_receive, tc_pico_ll_receive);
    suite_add_tcase(s, TCase_pico_ll_receive);
    tcase_add_test(TCase_pico_ll_check_bcast, tc_pico_ll_check_bcast);
    suite_add_tcase(s, TCase_pico_ll_check_bcast);
    tcase_add_test(TCase_destination_is_bcast, tc_destination_is_bcast);
    suite_add_tcase(s, TCase_destination_is_bcast);
    tcase_add_test(TCase_destination_is_mcast, tc_destination_is_mcast);
    suite_add_tcase(s, TCase_destination_is_mcast);
    tcase_add_test(TCase_pico_eth, tc_pico_eth);
    suite_add_tcase(s, TCase_pico_eth);
    tcase_add_test(TCase_pico_ethsend_local, tc_pico_ethsend_local);
    suite_add_tcase(s, TCase_pico_ethsend_local);
    tcase_add_test(TCase_pico_ethsend_bcast, tc_pico_ethsend_bcast);
    suite_add_tcase(s, TCase_pico_ethsend_bcast);
    tcase_add_test(TCase_pico_ethsend_dispatch, tc_pico_ethsend_dispatch);
    suite_add_tcase(s, TCase_pico_ethsend_dispatch);
    tcase_add_test(TCase_calc_score, tc_calc_score);
    suite_add_tcase(s, TCase_calc_score);
    tcase_add_test(TCase_stack_generic, tc_stack_generic);
    suite_add_tcase(s, TCase_stack_generic);
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
