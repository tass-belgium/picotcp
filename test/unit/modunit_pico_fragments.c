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

/* Mock! */
static int transport_recv_called = 0;
#define TESTPROTO 0x99
int32_t pico_transport_receive(struct pico_frame *f, uint8_t proto)
{
    fail_if(proto != TESTPROTO);
    transport_recv_called++;
    pico_frame_discard(f);
    return 0;
}


START_TEST(tc_pico_ipv6_frag_compare)
{
    struct pico_frame *a, *b;
    a = pico_frame_alloc(10);
    fail_if(!a);
    b = pico_frame_alloc(10);
    fail_if(!b);
    a->frag = 0xaa00;
    b->frag = 0xbb00;
    fail_unless(pico_ipv6_frag_compare(a, b) < 0);
    fail_unless(pico_ipv6_frag_compare(b, a) > 0);
    b->frag = 0xaa00;
    fail_unless(pico_ipv6_frag_compare(a, b) == 0);
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST

START_TEST(tc_pico_ipv4_frag_compare)
{
    struct pico_frame *a, *b;
    a = pico_frame_alloc(10);
    fail_if(!a);
    b = pico_frame_alloc(10);
    fail_if(!b);
    a->frag = 0xaa00;
    b->frag = 0xbb00;
    fail_unless(pico_ipv4_frag_compare(a, b) < 0);
    fail_unless(pico_ipv4_frag_compare(b, a) > 0);
    b->frag = 0xaa00;
    fail_unless(pico_ipv4_frag_compare(a, b) == 0);
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST

START_TEST(tc_pico_ipv6_fragments_complete)
{
    struct pico_frame *a, *b;
    transport_recv_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = 1; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20; /* off = 32 */

    pico_tree_insert(&ipv6_fragments, a);
    pico_tree_insert(&ipv6_fragments, b);

    pico_set_mm_failure(1);
    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV6);
    fail_if(transport_recv_called != 0);

    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV6);
    fail_if(transport_recv_called != 1);
}
END_TEST

START_TEST(tc_pico_ipv4_fragments_complete)
{
    struct pico_frame *a, *b;
    transport_recv_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u; /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);
    pico_tree_insert(&ipv4_fragments, b);

    pico_set_mm_failure(1);
    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV4);
    fail_if(transport_recv_called != 0);

    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV4);
    fail_if(transport_recv_called != 1);
}
END_TEST

START_TEST(tc_pico_fragments_complete)
{
    /* Done in the two tests above */
}
END_TEST

START_TEST(tc_pico_fragments_check_complete)
{
    struct pico_frame *a, *b;
    fail_if(pico_fragments_check_complete(TESTPROTO, PICO_PROTO_IPV4) != 0);
    fail_if(pico_fragments_check_complete(TESTPROTO, PICO_PROTO_IPV6) != 0);

    transport_recv_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u; /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);
    pico_tree_insert(&ipv4_fragments, b);

    fail_if(pico_fragments_check_complete(TESTPROTO, PICO_PROTO_IPV4) == 0);
    fail_if(transport_recv_called != 1);

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
