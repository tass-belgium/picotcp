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

Suite *pico_suite(void);
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

static int timer_add_called = 0;
uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    IGNORE_PARAMETER(expire);
    IGNORE_PARAMETER(arg);
    fail_if(timer != pico_frag_expire);
    timer_add_called++;
    return NULL;
}

static int timer_cancel_called = 0;
void pico_timer_cancel(uint32_t id)
{
    timer_cancel_called++;
}

static int icmp4_frag_expired_called = 0;
int pico_icmp4_frag_expired(struct pico_frame *f)
{
    fail_unless(IS_IPV4(f));
    icmp4_frag_expired_called++;
    return 0;
}

static int icmp6_frag_expired_called = 0;
int pico_icmp6_frag_expired(struct pico_frame *f)
{
    fail_unless(IS_IPV6(f));
    icmp6_frag_expired_called++;
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
    timer_cancel_called = 0;
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
    fail_if(timer_cancel_called != 0);

    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV6);
    fail_if(transport_recv_called != 1);
    fail_if(timer_cancel_called != 1);
}
END_TEST

START_TEST(tc_pico_ipv4_fragments_complete)
{
    struct pico_frame *a, *b;
    transport_recv_called = 0;
    timer_cancel_called = 0;
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
    fail_if(timer_cancel_called != 0);

    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV4);
    fail_if(transport_recv_called != 1);
    fail_if(timer_cancel_called != 1);
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
    timer_cancel_called = 0;
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
    fail_if(timer_cancel_called != 1);

}
END_TEST
START_TEST(tc_pico_frag_expire)
{
    struct pico_frame *a, *b;
    /* Addr setup, choose a unicast addr */
    struct pico_ip6 addr_1 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    char ipv4_multicast_address[] = {
        "224.0.0.1"
    };
    struct pico_ip6 ipv6_multicast_addr = {{ 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};

    /* Clear env vars */
    icmp4_frag_expired_called = 0;
    icmp6_frag_expired_called = 0;

    /* Common tests */
    /* Case 1: tree is NULL */
    pico_frag_expire(0, NULL);
    fail_if(icmp4_frag_expired_called);
    fail_if(icmp6_frag_expired_called);

    /* IPV4 TESTS */
    /* Initial setup */
    a = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* Case 1: first fragment was not received, do not send notify + empty tree */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv4_hdr);
    a->buffer[0] = 0x40;        /* IPV4 */
    a->frag = 0x20 >> 3u;       /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);

    pico_frag_expire(0, (void*)(&ipv4_fragments));
    fail_if(icmp4_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv4_fragments));

    /* Case 2: first fragment was received, send notify + empty tree */

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);
    b->buffer[0] = 0x40;        /* IPV4 */
    b->frag = PICO_IPV4_MOREFRAG; /* more frags */

    pico_tree_insert(&ipv4_fragments, b);

    pico_frag_expire(0, (void*)(&ipv4_fragments));
    fail_if(!icmp4_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv4_fragments));

    /* Case 3: first fragment was received but it is multicast, do not send notify + empty tree */
    /* Reallocate frame, it was discarded in the last pico_frag_expire() */
    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);
    /* Reset env vars */
    icmp4_frag_expired_called = 0;

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);
    b->buffer[0] = 0x40;        /* IPV4 */
    b->frag = PICO_IPV4_MOREFRAG; /* more frags */

    pico_string_to_ipv4(ipv4_multicast_address, &((struct pico_ipv4_hdr*)(b->net_hdr))->dst.addr);

    pico_tree_insert(&ipv4_fragments, b);

    pico_frag_expire(0, (void*)(&ipv4_fragments));
    fail_if(icmp4_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv4_fragments));


    /* IPV6 TESTS */
    /* re-allocate frames, they were discarded in pico_frag_expire */
    a = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* Case 4: first fragment was not received, do not send notify + empty tree */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv6_hdr);
    a->buffer[0] = 0x60;        /* IPV6 */
    a->frag = 0x20;             /* off = 32 */
    memcpy(((struct pico_ipv6_hdr*)(a->net_hdr))->dst.addr, addr_1.addr, PICO_SIZE_IP6);

    pico_tree_insert(&ipv6_fragments, a);

    pico_frag_expire(0, (void*)(&ipv6_fragments));
    fail_if(icmp6_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv6_fragments));

    /* Case 5: first fragment was received, send notify + empty tree */

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv6_hdr);
    b->buffer[0] = 0x60;        /* IPV6 */
    b->frag = 1;
    memcpy(((struct pico_ipv6_hdr*)(b->net_hdr))->dst.addr, addr_1.addr, PICO_SIZE_IP6);

    pico_tree_insert(&ipv6_fragments, b);

    pico_frag_expire(0, (void*)(&ipv6_fragments));
    fail_if(!icmp6_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv6_fragments));

    /* Case 6: first fragment was received but it is multicast, do not send notify + empty tree */
    /* Reallocate frame, it was discarded in the last pico_frag_expire() */
    b = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);
    /* Reset env vars */
    icmp6_frag_expired_called = 0;

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);
    b->buffer[0] = 0x60;        /* IPV4 */
    b->frag = 1;

    memcpy(((struct pico_ipv6_hdr*)(b->net_hdr))->dst.addr, ipv6_multicast_addr.addr, PICO_SIZE_IP6);

    pico_tree_insert(&ipv6_fragments, b);

    pico_frag_expire(0, (void*)(&ipv6_fragments));
    fail_if(icmp6_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv6_fragments));

}
END_TEST
START_TEST(tc_pico_ipv6_frag_timer_on)
{
    /* Reset env variable */
    timer_add_called = 0;

    pico_ipv6_frag_timer_on();

    /* Was timer added? */
    fail_if(!timer_add_called);
}
END_TEST
START_TEST(tc_pico_ipv4_frag_timer_on)
{
    /* Reset env variable */
    timer_add_called = 0;

    pico_ipv4_frag_timer_on();

    /* Was timer added? */
    fail_if(!timer_add_called);
}
END_TEST
START_TEST(tc_pico_ipv6_frag_match)
{
    struct pico_frame *a, *b;
    struct pico_ipv6_hdr *ha, *hb;

    /* Addr setup */
    struct pico_ip6 addr_1 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    struct pico_ip6 addr_2 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8 }};

    /* Inital setup */
    a = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* Case 1: net hdr(s) are NULL */
    a->net_hdr = NULL;
    b->net_hdr = NULL;

    fail_if(pico_ipv6_frag_match(a, b) != 0);

    /* Init a frame */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv6_hdr);

    fail_if(pico_ipv6_frag_match(a, b) != 0);

    /* Init b frame */
    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv6_hdr);

    /* Init hdrs for rest of tests*/
    ha = (struct pico_ipv6_hdr *)a->net_hdr;
    hb = (struct pico_ipv6_hdr *)b->net_hdr;

    /* Case 2: src addr are different*/
    /* Init a and b net hdr adresses */
    memcpy(ha->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(ha->dst.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->src.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->dst.addr, addr_2.addr, PICO_SIZE_IP6);

    fail_if(pico_ipv6_frag_match(a, b) != 0);

    /* Case 3: dst addr are different*/
    /* Init a and b net hdr adresses */
    memcpy(ha->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(ha->dst.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(hb->dst.addr, addr_1.addr, PICO_SIZE_IP6);

    fail_if(pico_ipv6_frag_match(a, b) != 0);

    /* Case 4: fragments are the same (src and dst are the same)*/
    /* Init a and b net hdr adresses */
    memcpy(ha->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(ha->dst.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(hb->dst.addr, addr_2.addr, PICO_SIZE_IP6);

    fail_if(pico_ipv6_frag_match(a, b) != 1);

    /* Cleanup */
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST
START_TEST(tc_pico_ipv4_frag_match)
{
    struct pico_frame *a, *b;
    struct pico_ipv4_hdr *ha, *hb;

    /* Addr setup */
    struct pico_ip4 addr_1 = {
        .addr = long_be(0x0a280064)
    };

    struct pico_ip4 addr_2 = {
        .addr = long_be(0x0a280312)
    };

    /* Inital setup */
    a = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);


    /* Case 1: net hdr(s) are NULL */
    a->net_hdr = NULL;
    b->net_hdr = NULL;

    fail_if(pico_ipv4_frag_match(a, b) != 0);

    /* Init a frame */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv4_hdr);

    fail_if(pico_ipv4_frag_match(a, b) != 0);

    /* Init b frame */
    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);

    /* Init hdrs for rest of tests*/
    ha = (struct pico_ipv4_hdr *)a->net_hdr;
    hb = (struct pico_ipv4_hdr *)b->net_hdr;

    /* Case 2: src addr are different*/
    /* Init a and b net hdr adresses */
    ha->src = addr_1;
    ha->dst = addr_2;
    hb->src = addr_2;
    hb->dst = addr_2;

    fail_if(pico_ipv4_frag_match(a, b) != 0);

    /* Case 3: dst addr are different*/
    /* Init a and b net hdr adresses */
    ha->src = addr_1;
    ha->dst = addr_2;
    hb->src = addr_1;
    hb->dst = addr_1;

    fail_if(pico_ipv4_frag_match(a, b) != 0);

    /* Case 4: fragments are the same (src and dst are the same)*/
    /* Init a and b net hdr adresses */
    ha->src = addr_1;
    ha->dst = addr_2;
    hb->src = addr_1;
    hb->dst = addr_2;

    fail_if(pico_ipv4_frag_match(a, b) != 1);

    /* Cleanup */
    pico_frame_discard(a);
    pico_frame_discard(b);
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
