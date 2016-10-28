//#include "pico_config.h"
#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_icmp4.h"
#include "pico_icmp6.h"
#include "pico_arp.h"
#include "pico_ethernet.h"
#include "modules/pico_ethernet.c"
#include "check.h"

#define STARTING()                                                             \
            printf("*********************** STARTING %s ***\n", __func__);     \
            fflush(stdout)
#define TRYING(s, ...)                                                         \
            printf("Trying %s: " s, __func__, ##__VA_ARGS__);                  \
            fflush(stdout)
#define CHECKING(i)                                                            \
            printf("Checking the results of test %2d in %s...", (i)++,         \
                   __func__);                                                  \
            fflush(stdout)
#define SUCCESS()                                                              \
            printf(" SUCCES\n");                                               \
            fflush(stdout)
#define BREAKING(s, ...)                                                       \
            printf("Breaking %s: " s, __func__, ##__VA_ARGS__);                \
            fflush(stdout)
#define ENDING(i)                                                              \
            printf("*********************** ENDING %s *** N TESTS: %d\n",      \
                   __func__, ((i)-1));                                         \
            fflush(stdout)
#define DBG(s, ...)                                                            \
            printf(s, ##__VA_ARGS__);                                          \
            fflush(stdout)

Suite *pico_suite(void);

START_TEST(tc_destination_is_bcast)
{
    /* test this: static int destination_is_bcast(struct pico_frame *f) */
    struct pico_ip6 addr = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    struct pico_frame *f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    struct pico_ipv6_hdr *h = (struct pico_ipv6_hdr *)f->buffer;
    struct pico_ipv4_hdr *h4 = NULL;

    /* Test parameters */
    int ret = 0, count = 0;

    f->net_hdr = (uint8_t*) h;
    f->buffer[0] = 0x60; /* Ipv6 */

    STARTING();

    TRYING("With wrong protocol -> IPv6\n");
    memcpy(h->dst.addr, addr.addr, PICO_SIZE_IP6);
    ret = destination_is_bcast(f);
    CHECKING(count);
    fail_unless(0 == ret, "Should've returned 0 since IPv6 frame\n");
    SUCCESS();
    pico_frame_discard(f);

    f = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    h4 = (struct pico_ipv4_hdr *)f->buffer;
    f->net_hdr = (uint8_t *)h4;
    f->buffer[0] = 0x40; /* IPv4 */
    TRYING("With right protocol -> IPv4\n");
    ret = destination_is_bcast(f);
    CHECKING(count);
    fail_unless(0 == ret, "Should've returned 0 since not a mcast address\n");
    SUCCESS();

    BREAKING();
    ret = destination_is_bcast(NULL);
    CHECKING(count);
    fail_unless(0 == ret, "Should've returned 0 since NULL-pointer\n");
    SUCCESS();

    ENDING(count);
}
END_TEST
START_TEST(tc_destination_is_mcast)
{
    struct pico_ip6 addr = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    struct pico_ip6 mcast = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    struct pico_ip4 addr4 = {0};
    struct pico_ip4 mcast4 = {0};
    struct pico_frame *f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    struct pico_ipv6_hdr *h = (struct pico_ipv6_hdr *)f->buffer;
    struct pico_ipv4_hdr *h4 = (struct pico_ipv4_hdr *)f->buffer;
    /* Test parameters */
    int ret = 0, count = 0;

    f->net_hdr = (uint8_t*) h;
    f->buffer[0] = 0x60; /* Ipv6 */

    STARTING();

    pico_string_to_ipv4("232.1.1.0", &(mcast4.addr)); /* 0 */
    pico_string_to_ipv4("10.20.0.1", &(addr4.addr));

    pico_string_to_ipv6("ff00:0:0:0:0:0:e801:100", (mcast.addr)); /* 0 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:100", (addr.addr)); /* 0 */

    TRYING("With IPv6 unicast addr\n");
    memcpy(h->dst.addr, addr.addr, PICO_SIZE_IP6);
    ret = destination_is_mcast(f);
    CHECKING(count);
    fail_unless(0 == ret, "Should've returned 0 since not an IPv6 multicast\n");
    SUCCESS();

    TRYING("With IPv6 multicast addr\n");
    memcpy(h->dst.addr, mcast.addr, PICO_SIZE_IP6);
    ret = destination_is_mcast(f);
    CHECKING(count);
    fail_unless(1 == ret, "Should've returned 1 since an IPv6 multicast\n");
    SUCCESS();

    pico_frame_discard(f);
    f = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    h4 = (struct pico_ipv4_hdr *)f->buffer;
    f->net_hdr = (uint8_t *)h4;
    f->buffer[0] = 0x40; /* IPv4 */

    TRYING("With IPv4 unicast addr\n");
    h4->dst = addr4;
    ret = destination_is_bcast(f);
    CHECKING(count);
    fail_unless(0 == ret, "Should've returned 0 since not an IPv4 mcast address\n");
    SUCCESS();

    TRYING("With IPv4 multicast addr\n");
    h4->dst = mcast4;
    ret = destination_is_mcast(f);
    CHECKING(count);
    fail_unless(1 == ret, "Should've returned 1 since an IPv4 multicast\n");
    SUCCESS();

    BREAKING();
    ret = destination_is_bcast(NULL);
    CHECKING(count);
    fail_unless(0 == ret, "Should've returned 0 since NULL-pointer\n");
    SUCCESS();

    ENDING(count);
}
END_TEST
START_TEST(tc_pico_ipv4_ethernet_receive)
{
   /* test this: static int32_t pico_ipv4_ethernet_receive(struct pico_frame *f) */
    struct pico_frame *f = NULL;
    struct pico_ipv4_hdr *h4 = NULL;
    int ret = 0, count = 0;

    STARTING();

    f = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    h4 = (struct pico_ipv4_hdr *)f->buffer;
    f->net_hdr = (uint8_t *)h4;
    f->buffer[0] = 0x40; /* IPv4 */

    TRYING("With IPv4 frame\n");
    ret = pico_ipv4_ethernet_receive(f);
    CHECKING(count);
    fail_unless(ret > 0, "Was correct frame should've returned size of frame\n");
    SUCCESS();
    CHECKING(count);
    fail_unless(pico_proto_ipv4.q_in->size == f->buffer_len, "Frame not enqueued\n");
    SUCCESS();

    ENDING(count);
}
END_TEST
START_TEST(tc_pico_ipv6_ethernet_receive)
{
   /* test this: static int32_t pico_ipv6_ethernet_receive(struct pico_frame *f) */
    struct pico_frame *f = NULL;
    struct pico_ipv6_hdr *h = NULL;

    int ret = 0, count = 0;

    STARTING();
    f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    h = (struct pico_ipv6_hdr *)f->buffer;
    f->net_hdr = (uint8_t*) h;
    f->buffer[0] = 0x40; /* Ipv6 */

    TRYING("With wrong network type\n");
    ret = pico_ipv6_ethernet_receive(f);
    CHECKING(count);
    fail_unless(ret == -1, "Wrong type should've returned an error\n");
    SUCCESS();

    f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    h = (struct pico_ipv6_hdr *)f->buffer;
    f->net_hdr = (uint8_t*) h;
    f->buffer[0] = 0x60;
    TRYING("With correct network type\n");
    ret = pico_ipv6_ethernet_receive(f);
    CHECKING(count);
    fail_unless(ret == (int32_t)f->buffer_len, "Was correct frame, should've returned success\n");
    SUCCESS();
    CHECKING(count);
    fail_unless(pico_proto_ipv6.q_in->size == f->buffer_len, "Frame not enqueued\n");
    SUCCESS();

    ENDING(count);
}
END_TEST
START_TEST(tc_pico_eth_receive)
{
    struct pico_frame *f = NULL;
    struct pico_eth_hdr *eth = NULL;
    int ret = 0, count = 0;

    STARTING();

    f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr) + sizeof(struct pico_eth_hdr));
    f->datalink_hdr = f->buffer;
    f->net_hdr = f->datalink_hdr + sizeof(struct pico_eth_hdr);
    eth = (struct pico_eth_hdr *)f->datalink_hdr;
    ((uint8_t *)(f->net_hdr))[0] = 0x40; /* Ipv4 */

    /* ETHERNET PROTOCOL : IPV6 */
    eth->proto = PICO_IDETH_IPV6;

    TRYING("With wrong network type\n");
    ret = pico_eth_receive(f);
    CHECKING(count);
    fail_unless(ret == -1, "Wrong type should've returned an error\n");
    SUCCESS();

    f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr) + sizeof(struct pico_eth_hdr));
    f->datalink_hdr = f->buffer;
    f->net_hdr = f->datalink_hdr + sizeof(struct pico_eth_hdr);
    eth = (struct pico_eth_hdr *)f->datalink_hdr;
    ((uint8_t *)(f->net_hdr))[0] = 0x60; /* Ipv6 */

    /* ETHERNET PROTOCOL : IPV6 */
    eth->proto = PICO_IDETH_IPV6;
    TRYING("With correct network type\n");
    ret = pico_eth_receive(f);
    CHECKING(count);
    fail_unless(ret == (int32_t)f->buffer_len, "Was correct frame, should've returned success\n");
    SUCCESS();
    CHECKING(count);
    fail_unless(pico_proto_ipv6.q_in->size == f->buffer_len, "Frame not enqueued\n");
    SUCCESS();

    pico_frame_discard(f);

    f = pico_frame_alloc(sizeof(struct pico_ipv4_hdr) + sizeof(struct pico_eth_hdr));
    f->datalink_hdr = f->buffer;
    f->net_hdr = f->datalink_hdr + sizeof(struct pico_eth_hdr);
    eth = (struct pico_eth_hdr *)f->datalink_hdr;
    ((uint8_t *)(f->net_hdr))[0] = 0x40; /* Ipv4 */

    TRYING("With wrong frame type\n");
    ret = pico_eth_receive(f);
    CHECKING(count);
    fail_unless(ret == -1, "should've returned -1 wrong ethernet protocol\n");
    SUCCESS();

    f = pico_frame_alloc(sizeof(struct pico_ipv4_hdr) + sizeof(struct pico_eth_hdr));
    f->datalink_hdr = f->buffer;
    f->net_hdr = f->datalink_hdr + sizeof(struct pico_eth_hdr);
    eth = (struct pico_eth_hdr *)f->datalink_hdr;
    ((uint8_t *)(f->net_hdr))[0] = 0x40; /* Ipv4 */
    eth->proto = PICO_IDETH_IPV4;

    TRYING("With IPv4 frame\n");
    ret = pico_eth_receive(f);
    CHECKING(count);
    fail_unless(ret > 0, "Was correct frame should've returned size of frame\n");
    SUCCESS();
    CHECKING(count);
    fail_unless(pico_proto_ipv4.q_in->size == f->buffer_len, "Frame not enqueued\n");
    SUCCESS();

    ENDING(count);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_destination_is_bcast = tcase_create("Unit test for destination_is_bcast");
    TCase *TCase_destination_is_mcast = tcase_create("Unit test for destination_is_mcast");
    TCase *TCase_pico_ipv4_ethernet_receive = tcase_create("Unit test for pico_ipv4_ethernet_receive");
    TCase *TCase_pico_ipv6_ethernet_receive = tcase_create("Unit test for pico_ipv6_ethernet_receive");
    TCase *TCase_pico_eth_receive = tcase_create("Unit test for pico_eth_receive");

    tcase_add_test(TCase_destination_is_bcast, tc_destination_is_bcast);
    suite_add_tcase(s, TCase_destination_is_bcast);
    tcase_add_test(TCase_destination_is_mcast, tc_destination_is_mcast);
    suite_add_tcase(s, TCase_destination_is_mcast);
    tcase_add_test(TCase_pico_ipv4_ethernet_receive, tc_pico_ipv4_ethernet_receive);
    suite_add_tcase(s, TCase_pico_ipv4_ethernet_receive);
    tcase_add_test(TCase_pico_ipv6_ethernet_receive, tc_pico_ipv6_ethernet_receive);
    suite_add_tcase(s, TCase_pico_ipv6_ethernet_receive);
    tcase_add_test(TCase_pico_eth_receive, tc_pico_eth_receive);
    suite_add_tcase(s, TCase_pico_eth_receive);
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
