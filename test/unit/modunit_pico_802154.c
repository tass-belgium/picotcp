#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "pico_6lowpan.h"
#include "modules/pico_802154.c"
#include "check.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*******************************************************************************
 *  MACROS
 ******************************************************************************/

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
#define FAIL_UNLESS(cond, s, ...)                                              \
            if ((cond)) {                                                      \
                printf(" SUCCESS\n");                                          \
            } else {                                                           \
                printf(" FAILED\n");                                           \
            }                                                                  \
            fail_unless((cond), s, ##__VA_ARGS__)
#define FAIL_IF(cond, s, ...)                                                  \
            if (!(cond)) {                                                     \
                printf(" SUCCESS\n");                                          \
            } else {                                                           \
                printf(" FAILED\n");                                           \
            }                                                                  \
            fail_if((cond), s, ##__VA_ARGS__)
#define ENDING(i)                                                              \
            printf("*********************** ENDING %s *** NUMBER OF TESTS: %d\n",\
                   __func__, ((i)-1));                                         \
            fflush(stdout)
#define DBG(s, ...)                                                            \
            printf(s, ##__VA_ARGS__);                                          \
            fflush(stdout)

/*******************************************************************************
 *  HELPER FUNCTIONS
 ******************************************************************************/

static void dbg_addr_ext(const char *msg, uint8_t a[SIZE_6LOWPAN_EXT])
{
    DBG("%s: (64-bit extended address): ", msg);
    DBG("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
        a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
}

/*******************************************************************************
 *  ADDRESSES
 ******************************************************************************/

START_TEST(tc_swap)
{
    int test = 1;
    uint8_t a = 5;
    uint8_t b = 1;

    STARTING();

    // TEST 1
    TRYING("With a = %d and b = %d\n", a, b);
    pico_swap(&a, &b);
    CHECKING(test);
    FAIL_IF(1 != a && b != 5, "Failed swapping numbers\n");

    ENDING(test);
}
END_TEST

START_TEST(tc_802154_to_ietf)
{
    int test = 1;
    struct pico_802154 a = {
        .addr.data = { 1,2,3,4,5,6,7,8 },
        .mode = AM_6LOWPAN_EXT
    };
    uint8_t buf[] = {8,7,6,5,4,3,2,1};

    STARTING();

    // TEST 1
    TRYING("Extended address mode\n");
    addr_802154_to_ietf(&a);
    dbg_addr_ext("After", a.addr.data);
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(a.addr.data, buf, SIZE_6LOWPAN_EXT),
                "Failed converting to IETF endianness\n");

    // TEST 2
    TRYING("Short address mode\n");
    a.mode = AM_6LOWPAN_SHORT;
    addr_802154_to_ietf(&a);
    dbg_addr_ext("After", a.addr.data);
    CHECKING(test);
    FAIL_UNLESS(a.addr._short.addr == short_be(0x0708),
                "Failed converting short to IETF endianness\n");

    // TEST 3
    TRYING("Wrong address mode\n");
    a.mode = AM_6LOWPAN_NONE;
    addr_802154_to_ietf(&a);
    dbg_addr_ext("After", a.addr.data);
    buf[0] = 7;
    buf[1] = 8;
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(a.addr.data, buf, SIZE_6LOWPAN_EXT),
                "Should've done nothing\n");

    ENDING(test);

}
END_TEST

START_TEST(tc_802154_ll_src)
{
    int test = 1;
    struct pico_ip6 ip = {
        .addr = {0,0,0,0,0,0,0,0, 3,2,3,4,5,6,7,8}
    };
    struct pico_ip6 ip2 = {
        .addr = {0,0,0,0,0,0,0,0, 0,0,0,0xff,0xfe,0,0x12,0x34}
    };
    struct pico_6lowpan_info info = {
        .addr_short.addr = short_be(0x1234),
        .addr_ext.addr = {3,2,3,4,5,6,7,8}
    };
    struct pico_device dev;
    struct pico_802154 addr;
    struct pico_frame *f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->buffer;

    STARTING();

    dev.eth = (struct pico_ethdev *)&info;
    f->net_hdr = f->buffer;
    f->dev = &dev;
    dev.hostvars.lowpan_flags = PICO_6LP_FLAG_LOWPAN;

    // TEST 3
    TRYING("With an IPv6 address that is derived from MAC short address\n");
    info.addr_short.addr = short_be(0x1234);
    hdr->src = ip2;
    addr = addr_802154_ll_src(f);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_SHORT == addr.mode,
                "Should've returned device's short address \n");
    CHECKING(test);
    FAIL_UNLESS(short_be(0x1234) == addr.addr._short.addr,
                "Should've copied the short address from the device\n");

    // TEST 4
    TRYING("With an IPv6 address that is derived from MAC extended address\n");
    ip.addr[8] = 1;
    hdr->src = ip;
    addr = addr_802154_ll_src(f);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_EXT == addr.mode,
                "Should've returned device's extended address\n");
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(info.addr_ext.addr, addr.addr._ext.addr, SIZE_6LOWPAN_EXT),
                "Should've copied device's extended address\n");

    ENDING(test);
}
END_TEST

START_TEST(tc_802154_ll_dst)
{
    int test = 1;
    struct pico_ip6 ip;
    struct pico_ip6 local;
    struct pico_ip6 local2;
    struct pico_802154 addr;
    struct pico_frame *f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->buffer;
    struct pico_device dev;
    uint8_t buf[] = {3,2,3,4,5,6,7,8};
    pico_string_to_ipv6("ff00:0:0:0:0:0:e801:100", ip.addr);
    pico_string_to_ipv6("fe80:0:0:0:0102:0304:0506:0708", local.addr);
    pico_string_to_ipv6("fe80:0:0:0:0:0ff:fe00:1234", local2.addr);

    STARTING();

    f->net_hdr = f->buffer;
    f->dev = &dev;
    dev.hostvars.lowpan_flags = PICO_6LP_FLAG_LOWPAN;

    // TEST 1
    TRYING("With a MCAST IPv6 address, should return 0xFFFF\n");
    hdr->dst = ip;
    addr = addr_802154_ll_dst(f);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_SHORT == addr.mode,
                "Should've set address mode to SHORT\n");
    CHECKING(test);
    FAIL_UNLESS(short_be(ADDR_802154_BCAST) == addr.addr._short.addr,
                "Should've set address to BCAST\n");

    // TEST 2
    TRYING("With a link local IPv6 address derived from an extended L2 address\n");
    hdr->dst = local;
    addr = addr_802154_ll_dst(f);
    dbg_addr_ext("After:", addr.addr._ext.addr);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_EXT == addr.mode,
                "Should've set address mode to EXTENDED\n");
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(buf, addr.addr._ext.addr, SIZE_6LOWPAN_EXT),
                "Should've copied the extended address from the IP address\n");

    // TEST 3
    TRYING("With a link local IPv6 address derived from a short L2 address\n");
    hdr->dst = local2;
    addr = addr_802154_ll_dst(f);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_SHORT == addr.mode,
                "Should've set address mode to SHORT\n");
    CHECKING(test);
    FAIL_UNLESS(short_be(0x1234) == addr.addr._short.addr,
                "Should've copied the short address from the IP address\n");

    /* TODO: Test getting address from neighbour table */

    ENDING(test);
}
END_TEST

/*******************************************************************************
 *  FRAME
 ******************************************************************************/

/* Frame (123 bytes) */
static uint8_t pkt[] = {
0x41, 0xcc, 0xa6, 0xff, 0xff, 0x8a,       /*   A..... */
0x18, 0x00, 0xff, 0xff, 0xda, 0x1c, 0x00, 0x88, /* ........ */
0x18, 0x00, 0xff, 0xff, 0xda, 0x1c, 0x00, 0xc1, /* ........ */
0x09, 0x00, 0x02, 0x42, 0xfa, 0x40, 0x04, 0x01, /* ...B.@.. */
0xf0, 0xb1, 0x01, 0x06, 0x6f, 0xaf, 0x48, 0x65, /* ....o.He */
0x6c, 0x6c, 0x6f, 0x20, 0x30, 0x30, 0x36, 0x20, /* llo 006  */
0x30, 0x78, 0x46, 0x46, 0x33, 0x43, 0x0a, 0x00, /* 0xFF3C.. */
0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, /* ........ */
0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, /* ...... ! */
0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, /* "#$%&'() */
0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, /* *+,-./01 */
0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, /* 23456789 */
0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, /* :;<=>?@A */
0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, /* BCDEFGHI */
0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, /* JKLMNOPQ */
0x52, 0x53, 0x54, 0x68, 0x79                    /* RSThy */
};

START_TEST(tc_dst_am)
{
    int test = 1;
    int ret = 0;

    STARTING();

    // TEST 1
    TRYING("Trying to determine AM of destination addr from buffer \n");
    ret = dst_am((struct pico_802154_hdr *)pkt);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_EXT == ret,
                "Should've returned the AM of an extended address\n");

    ENDING(test);
}
END_TEST

START_TEST(tc_src_am)
{
    int test = 1;
    int ret = 0;

    STARTING();

    // TEST 1
    TRYING("Trying to determine AM of source addr from buffer \n");
    ret = src_am((struct pico_802154_hdr *)pkt);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_EXT == ret,
                "Should've returned the AM of an extended address\n");

    ENDING(test);
}
END_TEST

START_TEST(tc_802154_hdr_len)
{
    int test = 1;
    int ret = 0;

    STARTING();

    // TEST 1
    TRYING("Trying to determine length of the header from buffer\n");
    ret = frame_802154_hdr_len((struct pico_802154_hdr *)pkt);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    FAIL_UNLESS(21 == ret,
                "Should've returned the correct length of the header\n");

    ENDING(test);
}
END_TEST

START_TEST(tc_802154_src)
{
    int test = 1;
    struct pico_802154_hdr *hdr;
    struct pico_802154 addr;
    uint8_t src[] = {0x00, 0x1C, 0xDA, 0xFF, 0xFF, 0x00, 0x18, 0x88};
    STARTING();

    hdr = (struct pico_802154_hdr *)pkt;

    // TEST 1
    TRYING("To receive the source address from a mapped buffer\n");
    addr = frame_802154_src(hdr);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_EXT == addr.mode,
                "Should've returned an extended address\n");
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(src, addr.addr._ext.addr, SIZE_6LOWPAN_EXT),
                "Should've copied the extended source address\n");

    ENDING(test);
}
END_TEST

START_TEST(tc_802154_dst)
{
    int test = 1;
    struct pico_802154_hdr *hdr;
    struct pico_802154 addr;
    uint8_t dst[] = {0x00, 0x1C, 0xDA, 0xFF, 0xFF, 0x00, 0x18, 0x8a};

    STARTING();
    hdr = (struct pico_802154_hdr *)pkt;

    // TEST 1
    TRYING("To receive the source address from a mapped buffer\n");
    addr = frame_802154_dst(hdr);
    CHECKING(test);
    FAIL_UNLESS(AM_6LOWPAN_EXT == addr.mode,
                "Should've returned an extended address\n");
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(dst, addr.addr._ext.addr, SIZE_6LOWPAN_EXT),
                "Should've copied the extended source address\n");

    ENDING(test);
}
END_TEST

START_TEST(tc_802154_format)
{
    int test = 1;
    struct pico_802154 src = {
        .addr.data = {0x00, 0x1C, 0xDA, 0xFF, 0xFF, 0x00, 0x18, 0x88},
        .mode = AM_6LOWPAN_EXT
    };
    struct pico_802154 dst = {
        .addr.data = {0x00, 0x1C, 0xDA, 0xFF, 0xFF, 0x00, 0x18, 0x8a},
        .mode = AM_6LOWPAN_EXT
    };
    struct pico_6lowpan_short pan = { .addr = short_be(0xffff) };
    uint8_t buf[127] = {0};
    int i = 0;

    STARTING();

    // TEST 1
    TRYING("To format a frame like sample capture\n");
    frame_802154_format(buf, 166, FCF_INTRA_PAN, FCF_NO_ACK_REQ,
                        FCF_NO_SEC, pan, src, dst);
    printf("Buffer:");
    for (i = 0; i < 21; i++) {
        if (i % 8 != 0)
            printf("%02x ", buf[i]);
        else {
            printf("\n%02x ", buf[i]);
        }
    }
    printf("\n");
    CHECKING(test);
    FAIL_UNLESS(21 == frame_802154_hdr_len((struct pico_802154_hdr *)buf),
                "Failed to correctly set the frame header, the length isn't right\n");
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(pkt, buf, 21),
                "Failed to correctly format IEEE802.15.4 frame\n");

    ENDING(test);
}
END_TEST
START_TEST(tc_802154_process_out)
{
    int i = 0;
    int ret = 0;
    int test = 1;
    struct pico_802154 src = {
        .addr.data = {3,2,3,4,5,6,7,8},
        .mode = AM_6LOWPAN_EXT
    };
    struct pico_802154 dst = {
        .addr.data = {0x00, 0x1C, 0xDA, 0xFF, 0xFF, 0x00, 0x18, 0x8a},
        .mode = AM_6LOWPAN_EXT
    };
    struct pico_frame *f = pico_frame_alloc(0);
    struct pico_6lowpan_info info = {
        .addr_short.addr = short_be(0x1234),
        .addr_ext.addr = {3,2,3,4,5,6,7,8},
        .pan_id.addr = short_be(0x1234)
    };
    struct pico_device dev;
    uint8_t buf[] = {0x41,0xcc,0x00,0x34,0x12,0x8a,0x18,0x00,
                     0xff,0xff,0xda,0x1c,0x00,0x08,0x07,0x06,
                     0x05,0x04,0x03,0x02,0x03};
    dev.eth = (struct pico_ethdev *)&info;
    dev.q_out = PICO_ZALLOC(sizeof(struct pico_queue));
    f->dev = &dev;
    dev.hostvars.lowpan_flags = PICO_6LP_FLAG_LOWPAN;

    STARTING();
    pico_stack_init();

    // TEST 1
    TRYING("Trying with bare frame\n");
    f->src.pan = src;
    f->dst.pan = dst;
    ret = pico_802154_process_out(f);
    printf("Buffer:");
    for (i = 0; i < 21; i++) {
        if (i % 8 != 0)
            printf("%02x ", f->datalink_hdr[i]);
        else {
            printf("\n%02x ", f->datalink_hdr[i]);
        }
    }
    printf("\n");
    CHECKING(test);
    FAIL_UNLESS(0 < ret, "Shouldn't have returned an error\n");
    CHECKING(test);
    FAIL_UNLESS(0 == memcmp(buf, f->datalink_hdr, 21),
                "Frame isn't correctly formatted\n");

    pico_frame_discard(f);

    ENDING(test);
}
END_TEST
START_TEST(tc_802154_process_in)
{
    int ret = 0;
    int test = 1;
    struct pico_802154 src = {
        .addr.data = {3,2,3,4,5,6,7,8},
        .mode = AM_6LOWPAN_EXT
    };
    struct pico_802154 dst = {
        .addr.data = {0x00, 0x1C, 0xDA, 0xFF, 0xFF, 0x00, 0x18, 0x8a},
        .mode = AM_6LOWPAN_EXT
    };
    struct pico_frame *f = pico_frame_alloc(22);
    uint8_t buf[] = {0x41,0xcc,0x00,0x34,0x12,0x8a,0x18,0x00,
                     0xff,0xff,0xda,0x1c,0x00,0x08,0x07,0x06,
                     0x05,0x04,0x03,0x02,0x03,0x60};
    memcpy(f->buffer, buf, 22);
    f->src.pan = src;
    f->dst.pan = dst;

    STARTING();
    pico_stack_init();

    TRYING("Apply processing function on predefined buffer\n");
    ret = pico_802154_process_in(f);
    CHECKING(test);
    FAIL_UNLESS(0 < ret, "Should not return failure\n");
}
END_TEST
static Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_swap = tcase_create("Unit test for pico_swap");
    TCase *TCase_802154_to_ietf = tcase_create("Unit test for 802154_to_ietf");
    TCase *TCase_802154_ll_src = tcase_create("Unit test for 802154_ll_src");
    TCase *TCase_802154_ll_dst = tcase_create("Unit test for 802154_ll_dst");
    TCase *TCase_802154_hdr_len = tcase_create("Unit test for 802154_hdr_len");
    TCase *TCase_src_am = tcase_create("Unit test for src_am");
    TCase *TCase_dst_am = tcase_create("Unit test for dst_am");
    TCase *TCase_802154_src = tcase_create("Unit test for 802154_src");
    TCase *TCase_802154_dst = tcase_create("Unit test for 802154_dst");
    TCase *TCase_802154_format = tcase_create("Unit test for 802154_format");
    TCase *TCase_802154_process_out = tcase_create("Unit test for 802154_process_out");
    TCase *TCase_802154_process_in = tcase_create("Unit test for 802154_process_in");

/*******************************************************************************
 *  ADDRESSES
 ******************************************************************************/
    tcase_add_test(TCase_swap, tc_swap);
    suite_add_tcase(s, TCase_swap);
    tcase_add_test(TCase_802154_to_ietf, tc_802154_to_ietf);
    suite_add_tcase(s, TCase_802154_to_ietf);
    tcase_add_test(TCase_802154_ll_src, tc_802154_ll_src);
    suite_add_tcase(s, TCase_802154_ll_src);
    tcase_add_test(TCase_802154_ll_dst, tc_802154_ll_dst);
    suite_add_tcase(s, TCase_802154_ll_dst);

/*******************************************************************************
 *  FRAME
 ******************************************************************************/
    tcase_add_test(TCase_802154_hdr_len, tc_802154_hdr_len);
    suite_add_tcase(s, TCase_802154_hdr_len);
    tcase_add_test(TCase_src_am, tc_src_am);
    suite_add_tcase(s, TCase_src_am);
    tcase_add_test(TCase_dst_am, tc_dst_am);
    suite_add_tcase(s, TCase_dst_am);
    tcase_add_test(TCase_802154_src, tc_802154_src);
    suite_add_tcase(s, TCase_802154_src);
    tcase_add_test(TCase_802154_dst, tc_802154_dst);
    suite_add_tcase(s, TCase_802154_dst);
    tcase_add_test(TCase_802154_format, tc_802154_format);
    suite_add_tcase(s, TCase_802154_format);
    tcase_add_test(TCase_802154_process_out, tc_802154_process_out);
    suite_add_tcase(s, TCase_802154_process_out);
    tcase_add_test(TCase_802154_process_in, tc_802154_process_in);
    suite_add_tcase(s, TCase_802154_process_in);

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
