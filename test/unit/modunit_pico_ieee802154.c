#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "modules/pico_ieee802154.c"
#include "check.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//===----------------------------------------------------------------------===//
//  MACROS
//===----------------------------------------------------------------------===//

#define STARTING()                                                             \
            printf("*********************** STARTING %s ***\n", __func__);     \
            fflush(stdout)
#define TRYING(s, ...)                                                         \
            printf("Trying %s: " s, __func__, ##__VA_ARGS__);                  \
            fflush(stdout)
#define CHECKING(i)                                                            \
            printf("Checking the results of test %2d in %s...", (i)++,        \
                   __func__);                                                  \
            fflush(stdout)
#define SUCCESS()                                                              \
            printf(" SUCCES\n");                                               \
            fflush(stdout)
#define BREAKING(s, ...)                                                       \
            printf("Breaking %s: " s, __func__, ##__VA_ARGS__);                \
            fflush(stdout)
#define ENDING(i)                                                              \
            printf("*********************** ENDING %s *** NUMBER OF TESTS: %d\n",\
                   __func__, ((i)-1));                                         \
            fflush(stdout)
#define DBG(s, ...)                                                            \
            printf(s, ##__VA_ARGS__);                                          \
            fflush(stdout)

//===----------------------------------------------------------------------===//
//  HELPER FUNCTIONS
//===----------------------------------------------------------------------===//

static void dbg_addr_short(const char *msg, uint16_t a)
{
    DBG("%s: (16-bit short address): ", msg);
    DBG("0x%04X\n",a);
}

static void dbg_addr_ext(const char *msg, uint8_t a[PICO_SIZE_IEEE802154_EXT])
{
    DBG("%s: (64-bit extended address): ", msg);
    DBG("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
        a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
}

static void dbg_addr(const char *msg, struct pico_ieee802154_addr *addr)
{
    if (IEEE802154_AM_SHORT == addr->mode) {
        dbg_addr_short(msg, addr->addr._short.addr);
    } else if (IEEE802154_AM_EXTENDED == addr->mode) {
        dbg_addr_ext(msg, addr->addr._ext.addr);
    } else {
        DBG("*** ERROR *** - address has unsupported address mode\n");
    }
}

//===----------------------------------------------------------------------===//
//  STUBS
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  ADDRESSES
//===----------------------------------------------------------------------===//

START_TEST(tc_ieee802154_addr_cmp)
{
    struct pico_ieee802154_addr a = {.addr._short.addr = 0x3210,
                                     .mode = IEEE802154_AM_NONE};
    struct pico_ieee802154_addr b = {.addr._short.addr = 0x1234,
                                     .mode = IEEE802154_AM_SHORT};
    int ret = 0;
    int test = 1;
    STARTING();

    /// TEST 1
    TRYING("With a.mode = NONE & b.mode = SHORT: a < b --> ret < 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    fail_if(ret >= 0, "a is smaller then b, should return negative number\n");
    SUCCESS();

    /// TEST 2
    a.mode = IEEE802154_AM_SHORT;
    TRYING("With a.mode = SHORT & b.mode = SHORT: a > b --> ret > 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    fail_if(ret <= 0, "a is larger then b, should return positive number\n");
    SUCCESS();

    /// TEST 3
    a.addr._short.addr = 0x1234;
    TRYING("With a = 0x1234 & b = 0x1234: a == b --> ret = 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    fail_unless(ret == 0, "a is equal to b, should return zero\n");
    SUCCESS();

    /// TEST 4
    b.mode = IEEE802154_AM_EXTENDED;
    TRYING("With a.mode = SHORT & b.mode = EXT: a < b --> ret < 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    fail_if(ret >= 0, "a is smaller then b, should return negative number\n");
    SUCCESS();

    /// TEST 5
    a.mode = IEEE802154_AM_EXTENDED;
    TRYING("With a.mode = EXT & b.mode = EXT: a == b --> ret = 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    fail_unless(ret == 0, "a is equal to b, should return zero\n");
    SUCCESS();

    /// TEST 6
    a.addr._short.addr = 0x3210;
    TRYING("With a = 0x3210... & b = 0x1230...: a > b --> ret > 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING(test);
    fail_if(ret <= 0, "a is larger then b, should return positive number\n");
    SUCCESS();

    ENDING(test);
}
END_TEST

START_TEST(tc_ieee802154_addr_to_le)
{
    struct pico_ieee802154_addr a = {.addr._short.addr = 0x1234,
                                     .mode = IEEE802154_AM_SHORT};
    uint8_t buf[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34};
    int test = 1;
    STARTING();

    /// TEST 1
    TRYING("With a = 0x1234: little endian -> {0x34, 0x12}\n");
    DBG("before: {0x%02X, 0x%02X}\n", a.addr._ext.addr[0], a.addr._ext.addr[1]);
    pico_ieee802154_addr_to_le(&a);
    DBG("result: {0x%02X, 0x%02X}\n", a.addr._ext.addr[0], a.addr._ext.addr[1]);
    CHECKING(test);
    fail_if(a.addr._ext.addr[0] != 0x34 &&
            a.addr._ext.addr[1] != 0x12,
            "Failed converting 16-bit short address to little endian\n");
    SUCCESS();

    /// TEST 2
    a.mode = IEEE802154_AM_EXTENDED;
    TRYING("With extended address -> little endian: {0x00, 0x00, .., 0x12, 0x34}\n");
    pico_ieee802154_addr_to_le(&a);
    dbg_addr("Address", &a);
    CHECKING(test);
    fail_unless(0 == memcmp(buf, a.addr._ext.addr, 8),
                "Failed converting 64-bit short address to little endian\n");
    SUCCESS();

    /// TEST 3
    a.mode = IEEE802154_AM_NONE;
    TRYING("With wrong address mode -> buffer should be left unchanged\n");
    pico_ieee802154_addr_to_le(&a);
    dbg_addr("Address", &a);
    CHECKING(test);
    fail_unless(0 == memcmp(buf, a.addr._ext.addr, 8),
                "Failed leaving address buffer alone with unsupported AM\n");
    SUCCESS();

    ENDING(test);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

//===----------------------------------------------------------------------===//
//  ADDRESSES
//===----------------------------------------------------------------------===//

    TCase *TCase_ieee802154_addr_cmp = tcase_create("Unit test for ieee802154_addr_cmp");
    tcase_add_test(TCase_ieee802154_addr_cmp, tc_ieee802154_addr_cmp);
    suite_add_tcase(s, TCase_ieee802154_addr_cmp);

    TCase *TCase_ieee802154_addr_to_le = tcase_create("Unit test for ieee802154_addr_to_le");
    tcase_add_test(TCase_ieee802154_addr_to_le, tc_ieee802154_addr_to_le);
    suite_add_tcase(s, TCase_ieee802154_addr_to_le);

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
