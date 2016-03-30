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
#define CHECKING()                                                             \
            printf("Checking the results for %s...", __func__);              \
            fflush(stdout)
#define SUCCESS()                                                              \
            printf(" SUCCES\n");                                               \
            fflush(stdout)
#define BREAKING(s, ...)                                                       \
            printf("Breaking %s: " s, __func__, ##__VA_ARGS__);                \
            fflush(stdout)
#define ENDING()                                                               \
            printf("*********************** ENDING %s ***\n",__func__);        \
            fflush(stdout)
#define DBG(s, ...)                                                            \
            printf(s, ##__VA_ARGS__);                                          \
            fflush(stdout)

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
    STARTING();

    TRYING("With a.mode = NONE & b.mode = SHORT: a < b --> ret < 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING();
    fail_if(ret >= 0, "a is smaller then b, should return negative number\n");
    SUCCESS();

    a.mode = IEEE802154_AM_SHORT;
    TRYING("With a.mode = SHORT & b.mode = SHORT: a > b --> ret > 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING();
    fail_if(ret <= 0, "a is larger then b, should return positive number\n");
    SUCCESS();

    a.addr._short.addr = 0x1234;
    TRYING("With a = 0x1234 & b = 0x1234: a == b --> ret = 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING();
    fail_unless(ret == 0, "a is equal to b, should return zero\n");
    SUCCESS();

    b.mode = IEEE802154_AM_EXTENDED;
    TRYING("With a.mode = SHORT & b.mode = EXT: a < b --> ret < 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING();
    fail_if(ret >= 0, "a is smaller then b, should return negative number\n");
    SUCCESS();

    a.mode = IEEE802154_AM_EXTENDED;
    TRYING("With a.mode = EXT & b.mode = EXT: a == b --> ret = 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING();
    fail_unless(ret == 0, "a is equal to b, should return zero\n");
    SUCCESS();

    a.addr._short.addr = 0x3210;
    TRYING("With a = 0x3210... & b = 0x1230...: a > b --> ret > 0\n");
    ret = pico_ieee802154_addr_cmp(&a, &b);
    DBG("ret = %d\n", ret);
    CHECKING();
    fail_if(ret <= 0, "a is larger then b, should return positive number\n");
    SUCCESS();

    ENDING();
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
