#include "pico_tcp.c"
#include <check.h>

Suite *pico_suite(void);

START_TEST(tc_seq_compare)
{
    uint32_t big_a = 0xFFFFFF0alu;
    uint32_t big_b = 0xFFFFFF0blu;
    uint32_t small_a = 0xalu;
    uint32_t small_b = 0xblu;
    uint32_t under_thresh = 0x7ffffffflu;
    uint32_t over_thresh  = 0x80000000lu;
    uint32_t zero = 0lu;

    fail_if(pico_seq_compare(small_a, small_b) >= 0);
    fail_if(pico_seq_compare(small_b, small_a) <= 0);

    fail_if(pico_seq_compare(over_thresh, under_thresh) <= 0);
    fail_if(pico_seq_compare(under_thresh, over_thresh) >= 0);

    fail_if(pico_seq_compare(small_a, big_b) <= 0);
    fail_if(pico_seq_compare(big_b, small_a) >= 0);

    fail_if(pico_seq_compare(small_a, zero) <= 0);
    fail_if(pico_seq_compare(zero, small_a) >= 0);

    fail_if(pico_seq_compare(big_a, zero) >= 0);
    fail_if(pico_seq_compare(zero, big_a) <= 0);

    fail_if(pico_seq_compare(big_a, big_b) >= 0);
    fail_if(pico_seq_compare(big_b, big_a) <= 0);

    fail_if(pico_seq_compare(big_a, big_a) != 0);
    fail_if(pico_seq_compare(zero, zero) != 0);

}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("pico tcp sequence numbers");
    TCase *TCase_seq_compare = tcase_create("Unit test for pico_seq_compare");
    tcase_add_test(TCase_seq_compare, tc_seq_compare);
    suite_add_tcase(s, TCase_seq_compare);
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

