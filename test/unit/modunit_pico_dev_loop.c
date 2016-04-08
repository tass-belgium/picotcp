#include "modules/pico_dev_loop.c"
#include "check.h"
static int called = 0;
static int fail = 0;

Suite *pico_suite(void);

int pico_device_init(struct pico_device __attribute__((unused)) *dev, const char __attribute__((unused)) *name, const uint8_t __attribute__((unused)) *mac)
{
    if (fail)
        return -1;

    return 0;
}

void pico_device_destroy(struct pico_device *dev)
{
    dev = dev;
}

int32_t pico_stack_recv(struct pico_device __attribute__((unused)) *dev, uint8_t __attribute__((unused)) *buffer, uint32_t __attribute__((unused)) len)
{
    called = 1;
    return 1;
}

START_TEST(tc_pico_loop_send)
{
    uint8_t buf[LOOP_MTU + 1] = {};
    fail_if(pico_loop_send(NULL, buf, LOOP_MTU + 1) != 0);

    /* First send: OK */
    fail_if(pico_loop_send(NULL, buf, LOOP_MTU) != LOOP_MTU);

    /* Second: buffer busy */
    fail_if(pico_loop_send(NULL, buf, LOOP_MTU) != 0);

}
END_TEST

START_TEST(tc_pico_loop_poll)
{
    uint8_t buf[LOOP_MTU + 1] = {};
    fail_if(pico_loop_poll(NULL, 0) != 0);
    called = 0;
    /* First send: OK */
    fail_if(pico_loop_send(NULL, buf, LOOP_MTU) != LOOP_MTU);
    fail_if(pico_loop_poll(NULL, 1) != 0);
    fail_if(called == 0);
}
END_TEST

START_TEST(tc_pico_loop_create)
{

#ifdef PICO_FAULTY
    printf("Testing with faulty memory in pico_loop_create (1)\n");
    pico_set_mm_failure(1);
    fail_if(pico_loop_create() != NULL);
#endif
    fail = 1;
    fail_if(pico_loop_create() != NULL);
    fail = 0;
    fail_if(pico_loop_create() == NULL);

}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_loop_send = tcase_create("Unit test for pico_loop_send");
    TCase *TCase_pico_loop_poll = tcase_create("Unit test for pico_loop_poll");
    TCase *TCase_pico_loop_create = tcase_create("Unit test for pico_loop_create");


    tcase_add_test(TCase_pico_loop_send, tc_pico_loop_send);
    suite_add_tcase(s, TCase_pico_loop_send);
    tcase_add_test(TCase_pico_loop_poll, tc_pico_loop_poll);
    suite_add_tcase(s, TCase_pico_loop_poll);
    tcase_add_test(TCase_pico_loop_create, tc_pico_loop_create);
    suite_add_tcase(s, TCase_pico_loop_create);
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
