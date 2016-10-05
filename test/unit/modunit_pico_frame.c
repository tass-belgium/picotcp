#include "pico_config.h"
#include "pico_protocol.h"
#include "pico_frame.h"
#include "stack/pico_frame.c"
#include "check.h"

volatile pico_err_t pico_err;

#define FRAME_SIZE 1000

Suite *pico_suite(void);

START_TEST(tc_pico_frame_alloc_discard)
{
    struct pico_frame *f = pico_frame_alloc(FRAME_SIZE);

    /* Test consistency */
    fail_if(!f);
    fail_if(!f->buffer);
    fail_if(!f->usage_count);
    fail_if(*f->usage_count != 1);
    fail_if(f->start != f->buffer);
    fail_if(f->len != f->buffer_len);
    fail_if(f->len != FRAME_SIZE);
    pico_frame_discard(f);

    /* Test empty discard */
    pico_frame_discard(NULL);

#ifdef PICO_FAULTY
    printf("Testing with faulty memory in frame_alloc (1)\n");
    pico_set_mm_failure(1);
    f = pico_frame_alloc(FRAME_SIZE);
    fail_if(f);

    printf("Testing with faulty memory in frame_alloc (2)\n");
    pico_set_mm_failure(2);
    f = pico_frame_alloc(FRAME_SIZE);
    fail_if(f);

    printf("Testing with faulty memory in frame_do_alloc, with external buffer, failing to allocate usage_count \n");
    pico_set_mm_failure(2);
    f = pico_frame_do_alloc(FRAME_SIZE, 1, 1);
    fail_if(f);
#endif
    printf("Testing frame_do_alloc, with invalid flags combination\n");
    f = pico_frame_do_alloc(FRAME_SIZE, 0, 1);
    fail_if(f);

}
END_TEST

START_TEST(tc_pico_frame_grow_head)
{
    struct pico_frame *f = pico_frame_alloc(3);
    struct pico_frame *f2 = pico_frame_alloc(0);
    int ret = 0;
    uint8_t buf[6] = { 0, 0, 0, 'a', 'b', 'c'};

    /* I don't care about usage_count, it's tested 'pico_frame_grow' */
    fail_if(pico_frame_grow_head(f, 2) == 0);

    /* Check for dereferencing OOB */
    fail_if(pico_frame_grow_head(f2, 2) == -1);
    f2->net_hdr[0] = 1;

    f->net_hdr = f->buffer;
    f->net_len = 3;
    f->net_hdr[0] = 'a';
    f->net_hdr[1] = 'b';
    f->net_hdr[2] = 'c';

    /* Try to grow head */
    ret = pico_frame_grow_head(f, 6);
    fail_if(ret != 0);
    fail_unless(0 == memcmp(f->buffer, buf, f->buffer_len));
    fail_unless(3 == f->net_hdr - f->buffer);

    f->datalink_hdr = f->net_hdr - 3;
    f->datalink_hdr[0] = 1;
}
END_TEST

START_TEST(tc_pico_frame_grow)
{
    struct pico_frame *f = pico_frame_alloc(3);
    struct pico_frame *f2 = pico_frame_alloc(0);
    fail_if(f->buffer_len != 3);
    /* Ensure that the usage_count starts at byte 4, for good alignment */
    fail_if(((void*)f->usage_count - (void *)f->buffer) != 4);

    ((uint8_t *)f->buffer)[0] = 'a';
    ((uint8_t *)f->buffer)[1] = 'b';
    ((uint8_t *)f->buffer)[2] = 'c';
    *f->usage_count = 12;


    /* First, the failing cases. */
    fail_if(pico_frame_grow(NULL, 30) == 0);
    fail_if(pico_frame_grow(f, 2) == 0);
    f->flags = 0;

    /* Check for dereferencing OOB */
    fail_if(pico_frame_grow(f2, 3) != 0);
    f2->net_hdr[0] = 1;
    f2->net_hdr[1] = 2;

    pico_set_mm_failure(1);
    fail_if(pico_frame_grow(f, 21) == 0);

    /* Now, the good one. */
    fail_if(pico_frame_grow(f, 21) != 0);
    fail_if(f->buffer_len != 21);
    fail_if(((void *)f->usage_count - (void *)f->buffer) != 24);


    fail_if(((uint8_t *)f->buffer)[0] != 'a');
    fail_if(((uint8_t *)f->buffer)[1] != 'b');
    fail_if(((uint8_t *)f->buffer)[2] != 'c');
    fail_if(*f->usage_count != 12);

    *f->usage_count = 1;
    pico_frame_discard(f);

    f = pico_frame_alloc_skeleton(10, 1);
    fail_if(!f);
    fail_if(f->buffer);
    fail_if(!f->flags);
    f->buffer = PICO_ZALLOC(10);

    fail_if(pico_frame_grow(f, 22) != 0);
    fail_if (f->flags);
    pico_frame_discard(f);

}
END_TEST

START_TEST(tc_pico_frame_copy)
{
    struct pico_frame *f = pico_frame_alloc(FRAME_SIZE);
    struct pico_frame *c1, *c2, *c3;
    (void)c3;
    fail_if(!f);
    fail_if(!f->buffer);
    fail_if(*f->usage_count != 1);

    /* First copy */
    c1 = pico_frame_copy(f);
    fail_if(!c1);
    fail_if(!c1->buffer);
    fail_if(!c1->usage_count);

    fail_if (c1->buffer != f->buffer);
    fail_if(c1->usage_count != f->usage_count);
    fail_if(*c1->usage_count != 2);
    fail_if(*f->usage_count != 2);
    fail_if(c1->start != c1->buffer);
    fail_if(c1->len != c1->buffer_len);
    fail_if(c1->len != FRAME_SIZE);

    /* Second copy */
    c2 = pico_frame_copy(f);
    fail_if (c2->buffer != f->buffer);
    fail_if(c2->usage_count != f->usage_count);
    fail_if(*c2->usage_count != 3);
    fail_if(*f->usage_count != 3);
    fail_if(c2->start != c2->buffer);
    fail_if(c2->len != c2->buffer_len);
    fail_if(c2->len != FRAME_SIZE);


#ifdef PICO_FAULTY
    printf("Testing with faulty memory in frame_copy (1)\n");
    pico_set_mm_failure(1);
    c3 = pico_frame_copy(f);
    fail_if(c3);
    fail_if(!f);
#endif

    /* Discard 1 */
    pico_frame_discard(c1);
    fail_if(*f->usage_count != 2);

    /* Discard 2 */
    pico_frame_discard(c2);
    fail_if(*f->usage_count != 1);

    pico_frame_discard(f);

}
END_TEST

START_TEST(tc_pico_frame_deepcopy)
{
    struct pico_frame *f = pico_frame_alloc(FRAME_SIZE);
    struct pico_frame *dc = pico_frame_deepcopy(f);
    fail_if(*f->usage_count != 1);
    fail_if(*dc->usage_count != 1);
    fail_if(dc->buffer == f->buffer);
#ifdef PICO_FAULTY
    printf("Testing with faulty memory in frame_deepcopy (1)\n");
    pico_set_mm_failure(1);
    dc = pico_frame_deepcopy(f);
    fail_if(dc);
    fail_if(!f);
#endif
}
END_TEST

START_TEST(tc_pico_is_digit)
{
    fail_if(pico_is_digit('a'));
    fail_if(pico_is_digit('Z'));
    fail_if(pico_is_digit('\0'));
    fail_if(pico_is_digit('\n'));
    fail_if(pico_is_digit('0' - 1));
    fail_if(pico_is_digit('9' + 1));
    fail_unless(pico_is_digit('0'));
    fail_unless(pico_is_digit('9'));
}
END_TEST


START_TEST(tc_pico_is_hex)
{
    fail_if(pico_is_hex('g'));
    fail_if(pico_is_hex('Z'));
    fail_if(pico_is_hex('\0'));
    fail_if(pico_is_hex('\n'));
    fail_if(pico_is_hex('0' - 1));
    fail_if(pico_is_hex('f' + 1));
    fail_if(pico_is_hex('F' + 1));
    fail_unless(pico_is_hex('0'));
    fail_unless(pico_is_hex('f'));
    fail_unless(pico_is_hex('A'));
    fail_unless(pico_is_hex('F'));
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("pico_frame.c");
    TCase *TCase_pico_frame_alloc_discard = tcase_create("Unit test for pico_frame_alloc_discard");
    TCase *TCase_pico_frame_copy = tcase_create("Unit test for pico_frame_copy");
    TCase *TCase_pico_frame_grow = tcase_create("Unit test for pico_frame_grow");
    TCase *TCase_pico_frame_grow_head = tcase_create("Unit test for pico_frame_grow_head");
    TCase *TCase_pico_frame_deepcopy = tcase_create("Unit test for pico_frame_deepcopy");
    TCase *TCase_pico_is_digit = tcase_create("Unit test for pico_is_digit");
    TCase *TCase_pico_is_hex = tcase_create("Unit test for pico_is_hex");
    tcase_add_test(TCase_pico_frame_alloc_discard, tc_pico_frame_alloc_discard);
    tcase_add_test(TCase_pico_frame_copy, tc_pico_frame_copy);
    tcase_add_test(TCase_pico_frame_grow, tc_pico_frame_grow);
    tcase_add_test(TCase_pico_frame_grow_head, tc_pico_frame_grow_head);
    tcase_add_test(TCase_pico_frame_deepcopy, tc_pico_frame_deepcopy);
    tcase_add_test(TCase_pico_is_digit, tc_pico_is_digit);
    tcase_add_test(TCase_pico_is_hex, tc_pico_is_hex);
    suite_add_tcase(s, TCase_pico_frame_alloc_discard);
    suite_add_tcase(s, TCase_pico_frame_copy);
    suite_add_tcase(s, TCase_pico_frame_grow);
    suite_add_tcase(s, TCase_pico_frame_grow_head);
    suite_add_tcase(s, TCase_pico_frame_deepcopy);
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
