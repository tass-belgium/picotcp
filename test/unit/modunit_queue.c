#include "pico_frame.h"
#include "pico_queue.h"
#include "stack/pico_frame.c"
#include "pico_stack.h"
#include "check.h"


Suite *pico_suite(void);

struct pico_queue q1 = {
    0
}, q2 = {
    0
};

START_TEST(tc_q)
{
    struct pico_frame *f0 = pico_frame_alloc(100);
    struct pico_frame *f1 = pico_frame_alloc(100);
    struct pico_frame *f2 = pico_frame_alloc(100);
    struct pico_frame *f3 = pico_frame_alloc(100);
    struct pico_frame *f4 = pico_frame_alloc(100);

    pico_queue_protect(&q1);

    q1.max_frames = 4;
    q2.max_size = 4 * 100;

    fail_if (pico_enqueue(&q1, pico_frame_copy(f0)) < 0);
    fail_if (pico_enqueue(&q1, pico_frame_copy(f1)) < 0);
    fail_if (pico_enqueue(&q1, pico_frame_copy(f2)) < 0);
    fail_if (pico_enqueue(&q1, pico_frame_copy(f3)) < 0);
    fail_if (pico_enqueue(&q1, pico_frame_copy(f4)) >= 0);

    fail_if (pico_enqueue(&q2, pico_frame_copy(f0)) < 0);
    fail_if (pico_enqueue(&q2, pico_frame_copy(f1)) < 0);
    fail_if (pico_enqueue(&q2, pico_frame_copy(f2)) < 0);
    fail_if (pico_enqueue(&q2, pico_frame_copy(f3)) < 0);
    fail_if (pico_enqueue(&q2, pico_frame_copy(f4)) >= 0);

    fail_if((pico_dequeue(&q1))->buffer != f0->buffer);
    fail_if((pico_dequeue(&q1))->buffer != f1->buffer);
    fail_if((pico_dequeue(&q1))->buffer != f2->buffer);
    fail_if((pico_dequeue(&q1))->buffer != f3->buffer);
    fail_if(pico_queue_peek(&q1) != NULL);
    fail_if(pico_dequeue(&q1) != NULL);
    fail_if(q1.size != 0);
    fail_if(q1.frames != 0);


    pico_queue_empty(&q2);
    fail_if(q2.size != 0);
    fail_if(q2.frames != 0);
    fail_if(pico_queue_peek(&q2) != NULL);
    fail_if(pico_dequeue(&q2) != NULL);

    pico_queue_deinit(&q1);
    pico_queue_deinit(&q2);


}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("Packet Queues");

    TCase *TCase_q = tcase_create("Unit test for pico_queue.c");
    tcase_add_test(TCase_q, tc_q);
    suite_add_tcase(s, TCase_q);
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
