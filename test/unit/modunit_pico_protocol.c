#include "pico_protocol.h"
#include "pico_tree.h"
#include "stack/pico_protocol.c"
#include "check.h"

Suite *pico_suite(void);

volatile pico_err_t pico_err = 0;

static int protocol_passby = 0;

static struct pico_frame f = {
    .next = NULL
};

static struct pico_queue q = {
    0
};

static struct pico_tree_node NODE_IN = {
    0
};
static struct pico_tree_node NODE_OUT = {
    0
};

#define KEY_IN 0x0D01
#define KEY_OUT 0x0D00


START_TEST(tc_pico_proto_cmp)
{
    struct pico_protocol a = {
        .hash = 0
    };
    struct pico_protocol b = {
        .hash = 1
    };
    fail_if(pico_proto_cmp(&a, &b) >= 0);
    a.hash = 1;
    fail_if(pico_proto_cmp(&a, &b) != 0);
    a.hash = 2;
    fail_if(pico_proto_cmp(&a, &b) <= 0);
}
END_TEST

static int modunit_proto_loop_cb_in(struct pico_protocol *self, struct pico_frame *p)
{
    if (!p)
        protocol_passby = -1; /* Error! */

    if (!self)
        protocol_passby = -1; /* Error! */

    if (protocol_passby != 0) /* Ensure that we are called only once. */
        protocol_passby = -1;

    protocol_passby = KEY_IN;

    return 1; /* One frame processed! */
}

static int modunit_proto_loop_cb_out(struct pico_protocol *self, struct pico_frame *p)
{
    if (!p)
        protocol_passby = -1; /* Error! */

    if (!self)
        protocol_passby = -1; /* Error! */

    if (protocol_passby != 0) /* Ensure that we are called only once. */
        protocol_passby = -1;

    protocol_passby = KEY_OUT;

    return 1; /* One frame processed! */
}

START_TEST(tc_proto_loop_in)
{
    struct pico_protocol p = {
        .process_in = modunit_proto_loop_cb_in, .q_in = &q
    };
    protocol_passby = 0;
    pico_enqueue(p.q_in, &f);
    fail_if(proto_loop_in(&p, 1) != 0);
    fail_if(protocol_passby != KEY_IN);

    /* Try to dequeue from empty queue, get same loop_score */
    protocol_passby = 0;
    fail_if(proto_loop_in(&p, 1) != 1);
    fail_if(protocol_passby != 0);
}
END_TEST


START_TEST(tc_proto_loop_out)
{
    struct pico_protocol p = {
        .process_out = modunit_proto_loop_cb_out, .q_out = &q
    };
    protocol_passby = 0;
    pico_enqueue(p.q_out, &f);
    fail_if(proto_loop_out(&p, 1) != 0);
    fail_if(protocol_passby != KEY_OUT);

    /* Try to dequeue from empty queue, get same loop_score */
    protocol_passby = 0;
    fail_if(proto_loop_out(&p, 1) != 1);
    fail_if(protocol_passby != 0);
}
END_TEST

START_TEST(tc_proto_loop)
{
    struct pico_protocol p = {
        .process_in = modunit_proto_loop_cb_in,
        .process_out = modunit_proto_loop_cb_out,
        .q_in = &q,
        .q_out = &q
    };
    protocol_passby = 0;
    pico_enqueue(p.q_in, &f);
    fail_if(proto_loop(&p, 1, PICO_LOOP_DIR_IN) != 0);
    fail_if(protocol_passby != KEY_IN);

    protocol_passby = 0;
    pico_enqueue(p.q_out, &f);
    fail_if(proto_loop(&p, 1, PICO_LOOP_DIR_OUT) != 0);
    fail_if(protocol_passby != KEY_OUT);

}
END_TEST

START_TEST(tc_pico_tree_node)
{
    struct pico_proto_rr rr = {
        0
    };
    rr.node_in = &NODE_IN;
    rr.node_out = &NODE_OUT;
    fail_unless(roundrobin_init(&rr, PICO_LOOP_DIR_IN) == &NODE_IN);
    fail_unless(roundrobin_init(&rr, PICO_LOOP_DIR_OUT) == &NODE_OUT);
}
END_TEST

START_TEST(tc_roundrobin_end)
{
    struct pico_proto_rr rr;
    roundrobin_end(&rr, PICO_LOOP_DIR_IN, &NODE_IN);
    fail_if(rr.node_in != &NODE_IN);
    roundrobin_end(&rr, PICO_LOOP_DIR_OUT, &NODE_OUT);
    fail_if(rr.node_out != &NODE_OUT);
}
END_TEST

START_TEST(tc_pico_protocol_generic_loop)
{
    struct pico_proto_rr rr = {
        0
    };
    int ret = 0;

    rr.node_in = &NODE_IN;
    rr.node_out = &NODE_OUT;
    ret = pico_protocol_generic_loop(&rr, 0, PICO_LOOP_DIR_IN);

    fail_if(ret != 0);

    pico_protocols_loop(0);
}
END_TEST


START_TEST(tc_proto_layer_rr_reset)
{
    struct pico_proto_rr rr;
    rr.node_in = &NODE_IN;
    rr.node_out = &NODE_OUT;
    proto_layer_rr_reset(&rr);
    fail_if(rr.node_in != NULL);
    fail_if(rr.node_out != NULL);
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("pico_protocol.c");

    TCase *TCase_pico_proto_cmp = tcase_create("Unit test for pico_proto_cmp");
    TCase *TCase_proto_loop_in = tcase_create("Unit test for proto_loop_in");
    TCase *TCase_proto_loop_out = tcase_create("Unit test for proto_loop_out");
    TCase *TCase_proto_loop = tcase_create("Unit test for proto_loop");
    TCase *TCase_pico_tree_node = tcase_create("Unit test for pico_tree_node");
    TCase *TCase_roundrobin_end = tcase_create("Unit test for roundrobin_end");
    TCase *TCase_pico_protocol_generic_loop = tcase_create("Unit test for pico_protocol_generic_loop");
    TCase *TCase_proto_layer_rr_reset = tcase_create("Unit test for proto_layer_rr_reset");


    tcase_add_test(TCase_pico_proto_cmp, tc_pico_proto_cmp);
    suite_add_tcase(s, TCase_pico_proto_cmp);
    tcase_add_test(TCase_proto_loop_in, tc_proto_loop_in);
    suite_add_tcase(s, TCase_proto_loop_in);
    tcase_add_test(TCase_proto_loop_out, tc_proto_loop_out);
    suite_add_tcase(s, TCase_proto_loop_out);
    tcase_add_test(TCase_proto_loop, tc_proto_loop);
    suite_add_tcase(s, TCase_proto_loop);
    tcase_add_test(TCase_pico_tree_node, tc_pico_tree_node);
    suite_add_tcase(s, TCase_pico_tree_node);
    tcase_add_test(TCase_roundrobin_end, tc_roundrobin_end);
    suite_add_tcase(s, TCase_roundrobin_end);
    tcase_add_test(TCase_pico_protocol_generic_loop, tc_pico_protocol_generic_loop);
    suite_add_tcase(s, TCase_pico_protocol_generic_loop);
    tcase_add_test(TCase_proto_layer_rr_reset, tc_proto_layer_rr_reset);
    suite_add_tcase(s, TCase_proto_layer_rr_reset);
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
