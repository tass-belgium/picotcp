#include "pico_config.h"
#include "pico_tree.h"
#include "pico_ipv6_nd.h"
#include "pico_icmp6.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_device.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "modules/pico_ipv6_nd.c"
#include "check.h"
#ifdef PICO_SUPPORT_IPV6

#undef PICO_TIME
#undef PICO_TIME_MS

#define PICO_TIME_MS (0)
#define PICO_TIME (0)

Suite *pico_suite(void);
START_TEST(tc_pico_nd_new_expire_time)
{
    struct pico_ipv6_neighbor n = {
        0
    };
    struct pico_device d = { {0} };

    /* TODO: how to test these time values */

    n.dev = &d;

    d.hostvars.retranstime = 666;

    n.state = PICO_ND_STATE_INCOMPLETE;
    pico_nd_new_expire_time(&n);

    n.state = PICO_ND_STATE_REACHABLE;
    pico_nd_new_expire_time(&n);


    n.state = PICO_ND_STATE_STALE;
    pico_nd_new_expire_time(&n);


    n.state = PICO_ND_STATE_PROBE;
    pico_nd_new_expire_time(&n);

}
END_TEST
START_TEST(tc_pico_nd_queue)
{
    struct pico_ip6 addr = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    int i;
    struct pico_frame *f = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    struct pico_ipv6_hdr *h = (struct pico_ipv6_hdr *) f->buffer;
    f->net_hdr = (uint8_t*) h;
    f->buffer[0] = 0x60; /* Ipv6 */
    memcpy(h->dst.addr, addr.addr, PICO_SIZE_IP6);

    fail_if(!f);

    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; i++) {
        fail_if(frames_queued_v6[i] != NULL);
    }
    pico_ipv6_nd_unreachable(&addr);
    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; i++) {
        fail_if(frames_queued_v6[i] != NULL);
    }
    pico_ipv6_nd_postpone(f);
    fail_if(frames_queued_v6[0]->buffer != f->buffer);

    pico_ipv6_nd_unreachable(&addr);

    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; i++) {
        fail_if(frames_queued_v6[i] != NULL);
    }
}
END_TEST

START_TEST(tc_pico_nd_discover)
{
    /* TODO: test this: static void pico_nd_discover(struct pico_ipv6_neighbor *n) */
}
END_TEST
START_TEST(tc_neigh_options)
{
    /* TODO: test this: static int neigh_options(struct pico_frame *f, struct pico_icmp6_opt_lladdr *opt, uint8_t expected_opt) */
}
END_TEST
START_TEST(tc_neigh_adv_complete)
{
    /* TODO: test this: static int neigh_adv_complete(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt) */
}
END_TEST
START_TEST(tc_neigh_adv_reconfirm_router_option)
{
    /* TODO: test this: static void neigh_adv_reconfirm_router_option(struct pico_ipv6_neighbor *n, unsigned int isRouter) */
}
END_TEST
START_TEST(tc_neigh_adv_reconfirm)
{
    /* TODO: test this: static int neigh_adv_reconfirm(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt, struct pico_icmp6_hdr *hdr) */
}
END_TEST
START_TEST(tc_neigh_adv_check_solicited)
{
    /* TODO: test this: static void neigh_adv_check_solicited(struct pico_icmp6_hdr *ic6, struct pico_ipv6_neighbor *n) */
}
END_TEST
START_TEST(tc_neigh_adv_process)
{
    /* TODO: test this: static int neigh_adv_process(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ipv6_neighbor)
{
    /* TODO: test this: static struct pico_ipv6_neighbor *neighbor_from_sol_new(struct pico_ip6 *ip, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev) */
}
END_TEST
START_TEST(tc_neighbor_from_sol)
{
    /* TODO: test this: static void neighbor_from_sol(struct pico_ip6 *ip, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev) */
}
END_TEST
START_TEST(tc_neigh_sol_process)
{
    /* TODO: test this: static int neigh_sol_process(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_icmp6_initial_checks)
{
    /* TODO: test this: static int icmp6_initial_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_adv_mcast_validity_checks)
{
    /* TODO: test this: static int neigh_adv_mcast_validity_check(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_mcast_validity_checks)
{
    /* TODO: test this: static int neigh_sol_mcast_validity_check(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_adv_validity_checks)
{
    /* TODO: test this: static int neigh_adv_validity_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_validity_checks)
{
    /* TODO: test this: static int neigh_sol_validity_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_adv_checks)
{
    /* TODO: test this: static int neigh_adv_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_router_sol_recv)
{
    /* TODO: test this: static int pico_nd_router_sol_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_router_adv_recv)
{
    /* TODO: test this: static int pico_nd_router_adv_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_neigh_sol_recv)
{
    /* TODO: test this: static int pico_nd_neigh_sol_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_neigh_adv_recv)
{
    /* TODO: test this: static int pico_nd_neigh_adv_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_redirect_recv)
{
    /* TODO: test this: static int pico_nd_redirect_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_timer_callback)
{
    /* TODO: test this: static void pico_ipv6_nd_timer_callback(pico_time now, void *arg) */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_nd_new_expire_time = tcase_create("Unit test for pico_nd_new_expire_time");
    TCase *TCase_pico_nd_discover = tcase_create("Unit test for pico_nd_discover");
    TCase *TCase_neigh_options = tcase_create("Unit test for neigh_options");
    TCase *TCase_neigh_adv_complete = tcase_create("Unit test for neigh_adv_complete");
    TCase *TCase_neigh_adv_reconfirm_router_option = tcase_create("Unit test for neigh_adv_reconfirm_router_option");
    TCase *TCase_neigh_adv_reconfirm = tcase_create("Unit test for neigh_adv_reconfirm");
    TCase *TCase_neigh_adv_check_solicited = tcase_create("Unit test for neigh_adv_check_solicited");
    TCase *TCase_neigh_adv_process = tcase_create("Unit test for neigh_adv_process");
    TCase *TCase_pico_ipv6_neighbor = tcase_create("Unit test for pico_ipv6_neighbor");
    TCase *TCase_neighbor_from_sol = tcase_create("Unit test for neighbor_from_sol");
    TCase *TCase_neigh_sol_process = tcase_create("Unit test for neigh_sol_process");
    TCase *TCase_icmp6_initial_checks = tcase_create("Unit test for icmp6_initial_checks");
    TCase *TCase_neigh_sol_mcast_validity_checks = tcase_create("Unit test for neigh_sol_mcast_validity_checks");
    TCase *TCase_neigh_sol_validity_checks = tcase_create("Unit test for neigh_sol_validity_checks");
    TCase *TCase_neigh_adv_checks = tcase_create("Unit test for neigh_adv_checks");
    TCase *TCase_neigh_adv_validity_checks = tcase_create("Unit test for neigh_adv_validity_checks");
    TCase *TCase_neigh_adv_mcast_validity_checks = tcase_create("Unit test for neigh_adv_mcast_validity_checks");
    TCase *TCase_pico_nd_router_sol_recv = tcase_create("Unit test for pico_nd_router_sol_recv");
    TCase *TCase_pico_nd_router_adv_recv = tcase_create("Unit test for pico_nd_router_adv_recv");
    TCase *TCase_pico_nd_neigh_sol_recv = tcase_create("Unit test for pico_nd_neigh_sol_recv");
    TCase *TCase_pico_nd_neigh_adv_recv = tcase_create("Unit test for pico_nd_neigh_adv_recv");
    TCase *TCase_pico_nd_redirect_recv = tcase_create("Unit test for pico_nd_redirect_recv");
    TCase *TCase_pico_ipv6_nd_timer_callback = tcase_create("Unit test for pico_ipv6_nd_timer_callback");
    TCase *TCase_pico_nd_queue = tcase_create("Unit test for pico_ipv6_nd: queue for pending frames");


    tcase_add_test(TCase_pico_nd_new_expire_time, tc_pico_nd_new_expire_time);
    suite_add_tcase(s, TCase_pico_nd_new_expire_time);
    tcase_add_test(TCase_pico_nd_discover, tc_pico_nd_discover);
    suite_add_tcase(s, TCase_pico_nd_discover);
    tcase_add_test(TCase_neigh_options, tc_neigh_options);
    suite_add_tcase(s, TCase_neigh_options);
    tcase_add_test(TCase_neigh_adv_complete, tc_neigh_adv_complete);
    suite_add_tcase(s, TCase_neigh_adv_complete);
    tcase_add_test(TCase_neigh_adv_reconfirm_router_option, tc_neigh_adv_reconfirm_router_option);
    suite_add_tcase(s, TCase_neigh_adv_reconfirm_router_option);
    tcase_add_test(TCase_neigh_adv_reconfirm, tc_neigh_adv_reconfirm);
    suite_add_tcase(s, TCase_neigh_adv_reconfirm);
    tcase_add_test(TCase_neigh_adv_check_solicited, tc_neigh_adv_check_solicited);
    suite_add_tcase(s, TCase_neigh_adv_check_solicited);
    tcase_add_test(TCase_neigh_adv_process, tc_neigh_adv_process);
    suite_add_tcase(s, TCase_neigh_adv_process);
    tcase_add_test(TCase_pico_ipv6_neighbor, tc_pico_ipv6_neighbor);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor);
    tcase_add_test(TCase_neighbor_from_sol, tc_neighbor_from_sol);
    suite_add_tcase(s, TCase_neighbor_from_sol);
    tcase_add_test(TCase_neigh_sol_process, tc_neigh_sol_process);
    suite_add_tcase(s, TCase_neigh_sol_process);
    tcase_add_test(TCase_icmp6_initial_checks, tc_icmp6_initial_checks);
    suite_add_tcase(s, TCase_icmp6_initial_checks);
    tcase_add_test(TCase_neigh_adv_mcast_validity_checks, tc_neigh_adv_mcast_validity_checks);
    suite_add_tcase(s, TCase_neigh_adv_mcast_validity_checks);
    tcase_add_test(TCase_neigh_sol_mcast_validity_checks, tc_neigh_sol_mcast_validity_checks);
    suite_add_tcase(s, TCase_neigh_sol_mcast_validity_checks);
    tcase_add_test(TCase_neigh_adv_validity_checks, tc_neigh_adv_validity_checks);
    suite_add_tcase(s, TCase_neigh_adv_validity_checks);
    tcase_add_test(TCase_neigh_sol_validity_checks, tc_neigh_sol_validity_checks);
    suite_add_tcase(s, TCase_neigh_sol_validity_checks);
    tcase_add_test(TCase_neigh_adv_checks, tc_neigh_adv_checks);
    suite_add_tcase(s, TCase_neigh_adv_checks);
    tcase_add_test(TCase_pico_nd_router_sol_recv, tc_pico_nd_router_sol_recv);
    suite_add_tcase(s, TCase_pico_nd_router_sol_recv);
    tcase_add_test(TCase_pico_nd_router_adv_recv, tc_pico_nd_router_adv_recv);
    suite_add_tcase(s, TCase_pico_nd_router_adv_recv);
    tcase_add_test(TCase_pico_nd_neigh_sol_recv, tc_pico_nd_neigh_sol_recv);
    suite_add_tcase(s, TCase_pico_nd_neigh_sol_recv);
    tcase_add_test(TCase_pico_nd_neigh_adv_recv, tc_pico_nd_neigh_adv_recv);
    suite_add_tcase(s, TCase_pico_nd_neigh_adv_recv);
    tcase_add_test(TCase_pico_nd_redirect_recv, tc_pico_nd_redirect_recv);
    suite_add_tcase(s, TCase_pico_nd_redirect_recv);
    tcase_add_test(TCase_pico_ipv6_nd_timer_callback, tc_pico_ipv6_nd_timer_callback);
    suite_add_tcase(s, TCase_pico_ipv6_nd_timer_callback);
    tcase_add_test(TCase_pico_nd_queue, tc_pico_nd_queue);
    suite_add_tcase(s, TCase_pico_nd_queue);
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
#else
int main(void)
{
    return 0;
}

#endif
