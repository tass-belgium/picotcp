#include "pico_config.h"
#include "pico_tree.h"
#include "pico_ipv6_nd.h"
#include "pico_icmp6.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_device.h"
#include "pico_eth.h"
#include "modules/pico_ipv6_nd.c"
#include "check.h"

START_TEST(tc_pico_neighbor)
{
    struct pico_neighbor *ne0, *ne1, *ne2;
    struct pico_frame *f = NULL;
    struct pico_ip6 host, n0, n1;
    uint8_t type = 0;

    pico_stack_init();

    pico_string_to_ipv6("7a55::150", host.addr);

    pico_string_to_ipv6("7a55::0", n0.addr);
    pico_string_to_ipv6("7a55::1", n1.addr);


#ifdef PICO_FAULTY
    printf("Testing with faulty memory in pico_nd_add_neighbor (1)\n");
    pico_set_mm_failure(1);
    ne0 = pico_nd_add_neighbor(&host, &n0, PICO_ND_STATE_REACHABLE, NULL);
    fail_if(ne0 != NULL);
#endif

    ne0 = pico_nd_add_neighbor(&host, &n0, PICO_ND_STATE_REACHABLE, NULL);
    fail_if(!ne0);

    ne1 = pico_nd_add_neighbor(&host, &n1, PICO_ND_STATE_REACHABLE, NULL);
    fail_if(!ne1);


    /* Check comparison */
    fail_if(nd_neighbor_compare((void *)ne0, (void*)ne1) >= 0);


    /* Lookup node by address */
    ne2 = pico_nd_lookup(&n1);
    fail_if(ne2 != ne1);

    /* Lookup non-existing node */
    ne2 = pico_nd_lookup(&host);
    fail_if(ne2);

    /* Delete invalid neighbor */
    fail_if(pico_nd_del_neighbor(NULL) >= 0);

    /* Delete non-existing neighbor */
    fail_if(pico_nd_del_neighbor(&host) >= 0);

    /* Delete existing neighbor... */
    fail_if(pico_nd_del_neighbor(&n1) != 0);

    /* Try to find that again... */
    ne2 = pico_nd_lookup(&n1);
    fail_if(ne2);

    /* Check invalid solicitation */
    fail_if(pico_nd_send_solicitation(NULL, NULL, NULL, 0) != -1);



}
END_TEST
START_TEST(tc_pico_router)
{
    struct pico_neighbor *ne0, *ne1, *ne2;
    struct pico_router *ro0, *ro1, *ro2;
    struct pico_frame *f = NULL;
    struct pico_ip6 host, n0, n1;
    uint8_t type = 0;
    pico_stack_init();

    pico_string_to_ipv6("7a55::150", host.addr);

    pico_string_to_ipv6("7a55::0", n0.addr);
    pico_string_to_ipv6("7a55::1", n1.addr);

    ne0 = pico_nd_add_neighbor(&host, &n0, PICO_ND_STATE_REACHABLE, NULL);
    fail_if(!ne0);

    ne1 = pico_nd_add_neighbor(&host, &n1, PICO_ND_STATE_REACHABLE, NULL);
    fail_if(!ne0);

#ifdef PICO_FAULTY
    printf("Testing with faulty memory in pico_nd_add_router (1)\n");
    pico_set_mm_failure(1);
    fail_if (pico_nd_add_router(ne0, 0) != NULL);
#endif

    ro0 = pico_nd_add_router(ne0, 100);
    fail_unless(ro0);

    ro1 = pico_nd_add_router(ne1, 200);
    fail_unless(ro1);

    /* Check comparison = this is done via neighbor pointer addresses */
    if (ne0 > ne1)
        fail_if(nd_router_compare((void *)ro0, (void*)ro1) <= 0);
    else
        fail_if(nd_router_compare((void *)ro0, (void*)ro1) >= 0);


    /* Lookup node by address */
    ro2 = pico_nd_find_router(&n1);
    fail_if(ro2 != ro1);

    /* Lookup non-existing node */
    ro2 = pico_nd_find_router(&host);
    fail_if(ro2);

    /* Delete invalid node */
    fail_if(pico_nd_del_router(NULL) >= 0);

    /* Delete non-existing node */
    fail_if(pico_nd_del_router(&host) >= 0);

    /* Delete existing node... */
    fail_if(pico_nd_del_router(ro1) != 0);

    /* Try to find that again... */
    ro2 = pico_nd_find_router(&n1);
    fail_if(ro2);

}
END_TEST


START_TEST(tc_pico_nd_router_timer)
{
    /* TODO: test this: static void pico_nd_router_timer(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_prefix)
{
    struct pico_prefix *ro0, *ro1, *ro2;
    struct pico_frame *f = NULL;
    struct pico_ip6 host, n0, n1;
    uint8_t type = 0;
    pico_stack_init();

    pico_string_to_ipv6("7a55::150", host.addr);

    pico_string_to_ipv6("7a55::0", n0.addr);
    pico_string_to_ipv6("7a55::1", n1.addr);

#ifdef PICO_FAULTY
    printf("Testing with faulty memory in pico_nd_add_prefix (1)\n");
    pico_set_mm_failure(1);
    fail_if (pico_nd_add_prefix(&n0, 0) != NULL);
#endif

    ro0 = pico_nd_add_prefix(&n0, 100);
    fail_unless(ro0);

    ro1 = pico_nd_add_prefix(&n1, 200);
    fail_unless(ro1);

    /* Check comparison = this is done via neighbor IPv6 addresses */
    fail_if(nd_prefix_compare((void *)ro0, (void*)ro1) >= 0);


    /* Lookup node by address */
    ro2 = pico_nd_find_prefix(&n1);
    fail_if(ro2 != ro1);

    /* Lookup non-existing node */
    ro2 = pico_nd_find_prefix(&host);
    fail_if(ro2);

    /* Delete invalid node */
    fail_if(pico_nd_del_prefix(NULL) >= 0);

    /* Delete non-existing node */
    fail_if(pico_nd_del_prefix(&host) >= 0);

    /* Delete existing node... */
    fail_if(pico_nd_del_prefix(&n1) != 0);

    /* Try to find that again... */
    ro2 = pico_nd_find_prefix(&n1);
    fail_if(ro2);
}
END_TEST

START_TEST(tc_pico_nd_prefix_timer)
{
    /* TODO: test this: static void pico_nd_prefix_timer(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_destination)
{
    struct pico_destination *ro0, *ro1, *ro2;
    struct pico_frame *f = NULL;
    struct pico_ip6 host, n0, n1;
    uint8_t type = 0;
    pico_stack_init();

    pico_string_to_ipv6("7a55::150", host.addr);

    pico_string_to_ipv6("7a55::0", n0.addr);
    pico_string_to_ipv6("7a55::1", n1.addr);

#ifdef PICO_FAULTY
    printf("Testing with faulty memory in pico_nd_add_destination (1)\n");
    pico_set_mm_failure(1);
    fail_if (pico_nd_add_destination(&n0, 0) != NULL);
#endif

    ro0 = pico_nd_add_destination(&n0, &host);
    fail_unless(ro0);

    ro1 = pico_nd_add_destination(&n1, &host);
    fail_unless(ro1);

    /* Check comparison = this is done via neighbor IPv6 addresses */
    fail_if(nd_destination_compare((void *)ro0, (void*)ro1) >= 0);


    /* Lookup node by address */
    ro2 = pico_nd_find_destination(&n1);
    fail_if(ro2 != ro1);

    /* Lookup non-existing node */
    ro2 = pico_nd_find_destination(&host);
    fail_if(ro2);

    /* Delete invalid node */
    fail_if(pico_nd_del_destination(NULL) >= 0);

    /* Delete non-existing node */
    fail_if(pico_nd_del_destination(&host) >= 0);

    /* Delete existing node... */
    fail_if(pico_nd_del_destination(&n1) != 0);

    /* Try to find that again... */
    ro2 = pico_nd_find_destination(&n1);
    fail_if(ro2);
}
END_TEST
START_TEST(tc_pico_nd_destination_garbage_collect)
{
    /* TODO: test this: static void pico_nd_destination_garbage_collect(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_nd_pending)
{
    /* TODO: test this: static void pico_nd_pending(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_nd_first_probe)
{
    /* TODO: test this: static void pico_nd_first_probe(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_nd_probe)
{
    /* TODO: test this: static void pico_nd_probe(pico_time now, void *arg) */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_neighbor = tcase_create("Unit test for pico_neighbor");
    TCase *TCase_pico_router = tcase_create("Unit test for pico_router");
    TCase *TCase_pico_nd_router_timer = tcase_create("Unit test for pico_nd_router_timer");
    TCase *TCase_pico_prefix = tcase_create("Unit test for pico_prefix");
    TCase *TCase_pico_nd_prefix_timer = tcase_create("Unit test for pico_nd_prefix_timer");
    TCase *TCase_pico_destination = tcase_create("Unit test for pico_destination");
    TCase *TCase_pico_nd_destination_garbage_collect = tcase_create("Unit test for pico_nd_destination_garbage_collect");
    TCase *TCase_pico_nd_pending = tcase_create("Unit test for pico_nd_pending");
    TCase *TCase_pico_nd_first_probe = tcase_create("Unit test for pico_nd_first_probe");
    TCase *TCase_pico_nd_probe = tcase_create("Unit test for pico_nd_probe");


    tcase_add_test(TCase_pico_neighbor, tc_pico_neighbor);
    suite_add_tcase(s, TCase_pico_neighbor);
    tcase_add_test(TCase_pico_router, tc_pico_router);
    suite_add_tcase(s, TCase_pico_router);
    tcase_add_test(TCase_pico_nd_router_timer, tc_pico_nd_router_timer);
    suite_add_tcase(s, TCase_pico_nd_router_timer);
    tcase_add_test(TCase_pico_prefix, tc_pico_prefix);
    suite_add_tcase(s, TCase_pico_prefix);
    tcase_add_test(TCase_pico_nd_prefix_timer, tc_pico_nd_prefix_timer);
    suite_add_tcase(s, TCase_pico_nd_prefix_timer);
    tcase_add_test(TCase_pico_destination, tc_pico_destination);
    suite_add_tcase(s, TCase_pico_destination);
    tcase_add_test(TCase_pico_nd_destination_garbage_collect, tc_pico_nd_destination_garbage_collect);
    suite_add_tcase(s, TCase_pico_nd_destination_garbage_collect);
    tcase_add_test(TCase_pico_nd_pending, tc_pico_nd_pending);
    suite_add_tcase(s, TCase_pico_nd_pending);
    tcase_add_test(TCase_pico_nd_first_probe, tc_pico_nd_first_probe);
    suite_add_tcase(s, TCase_pico_nd_first_probe);
    tcase_add_test(TCase_pico_nd_probe, tc_pico_nd_probe);
    suite_add_tcase(s, TCase_pico_nd_probe);
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
