#include "pico_config.h"
#include "pico_tree.h"
#include "pico_icmp6.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_device.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_ethernet.h"
#include "./modules/pico_ipv6_nd.c"
#include "check.h"

#ifdef PICO_SUPPORT_IPV6

START_TEST(tc_pico_ipv6_neighbor_compare)
{
  struct pico_ipv6_neighbor a = { 0 }, b = { 0 };
  struct pico_ip6 address_a = { 0 }, address_b = { 0 };

  /* Same addresses */
  a.address = address_a;
  b.address = address_b;
  fail_if(pico_ipv6_neighbor_compare(&a, &b) != 0, "Neighbours A and B have same ipv6 addr, not true?");

  /* a has different addres */
  a.address.addr[0] = 1;
  fail_if(pico_ipv6_neighbor_compare(&a, &b) != 1, "Neighbour A has different ipv6 addr, not detected?");

  /* Reset */
  a.address = address_a;
  b.address = address_b;

  /* b has different addres */
  b.address.addr[0] = 1;
  fail_if(pico_ipv6_neighbor_compare(&a, &b) != -1, "Neighbour B has different ipv6 addr, not detected?");
}
END_TEST
START_TEST(tc_pico_ipv6_router_compare)
{
  struct pico_ipv6_router a = { 0 }, b = { 0 };
  struct pico_ipv6_neighbor neighbor_a = { 0 }, neighbor_b = { 0 };
  struct pico_ip6 address_a = { 0 }, address_b = { 0 };

  /* Same addresses */
  neighbor_a.address = address_a;
  neighbor_b.address = address_b;
  a.router = &neighbor_a;
  b.router = &neighbor_b;
  fail_if(pico_ipv6_router_compare(&a, &b) != 0, "Routers A and B have same ipv6 addr, not true?");

  /* a has different addres */
  neighbor_a.address.addr[0] = 1;
  fail_if(pico_ipv6_router_compare(&a, &b) != 1, "Router A has different ipv6 addr, not detected?");

  /* Reset */
  neighbor_a.address = address_a;
  neighbor_b.address = address_b;

  /* b has different addres */
  neighbor_b.address.addr[0] = 1;
  fail_if(pico_ipv6_router_compare(&a, &b) != -1, "Router B has different ipv6 addr, not detected?");
}
END_TEST
START_TEST(tc_pico_ipv6_nd_qcompare)
{
  /* TODO: test this: static int pico_ipv6_nd_qcompare(void *ka, void *kb){ */
  struct pico_frame a = { 0 }, b = { 0 };
  struct pico_ipv6_hdr a_hdr = { 0 }, b_hdr =  { 0 };
  struct pico_ip6 a_dest_addr = { 0 }, b_dest_addr = { 0 };

  /* Same packets */
  a_hdr.dst = a_dest_addr;
  b_hdr.dst = b_dest_addr;

  a.net_hdr = (uint8_t *)&a_hdr;
  b.net_hdr = (uint8_t *)&b_hdr;

  fail_if(pico_ipv6_nd_qcompare(&a, &b) != 0, "Frames A and B have same ipv6 addr, not true?");

  /* a has different addres */
  a_hdr.dst.addr[0] = 1;
  fail_if(pico_ipv6_nd_qcompare(&a, &b) != 1, "Frame A has different ipv6 addr, not detected?");

  /* Reset */
  a_hdr.dst = a_dest_addr;
  b_hdr.dst = b_dest_addr;

  /* b has different addres */
  b_hdr.dst.addr[0] = 1;
  fail_if(pico_ipv6_nd_qcompare(&a, &b) != -1, "Frame B has different ipv6 addr, not detected?");

  /* Reset */
  a_hdr.dst = a_dest_addr;
  b_hdr.dst = b_dest_addr;

  /* ------------------------------------------ */
  /* Timestamps */
  /* Same timestamp */
  a.timestamp = 0;
  b.timestamp = 0;

  fail_if(pico_ipv6_nd_qcompare(&a, &b) != 0, "Frames A and B have same timestamp, not true?");

  /* a has different timestamp */
  a.timestamp = 1;
  fail_if(pico_ipv6_nd_qcompare(&a, &b) != 1, "Frame A has different timestamp, not detected?");

  /* Reset */
  a.timestamp = 0;
  b.timestamp = 0;

  /* b has different timestamp */
  b.timestamp = 1;
  fail_if(pico_ipv6_nd_qcompare(&a, &b) != -1, "Frame B has different timestamp, not detected?");
}
END_TEST
START_TEST(tc_pico_get_neighbor_from_ncache)
{
  struct pico_ipv6_neighbor a = { 0 };
  struct pico_ipv6_neighbor b = { 0 };
  struct pico_ip6 a_addr = { 0 };
  struct pico_ip6 b_addr = { 0 };
  struct pico_ip6 c_addr = { 0 };

  /* Init */
  a.address = a_addr;

  /* neighbor not in neighbour cache */
  fail_if(pico_get_neighbor_from_ncache(&a_addr) != NULL, "Neighbor not registered yet but still found?");

  /* Neighbor in neighbour cache*/
  pico_tree_insert(&NCache, &a);
  fail_if(pico_get_neighbor_from_ncache(&a_addr) != &a, "Neighbor registered in ncache but NOT found?");

  /* Look for different neighbour */
  b_addr.addr[0] = 1;
  b.address = b_addr;
  fail_if(pico_get_neighbor_from_ncache(&b_addr) != NULL, "Neighbor not registered in ncache but found?");

  /* Insert other neigbhour */
  pico_tree_insert(&NCache, &b);
  fail_if(pico_get_neighbor_from_ncache(&b_addr) != &b, "Neighbor registered in ncache but NOT found?");

  /* Look for different neighbour when multiple neighbours in neigbhour cache*/
  c_addr.addr[0] = 2;
  fail_if(pico_get_neighbor_from_ncache(&c_addr) != NULL, "Neighbor not registered in ncache but found?");
}
END_TEST
START_TEST(tc_pico_get_router_from_rcache)
{
  struct pico_ipv6_router a = { 0 };
  struct pico_ipv6_router b = { 0 };
  struct pico_ipv6_neighbor a_nb = { 0 };
  struct pico_ipv6_neighbor b_nb = { 0 };
  struct pico_ip6 a_addr = { 0 };
  struct pico_ip6 b_addr = { 0 };
  struct pico_ip6 c_addr = { 0 };

  /* Init */
  a.router = &a_nb;
  b.router = &b_nb;
  a_nb.address = a_addr;

  /* Router not in router cache */
  fail_if(pico_get_router_from_rcache(&a_addr) != NULL, "Router not registered yet but still found?");

  /* Router in router cache*/
  pico_tree_insert(&RCache, &a);
  fail_if(pico_get_router_from_rcache(&a_addr) != &a, "Router registered in rcache but NOT found?");

  /* Look for different router */
  b_addr.addr[0] = 1;
  b_nb.address = b_addr;
  fail_if(pico_get_router_from_rcache(&b_addr) != NULL, "Router not registered in rcache but found?");

  /* Insert other router */
  pico_tree_insert(&RCache, &b);
  fail_if(pico_get_router_from_rcache(&b_addr) != &b, "Router registered in rcache but NOT found?");

  /* Look for different router when multiple router in router cache*/
  c_addr.addr[0] = 2;
  fail_if(pico_get_router_from_rcache(&c_addr) != NULL, "Router not registered in rcache but found?");

  /* Failing malloc */
  pico_set_mm_failure(1);
  fail_if(pico_get_router_from_rcache(&b_addr) != NULL, "Router registered in rcache but malloc failed and we don't return NULL?");

  pico_set_mm_failure(1);
  fail_if(pico_get_router_from_rcache(&c_addr) != NULL, "Router not registered in rcache and malloc failed, but we don't return NULL?");
}
END_TEST
START_TEST(tc_pico_nd_get_length_of_options)
{
  /* TODO: test this: static int pico_nd_get_length_of_options(struct pico_frame *f, uint8_t **first_option) */
}
END_TEST
START_TEST(tc_pico_ipv6_assign_default_router)
{
   /* TODO: test this: static void pico_ipv6_assign_default_router(int is_default) */
}
END_TEST
START_TEST(tc_pico_ipv6_router_add_link)
{
   /* TODO: test this: static void pico_ipv6_router_add_link(struct pico_ip6 *addr, struct pico_ipv6_link *link) */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_queued_trigger)
{
   /* TODO: test this: static void pico_ipv6_nd_queued_trigger(struct pico_ip6 *dst){ */
}
END_TEST
START_TEST(tc_ipv6_duplicate_detected)
{
   /* TODO: test this: static void ipv6_duplicate_detected(struct pico_ipv6_link *l) */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_unreachable)
{
   /* TODO: test this: static void pico_ipv6_nd_unreachable(struct pico_ip6 *a) */
}
END_TEST
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
START_TEST(tc_pico_nd_discover)
{
   /* TODO: test this: static void pico_nd_discover(struct pico_ipv6_neighbor *n) */
}
END_TEST
START_TEST(tc_neigh_options)
{
   /* TODO: test this: static int neigh_options(struct pico_frame *f, void *opt, uint8_t expected_opt) */
}
END_TEST
START_TEST(tc_pico_ipv6_neighbor_update)
{
   /* TODO: test this: static void pico_ipv6_neighbor_update(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt) */
}
END_TEST
START_TEST(tc_pico_ipv6_neighbor_compare_stored)
{
   /* TODO: test this: static int pico_ipv6_neighbor_compare_stored(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt) */
}
END_TEST
START_TEST(tc_neigh_adv_reconfirm_router_option)
{
   /* TODO: test this: static void neigh_adv_reconfirm_router_option(struct pico_ipv6_neighbor *n, unsigned int isRouter) */
}
END_TEST
START_TEST(tc_neigh_adv_reconfirm_no_tlla)
{
   /* TODO: test this: static int neigh_adv_reconfirm_no_tlla(struct pico_ipv6_neighbor *n, struct pico_icmp6_hdr *hdr) */
}
END_TEST
START_TEST(tc_neigh_adv_reconfirm)
{
   /* TODO: test this: static int neigh_adv_reconfirm(struct pico_ipv6_neighbor *n, struct pico_icmp6_opt_lladdr *opt, struct pico_icmp6_hdr *hdr) */
}
END_TEST
START_TEST(tc_neigh_adv_process_incomplete)
{
   /* TODO: test this: static void neigh_adv_process_incomplete(struct pico_ipv6_neighbor *n, struct pico_frame *f, struct pico_icmp6_opt_lladdr *opt) */
}
END_TEST
START_TEST(tc_neigh_adv_process)
{
   /* TODO: test this: static int neigh_adv_process(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ipv6_neighbor_from_unsolicited)
{
   /* TODO: test this: static void pico_ipv6_neighbor_from_unsolicited(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ipv6_router_from_unsolicited)
{
   /* TODO: test this: static void pico_ipv6_router_from_unsolicited(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_detect_dad)
{
   /* TODO: test this: static int neigh_sol_detect_dad(struct pico_frame *f) */
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
START_TEST(tc_neigh_adv_option_len_validity_check)
{
   /* TODO: test this: static int neigh_adv_option_len_validity_check(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_adv_mcast_validity_check)
{
   /* TODO: test this: static int neigh_adv_mcast_validity_check(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_adv_validity_checks)
{
   /* TODO: test this: static int neigh_adv_validity_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_mcast_validity_check)
{
   /* TODO: test this: static int neigh_sol_mcast_validity_check(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_unicast_validity_check)
{
   /* TODO: test this: static int neigh_sol_unicast_validity_check(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_validate_unspec)
{
   /* TODO: test this: static int neigh_sol_validate_unspec(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_validity_checks)
{
   /* TODO: test this: static int neigh_sol_validity_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_router_adv_validity_checks)
{
   /* TODO: test this: static int router_adv_validity_checks(struct pico_frame *f) */
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
START_TEST(tc_redirect_process)
{
   /* TODO: test this: static int redirect_process(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_radv_process)
{
   /* TODO: test this: static int radv_process(struct pico_frame *f) */
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
START_TEST(tc_pico_nd_redirect_is_valid)
{
   /* TODO: test this: static int pico_nd_redirect_is_valid(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_redirect_recv)
{
   /* TODO: test this: static int pico_nd_redirect_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_timer_elapsed)
{
   /* TODO: test this: static void pico_ipv6_nd_timer_elapsed(pico_time now, struct pico_ipv6_neighbor *n) */
}
END_TEST
START_TEST(tc_pico_ipv6_check_router_lifetime_callback)
{
   /* TODO: test this: static void pico_ipv6_check_router_lifetime_callback(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_timer_callback)
{
   /* TODO: test this: static void pico_ipv6_nd_timer_callback(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_ra_timer_callback)
{
   /* TODO: test this: static void pico_ipv6_nd_ra_timer_callback(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_check_rs_timer_expired)
{
   /* TODO: test this: static void pico_ipv6_nd_check_rs_timer_expired(pico_time now, void *arg){ */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_ipv6_neighbor_compare = tcase_create("Unit test for pico_ipv6_neighbor_compare");
    TCase *TCase_pico_ipv6_router_compare = tcase_create("Unit test for pico_ipv6_router_compare");
    TCase *TCase_pico_ipv6_nd_qcompare = tcase_create("Unit test for pico_ipv6_nd_qcompare");
    TCase *TCase_pico_get_neighbor_from_ncache = tcase_create("Unit test for pico_get_neighbor_from_ncache");
    TCase *TCase_pico_get_router_from_rcache = tcase_create("Unit test for pico_get_router_from_rcache");
    TCase *TCase_pico_ipv6_assign_default_router = tcase_create("Unit test for pico_ipv6_assign_default_router");
    TCase *TCase_pico_nd_get_length_of_options = tcase_create("Unit test for pico_nd_get_length_of_options");
    TCase *TCase_pico_ipv6_router_add_link = tcase_create("Unit test for pico_ipv6_router_add_link");
    TCase *TCase_pico_ipv6_nd_queued_trigger = tcase_create("Unit test for pico_ipv6_nd_queued_trigger");
    TCase *TCase_ipv6_duplicate_detected = tcase_create("Unit test for ipv6_duplicate_detected");
    TCase *TCase_pico_ipv6_nd_unreachable = tcase_create("Unit test for pico_ipv6_nd_unreachable");
    TCase *TCase_pico_nd_new_expire_time = tcase_create("Unit test for pico_nd_new_expire_time");
    TCase *TCase_pico_nd_discover = tcase_create("Unit test for pico_nd_discover");
    TCase *TCase_neigh_options = tcase_create("Unit test for neigh_options");
    TCase *TCase_pico_ipv6_neighbor_update = tcase_create("Unit test for pico_ipv6_neighbor_update");
    TCase *TCase_pico_ipv6_neighbor_compare_stored = tcase_create("Unit test for pico_ipv6_neighbor_compare_stored");
    TCase *TCase_neigh_adv_reconfirm_router_option = tcase_create("Unit test for neigh_adv_reconfirm_router_option");
    TCase *TCase_neigh_adv_reconfirm_no_tlla = tcase_create("Unit test for neigh_adv_reconfirm_no_tlla");
    TCase *TCase_neigh_adv_reconfirm = tcase_create("Unit test for neigh_adv_reconfirm");
    TCase *TCase_neigh_adv_process_incomplete = tcase_create("Unit test for neigh_adv_process_incomplete");
    TCase *TCase_neigh_adv_process = tcase_create("Unit test for neigh_adv_process");
    TCase *TCase_pico_ipv6_neighbor_from_unsolicited = tcase_create("Unit test for pico_ipv6_neighbor_from_unsolicited");
    TCase *TCase_pico_ipv6_router_from_unsolicited = tcase_create("Unit test for pico_ipv6_router_from_unsolicited");
    TCase *TCase_neigh_sol_detect_dad = tcase_create("Unit test for neigh_sol_detect_dad");
    TCase *TCase_neigh_sol_process = tcase_create("Unit test for neigh_sol_process");
    TCase *TCase_icmp6_initial_checks = tcase_create("Unit test for icmp6_initial_checks");
    TCase *TCase_neigh_adv_option_len_validity_check = tcase_create("Unit test for neigh_adv_option_len_validity_check");
    TCase *TCase_neigh_adv_mcast_validity_check = tcase_create("Unit test for neigh_adv_mcast_validity_check");
    TCase *TCase_neigh_adv_validity_checks = tcase_create("Unit test for neigh_adv_validity_checks");
    TCase *TCase_neigh_sol_mcast_validity_check = tcase_create("Unit test for neigh_sol_mcast_validity_check");
    TCase *TCase_neigh_sol_unicast_validity_check = tcase_create("Unit test for neigh_sol_unicast_validity_check");
    TCase *TCase_neigh_sol_validate_unspec = tcase_create("Unit test for neigh_sol_validate_unspec");
    TCase *TCase_neigh_sol_validity_checks = tcase_create("Unit test for neigh_sol_validity_checks");
    TCase *TCase_router_adv_validity_checks = tcase_create("Unit test for router_adv_validity_checks");
    TCase *TCase_neigh_adv_checks = tcase_create("Unit test for neigh_adv_checks");
    TCase *TCase_pico_nd_router_sol_recv = tcase_create("Unit test for pico_nd_router_sol_recv");
    TCase *TCase_redirect_process = tcase_create("Unit test for redirect_process");
    TCase *TCase_radv_process = tcase_create("Unit test for radv_process");
    TCase *TCase_pico_nd_router_adv_recv = tcase_create("Unit test for pico_nd_router_adv_recv");
    TCase *TCase_pico_nd_neigh_sol_recv = tcase_create("Unit test for pico_nd_neigh_sol_recv");
    TCase *TCase_pico_nd_neigh_adv_recv = tcase_create("Unit test for pico_nd_neigh_adv_recv");
    TCase *TCase_pico_nd_redirect_is_valid = tcase_create("Unit test for pico_nd_redirect_is_valid");
    TCase *TCase_pico_nd_redirect_recv = tcase_create("Unit test for pico_nd_redirect_recv");
    TCase *TCase_pico_ipv6_nd_timer_elapsed = tcase_create("Unit test for pico_ipv6_nd_timer_elapsed");
    TCase *TCase_pico_ipv6_check_router_lifetime_callback = tcase_create("Unit test for pico_ipv6_check_router_lifetime_callback");
    TCase *TCase_pico_ipv6_nd_timer_callback = tcase_create("Unit test for pico_ipv6_nd_timer_callback");
    TCase *TCase_pico_ipv6_nd_ra_timer_callback = tcase_create("Unit test for pico_ipv6_nd_ra_timer_callback");
    TCase *TCase_pico_ipv6_nd_check_rs_timer_expired = tcase_create("Unit test for pico_ipv6_nd_check_rs_timer_expired");


    tcase_add_test(TCase_pico_ipv6_neighbor_compare, tc_pico_ipv6_neighbor_compare);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor_compare);
    tcase_add_test(TCase_pico_ipv6_router_compare, tc_pico_ipv6_router_compare);
    suite_add_tcase(s, TCase_pico_ipv6_router_compare);
    tcase_add_test(TCase_pico_get_neighbor_from_ncache, tc_pico_get_neighbor_from_ncache);
    suite_add_tcase(s, TCase_pico_get_neighbor_from_ncache);
    tcase_add_test(TCase_pico_get_router_from_rcache, tc_pico_get_router_from_rcache);
    suite_add_tcase(s, TCase_pico_get_router_from_rcache);
    tcase_add_test(TCase_pico_ipv6_nd_qcompare, tc_pico_ipv6_nd_qcompare);
    suite_add_tcase(s, TCase_pico_ipv6_nd_qcompare);
    tcase_add_test(TCase_pico_nd_get_length_of_options, tc_pico_nd_get_length_of_options);
    suite_add_tcase(s, TCase_pico_nd_get_length_of_options);
    tcase_add_test(TCase_pico_ipv6_assign_default_router, tc_pico_ipv6_assign_default_router);
    suite_add_tcase(s, TCase_pico_ipv6_assign_default_router);
    tcase_add_test(TCase_pico_ipv6_router_add_link, tc_pico_ipv6_router_add_link);
    suite_add_tcase(s, TCase_pico_ipv6_router_add_link);
    tcase_add_test(TCase_pico_ipv6_nd_queued_trigger, tc_pico_ipv6_nd_queued_trigger);
    suite_add_tcase(s, TCase_pico_ipv6_nd_queued_trigger);
    tcase_add_test(TCase_ipv6_duplicate_detected, tc_ipv6_duplicate_detected);
    suite_add_tcase(s, TCase_ipv6_duplicate_detected);
    tcase_add_test(TCase_pico_ipv6_nd_unreachable, tc_pico_ipv6_nd_unreachable);
    suite_add_tcase(s, TCase_pico_ipv6_nd_unreachable);
    tcase_add_test(TCase_pico_nd_new_expire_time, tc_pico_nd_new_expire_time);
    suite_add_tcase(s, TCase_pico_nd_new_expire_time);
    tcase_add_test(TCase_pico_nd_discover, tc_pico_nd_discover);
    suite_add_tcase(s, TCase_pico_nd_discover);
    tcase_add_test(TCase_neigh_options, tc_neigh_options);
    suite_add_tcase(s, TCase_neigh_options);
    tcase_add_test(TCase_pico_ipv6_neighbor_update, tc_pico_ipv6_neighbor_update);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor_update);
    tcase_add_test(TCase_pico_ipv6_neighbor_compare_stored, tc_pico_ipv6_neighbor_compare_stored);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor_compare_stored);
    tcase_add_test(TCase_neigh_adv_reconfirm_router_option, tc_neigh_adv_reconfirm_router_option);
    suite_add_tcase(s, TCase_neigh_adv_reconfirm_router_option);
    tcase_add_test(TCase_neigh_adv_reconfirm_no_tlla, tc_neigh_adv_reconfirm_no_tlla);
    suite_add_tcase(s, TCase_neigh_adv_reconfirm_no_tlla);
    tcase_add_test(TCase_neigh_adv_reconfirm, tc_neigh_adv_reconfirm);
    suite_add_tcase(s, TCase_neigh_adv_reconfirm);
    tcase_add_test(TCase_neigh_adv_process_incomplete, tc_neigh_adv_process_incomplete);
    suite_add_tcase(s, TCase_neigh_adv_process_incomplete);
    tcase_add_test(TCase_neigh_adv_process, tc_neigh_adv_process);
    suite_add_tcase(s, TCase_neigh_adv_process);
    tcase_add_test(TCase_pico_ipv6_neighbor_from_unsolicited, tc_pico_ipv6_neighbor_from_unsolicited);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor_from_unsolicited);
    tcase_add_test(TCase_pico_ipv6_router_from_unsolicited, tc_pico_ipv6_router_from_unsolicited);
    suite_add_tcase(s, TCase_pico_ipv6_router_from_unsolicited);
    tcase_add_test(TCase_neigh_sol_detect_dad, tc_neigh_sol_detect_dad);
    suite_add_tcase(s, TCase_neigh_sol_detect_dad);
    tcase_add_test(TCase_neigh_sol_process, tc_neigh_sol_process);
    suite_add_tcase(s, TCase_neigh_sol_process);
    tcase_add_test(TCase_icmp6_initial_checks, tc_icmp6_initial_checks);
    suite_add_tcase(s, TCase_icmp6_initial_checks);
    tcase_add_test(TCase_neigh_adv_option_len_validity_check, tc_neigh_adv_option_len_validity_check);
    suite_add_tcase(s, TCase_neigh_adv_option_len_validity_check);
    tcase_add_test(TCase_neigh_adv_mcast_validity_check, tc_neigh_adv_mcast_validity_check);
    suite_add_tcase(s, TCase_neigh_adv_mcast_validity_check);
    tcase_add_test(TCase_neigh_adv_validity_checks, tc_neigh_adv_validity_checks);
    suite_add_tcase(s, TCase_neigh_adv_validity_checks);
    tcase_add_test(TCase_neigh_sol_mcast_validity_check, tc_neigh_sol_mcast_validity_check);
    suite_add_tcase(s, TCase_neigh_sol_mcast_validity_check);
    tcase_add_test(TCase_neigh_sol_unicast_validity_check, tc_neigh_sol_unicast_validity_check);
    suite_add_tcase(s, TCase_neigh_sol_unicast_validity_check);
    tcase_add_test(TCase_neigh_sol_validate_unspec, tc_neigh_sol_validate_unspec);
    suite_add_tcase(s, TCase_neigh_sol_validate_unspec);
    tcase_add_test(TCase_neigh_sol_validity_checks, tc_neigh_sol_validity_checks);
    suite_add_tcase(s, TCase_neigh_sol_validity_checks);
    tcase_add_test(TCase_router_adv_validity_checks, tc_router_adv_validity_checks);
    suite_add_tcase(s, TCase_router_adv_validity_checks);
    tcase_add_test(TCase_neigh_adv_checks, tc_neigh_adv_checks);
    suite_add_tcase(s, TCase_neigh_adv_checks);
    tcase_add_test(TCase_pico_nd_router_sol_recv, tc_pico_nd_router_sol_recv);
    suite_add_tcase(s, TCase_pico_nd_router_sol_recv);
    tcase_add_test(TCase_redirect_process, tc_redirect_process);
    suite_add_tcase(s, TCase_redirect_process);
    tcase_add_test(TCase_radv_process, tc_radv_process);
    suite_add_tcase(s, TCase_radv_process);
    tcase_add_test(TCase_pico_nd_router_adv_recv, tc_pico_nd_router_adv_recv);
    suite_add_tcase(s, TCase_pico_nd_router_adv_recv);
    tcase_add_test(TCase_pico_nd_neigh_sol_recv, tc_pico_nd_neigh_sol_recv);
    suite_add_tcase(s, TCase_pico_nd_neigh_sol_recv);
    tcase_add_test(TCase_pico_nd_neigh_adv_recv, tc_pico_nd_neigh_adv_recv);
    suite_add_tcase(s, TCase_pico_nd_neigh_adv_recv);
    tcase_add_test(TCase_pico_nd_redirect_is_valid, tc_pico_nd_redirect_is_valid);
    suite_add_tcase(s, TCase_pico_nd_redirect_is_valid);
    tcase_add_test(TCase_pico_nd_redirect_recv, tc_pico_nd_redirect_recv);
    suite_add_tcase(s, TCase_pico_nd_redirect_recv);
    tcase_add_test(TCase_pico_ipv6_nd_timer_elapsed, tc_pico_ipv6_nd_timer_elapsed);
    suite_add_tcase(s, TCase_pico_ipv6_nd_timer_elapsed);
    tcase_add_test(TCase_pico_ipv6_check_router_lifetime_callback, tc_pico_ipv6_check_router_lifetime_callback);
    suite_add_tcase(s, TCase_pico_ipv6_check_router_lifetime_callback);
    tcase_add_test(TCase_pico_ipv6_nd_timer_callback, tc_pico_ipv6_nd_timer_callback);
    suite_add_tcase(s, TCase_pico_ipv6_nd_timer_callback);
    tcase_add_test(TCase_pico_ipv6_nd_ra_timer_callback, tc_pico_ipv6_nd_ra_timer_callback);
    suite_add_tcase(s, TCase_pico_ipv6_nd_ra_timer_callback);
    tcase_add_test(TCase_pico_ipv6_nd_check_rs_timer_expired, tc_pico_ipv6_nd_check_rs_timer_expired);
    suite_add_tcase(s, TCase_pico_ipv6_nd_check_rs_timer_expired);
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
