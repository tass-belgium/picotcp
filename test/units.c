/* PicoTCP unit test platform */
/* How does it works:
 * 1. Define your unit test function as described in the check manual
 * 2. Add your test to the suite in the pico_suite() function
 */


/* Inclusion of all the modules to test */
/* This allow direct access to static functions, and also
 * by compiling this, the namespace is checked for clashes in
 * static symbols.
 */
#include "pico_device.c"
#include "pico_frame.c"
#include "pico_stack.c"
#include "pico_protocol.c"
#include "pico_802154.c"
#include "pico_6lowpan.c"
#include "pico_6lowpan_ll.c"
#include "pico_ipv4.c"
#include "pico_socket.c"
#include "pico_socket_multicast.c"
#include "pico_socket_tcp.c"
#include "pico_socket_udp.c"
#include "pico_dev_null.c"
#include "pico_dev_mock.c"
#include "pico_udp.c"
#include "pico_tcp.c"
#include "pico_arp.c"
#include "pico_icmp4.c"
#include "pico_dns_client.c"
#include "pico_dns_common.c"
#include "pico_dhcp_common.c"
#include "pico_dhcp_server.c"
#include "pico_dhcp_client.c"
#include "pico_nat.c"
#include "pico_ipfilter.c"
#include "pico_tree.c"
#include "pico_slaacv4.c"
#include "pico_hotplug_detection.c"
#ifdef PICO_SUPPORT_MCAST
#include "pico_mcast.c"
#include "pico_igmp.c"
#endif
#ifdef PICO_SUPPORT_IPV6
#include "pico_ipv6.c"
#include "pico_ipv6_nd.c"
#include "pico_icmp6.c"
#ifdef PICO_SUPPORT_MCAST
#include "pico_mld.c"
#endif
#endif


/* Include Check. */
#include <check.h>

/* Inclusion of unit submodules.
 * Historically, this code has been part of
 * the units.c file.
 * Moved for readability of the units.
 */
#include "unit_mocks.c"
#include "unit_ipv4.c"
#include "unit_icmp4.c"
#include "unit_dhcp.c"
#include "unit_dns.c"
#include "unit_rbtree.c"
#include "unit_socket.c"
#include "unit_timer.c"
#include "unit_arp.c"
#include "unit_ipv6.c"

Suite *pico_suite(void);

START_TEST (test_frame)
{
    struct pico_frame *f1;
    struct pico_frame *cpy;
    struct pico_frame *deepcpy;

    f1 = pico_frame_alloc(200);
    f1->payload = f1->buffer + 32;
    f1->net_hdr = f1->buffer + 16;
    cpy = pico_frame_copy(f1);
    deepcpy = pico_frame_deepcopy(f1);
    fail_unless(*f1->usage_count == 2);
    fail_unless(*deepcpy->usage_count == 1);
    pico_frame_discard(f1);
    fail_unless(*cpy->usage_count == 1);
    pico_frame_discard(cpy);
    fail_unless(*deepcpy->usage_count == 1);
    pico_frame_discard(deepcpy);
}
END_TEST

START_TEST (test_tick)
{
    pico_tick = (uint64_t)-1;
    fail_if(pico_tick != 0xFFFFFFFFFFFFFFFF, "Failed to assign (uint64_t)-1 to pico_tick\n");
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *ipv4 = tcase_create("IPv4");
    TCase *icmp = tcase_create("ICMP4");
    TCase *dhcp = tcase_create("DHCP");
    TCase *dns = tcase_create("DNS");
    TCase *rb = tcase_create("RB TREE");
    TCase *rb2 = tcase_create("RB TREE 2");
    TCase *socket = tcase_create("SOCKET");
    TCase *nat = tcase_create("NAT");
    TCase *ipfilter = tcase_create("IPFILTER");
#ifdef PICO_SUPPORT_CRC_FAULTY_UNIT_TEST
    TCase *crc = tcase_create("CRC");
#endif

#ifdef PICO_SUPPORT_MCAST
    TCase *igmp = tcase_create("IGMP");
#endif
#ifdef PICO_SUPPORT_IPV6
    TCase *ipv6 = tcase_create("IPv6");
#ifdef PICO_SUPPORT_MCAST
    TCase *mld = tcase_create("MLD");
#endif
#endif

    TCase *frame = tcase_create("FRAME");
    TCase *timers = tcase_create("TIMERS");
    TCase *slaacv4 = tcase_create("SLAACV4");
    TCase *tick = tcase_create("pico_tick");
    TCase *arp = tcase_create("ARP");
    tcase_add_test(ipv4, test_ipv4);
    tcase_set_timeout(ipv4, 20);
    suite_add_tcase(s, ipv4);

    tcase_add_test(icmp, test_icmp4_ping);
    tcase_add_test(icmp, test_icmp4_incoming_ping);
    tcase_add_test(icmp, test_icmp4_unreachable_send);
    tcase_add_test(icmp, test_icmp4_unreachable_recv);
    suite_add_tcase(s, icmp);

    /* XXX: rewrite test_dhcp_client due to architectural changes to support multiple devices */
    /* tcase_add_test(dhcp, test_dhcp_client); */
    tcase_add_test(dhcp, test_dhcp_client_api);

    tcase_add_test(dhcp, test_dhcp_server_ipinarp);
    tcase_add_test(dhcp, test_dhcp_server_ipninarp);
    tcase_add_test(dhcp, test_dhcp_server_api);
    tcase_add_test(dhcp, test_dhcp);
    suite_add_tcase(s, dhcp);

    tcase_add_test(dns, test_dns);
    suite_add_tcase(s, dns);

    tcase_add_test(rb, test_rbtree);
    tcase_set_timeout(rb, 120);
    suite_add_tcase(s, rb);

    tcase_add_test(rb2, test_rbtree2);
    tcase_set_timeout(rb2, 20);
    suite_add_tcase(s, rb2);

    tcase_add_test(socket, test_socket);
    suite_add_tcase(s, socket);

    tcase_add_test(nat, test_nat_enable_disable);
    tcase_add_test(nat, test_nat_translation);
    tcase_add_test(nat, test_nat_port_forwarding);
    tcase_set_timeout(nat, 30);
    suite_add_tcase(s, nat);

    tcase_add_test(ipfilter, test_ipfilter);
    tcase_set_timeout(ipfilter, 10);
    suite_add_tcase(s, ipfilter);

#ifdef PICO_SUPPORT_CRC_FAULTY_UNIT_TEST
    tcase_add_test(crc, test_crc_check);
    suite_add_tcase(s, crc);
#endif

#ifdef PICO_SUPPORT_MCAST
    tcase_add_test(igmp, test_igmp_sockopts);
    suite_add_tcase(s, igmp);
#endif

    tcase_add_test(frame, test_frame);
    suite_add_tcase(s, frame);

    tcase_add_test(timers, test_timers);
    suite_add_tcase(s, timers);

    tcase_add_test(slaacv4, test_slaacv4);
    suite_add_tcase(s, slaacv4);

    tcase_add_test(tick, test_tick);
    suite_add_tcase(s, tick);

#ifdef PICO_SUPPORT_IPV6
    tcase_add_test(ipv6, test_ipv6);
    suite_add_tcase(s, ipv6);
#ifdef PICO_SUPPORT_MCAST
    tcase_add_test(mld, test_mld_sockopts);
    suite_add_tcase(s, mld);
#endif
#endif

    tcase_add_test(arp, arp_update_max_arp_reqs_test);
    tcase_add_test(arp, arp_compare_test);
    tcase_add_test(arp, arp_lookup_test);
    tcase_add_test(arp, arp_expire_test);
    tcase_add_test(arp, arp_receive_test);
    tcase_add_test(arp, arp_get_test);
    tcase_add_test(arp, tc_pico_arp_queue);
    suite_add_tcase(s, arp);
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
