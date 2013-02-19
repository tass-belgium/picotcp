/* PicoTCP unit test platform */
/* How does it works: 
 * 1. Define your unit test function as described in the check manual
 * 2. Add your test to the suite in the pico_suite() function
 */

#include "pico_device.c"
#include "pico_frame.c"
#include "pico_stack.c"
#include "pico_protocol.c"
#include "pico_ipv4.c"
#include "pico_socket.c"
#include "pico_dev_null.c"
#include "pico_udp.c"
#include "pico_tcp.c"
#include "pico_arp.c"
#include "pico_icmp4.c"
#include "pico_dhcp_common.c"
#include "pico_dns_client.c"
#include "pico_dhcp_server.c"
#include "pico_dhcp_client.c"
#include "pico_igmp2.c"
#include "pico_nat.c"
#include <check.h>

START_TEST (test_ipv4)
{
  #define IP_TST_SIZ 256
  int i;

  struct pico_device *dev[IP_TST_SIZ];
  char devname[8]; 
  struct pico_ip4 a[IP_TST_SIZ], d[IP_TST_SIZ], *source[IP_TST_SIZ], nm16, nm32, gw[IP_TST_SIZ], r[IP_TST_SIZ], ret;
  struct pico_ipv4_link *l[IP_TST_SIZ];

  char ipstr[] = "192.168.1.1";
  struct pico_ip4 ipaddr;

  struct pico_frame *f_NULL = NULL;
  struct pico_ip4 *dst_NULL = NULL;

  pico_stack_init();

  nm16.addr = long_be(0xFFFF0000);
  nm32.addr = long_be(0xFFFFFFFF);

  /*link_add*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    snprintf(devname, 8, "nul%d", i);
    dev[i] = pico_null_create(devname);
    a[i].addr = long_be(0x0a000001 + (i << 16));
    d[i].addr = long_be(0x0a000002 + (i << 16));
    fail_if(pico_ipv4_link_add(dev[i], a[i], nm16) != 0, "Error adding link");
  }

  /*link_find + link_get + route_add*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    gw[i].addr = long_be(0x0a0000f0 + (i << 16));
    r[i].addr = long_be(0x0c00001 + (i << 16));
    fail_unless(pico_ipv4_link_find(&a[i]) == dev[i], "Error finding link");
    l[i] = pico_ipv4_link_get(&a[i]);
    fail_if(l[i] == NULL, "Error getting link");
    fail_if(pico_ipv4_route_add(r[i], nm32, gw[i], 1, l[i]) != 0, "Error adding route");
    fail_if(pico_ipv4_route_add(d[i], nm32, gw[i], 1, l[i]) != 0, "Error adding route");
  }

  /*get_gateway + source_find*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    ret = pico_ipv4_route_get_gateway(&r[i]);
    fail_if(ret.addr != gw[i].addr, "Error get gateway: returned wrong route");
    source[i] = pico_ipv4_source_find(&d[i]);
    fail_if(source[i]->addr != a[i].addr, "Error find source: returned wrong route");
  }

  /*route_del + link_del*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    fail_if(pico_ipv4_route_del(r[i], nm32, gw[i], 1, l[i]) != 0, "Error deleting route");
    fail_if(pico_ipv4_link_del(dev[i], a[i]) != 0, "Error deleting link");
  }

  /*string_to_ipv4 + ipv4_to_string*/
  pico_string_to_ipv4(ipstr, &(ipaddr.addr));
  fail_if(ipaddr.addr != 0x0101a8c0, "Error string to ipv4");
  memset(ipstr, 0, 12);
  pico_ipv4_to_string(ipstr, ipaddr.addr);
  fail_if(strncmp(ipstr, "192.168.1.1", 11) != 0, "Error ipv4 to string");

  /*valid_netmask*/
  fail_if(pico_ipv4_valid_netmask(long_be(nm32.addr)) != 32, "Error checking netmask");

  /*is_unicast*/
  fail_if((pico_ipv4_is_unicast(0x0101a8c0)) != 1, "Error checking unicast");
  fail_if((pico_ipv4_is_unicast(0x010000e0)) != 0, "Error checking unicast");

  /*rebound*/
  fail_if(pico_ipv4_rebound(f_NULL) != -1, "Error rebound frame");

  /*frame_push*/
  fail_if(pico_ipv4_frame_push(f_NULL, dst_NULL, PICO_PROTO_TCP) != -1, "Error push frame");
}
END_TEST

START_TEST (test_dhcp)
{
	struct pico_device* dev;
	struct pico_dhcpd_settings s = {0};
	struct pico_ip4 address = {.addr=long_be(0x0a280001)};
	struct pico_ip4 netmask = {.addr=long_be(0xffffff00)};

	pico_stack_init();
	dev = pico_null_create("null");
	pico_ipv4_link_add(dev, address, netmask);

	s.dev = dev;

	fail_if(pico_dhcp_server_initiate(&s));
}
END_TEST


Suite *pico_suite(void)
{
  Suite *s = suite_create("PicoTCP");

  TCase *ipv4 = tcase_create("IPv4");
  tcase_add_test(ipv4, test_ipv4);
  suite_add_tcase(s, ipv4);

	TCase *dhcp = tcase_create("DHCP");
	tcase_add_test(dhcp, test_dhcp);
	suite_add_tcase(s, dhcp);

  return s;
}



int main(void) {
  int fails;
  Suite *s = pico_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  fails = srunner_ntests_failed(sr);
  srunner_free(sr);
  return fails;
}
