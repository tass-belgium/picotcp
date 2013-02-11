/* PicoTCP unit test platform */
/* How does it works: 
 * 1. Define your unit test function as described in the check manual
 * 2. Add your test to the suite in the pico_suite() function
 */


#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_dev_null.h"
#include "pico_device.h"
#include <check.h>

START_TEST (test_ipv4)
{
  #define IP_TST_SIZ 256
  int i;

  struct pico_device *dev[IP_TST_SIZ];
  char devname[8];
  struct pico_ip4 a[IP_TST_SIZ], nm16, nm32, gw[IP_TST_SIZ], r[IP_TST_SIZ], ret;
  struct pico_ipv4_link *l[IP_TST_SIZ];

  pico_stack_init();

  nm16.addr = long_be(0xFFFF0000);
  nm32.addr = long_be(0xFFFFFFFF);
  for (i = 0; i < IP_TST_SIZ; i++) {
    snprintf(devname, 8, "nul%d", i);
    dev[i] = pico_null_create(devname);
    a[i].addr = long_be(0x0a000001 + (i << 16));
    pico_ipv4_link_add(dev[i], a[i], nm16);
  }

  for (i = 0; i < IP_TST_SIZ; i++) {
    gw[i].addr = long_be(0x0a0000f0 + (i << 16));
    r[i].addr = long_be(0x0c00001 + (i << 16));
    fail_unless(pico_ipv4_link_find(&a[i]) == dev[i], "pico_ipv4_link_find");
    l[i] = pico_ipv4_link_get(&a[i]);
    fail_if(l[i] == NULL, "Link not found...");
    fail_if(pico_ipv4_route_add(r[i], nm32, gw[i], 1, l[i]) != 0, "Error adding route");

  }
  for (i = 0; i < IP_TST_SIZ; i++) {
    ret = pico_ipv4_route_get_gateway(&r[i]);
    fail_if(ret.addr != gw[i].addr, "gw find: returned wrong route");
  }
}
END_TEST


Suite *pico_suite(void)
{
  Suite *s = suite_create("PicoTCP");

  TCase *ipv4 = tcase_create("IPv4");
  tcase_add_test(ipv4, test_ipv4);
  suite_add_tcase(s, ipv4);

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
