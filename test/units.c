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
  struct pico_device *dev0, *dev1, *dev2;
  struct pico_ip4 a0, a1, a2, r0, r1, r2, nm24, nm16, nm32, zero={}, gw1, gw2, ret;
  struct pico_ipv4_link *l0, *l1, *l2;

  dev0 = pico_null_create("nul0");
  dev1 = pico_null_create("nul1");
  dev2 = pico_null_create("nul2");

  pico_stack_init();

  memset(&a0, 1, sizeof(a0));
  memset(&a1, 2, sizeof(a0));
  memset(&a2, 3, sizeof(a0));
  nm16.addr = long_be(0xFFFF0000);
  nm24.addr = long_be(0xFFFFFF00);
  nm32.addr = long_be(0xFFFFFFFF);
  gw1.addr  = long_be(0x020202F0);
  gw2.addr  = long_be(0x030303F0);


  pico_ipv4_link_add(dev0, a0, nm16);
  pico_ipv4_link_add(dev1, a1, nm16);
  pico_ipv4_link_add(dev2, a2, nm24);

  fail_unless(pico_ipv4_link_find(&a0) == dev0, "pico_ipv4_link_find");
  fail_unless(pico_ipv4_link_find(&a1) == dev1, "pico_ipv4_link_find");
  fail_unless(pico_ipv4_link_find(&a2) == dev2, "pico_ipv4_link_find");

  r0.addr = long_be(0x04040401);
  r1.addr = long_be(0x04040402);
  r2.addr = long_be(0x04040403);
  l0 = pico_ipv4_link_get(&a0);
  l1 = pico_ipv4_link_get(&a1);
  l2 = pico_ipv4_link_get(&a2);
  fail_if(l0 == NULL, "pico_ipv4_get_link");
  fail_if(l1 == NULL, "pico_ipv4_get_link");
  fail_if(l2 == NULL, "pico_ipv4_get_link");
  fail_unless(strcmp(l0->dev->name, "nul0") == 0, "wrong link");
  fail_unless(strcmp(l1->dev->name, "nul1") == 0, "wrong link");
  fail_unless(strcmp(l2->dev->name, "nul2") == 0, "wrong link");

  pico_ipv4_route_add(r0, nm24, zero, 1, l0);
  pico_ipv4_route_add(r1, nm32, gw1, 1, l1);
  pico_ipv4_route_add(r2, nm32, gw2, 1, l2);

  ret = pico_ipv4_route_get_gateway(&r0);
  fail_if(ret.addr != 0, "gw find: returned wrong route");
  ret = pico_ipv4_route_get_gateway(&r1);
  fail_if(ret.addr != gw1.addr, "gw find: returned wrong route");
  ret = pico_ipv4_route_get_gateway(&r2);
  fail_if(ret.addr != gw2.addr, "gw find: returned wrong route");

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
