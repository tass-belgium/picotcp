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

#define VALUE_BETWEEN_RANGE(val, min, max)      \
  (((val) > (min)) && ((val) < (max)))
#define EXPIRE_TIME_RANGE_MS               (5)
#define TIME_CHECK(time, expected)         VALUE_BETWEEN_RANGE(time, expected-EXPIRE_TIME_RANGE_MS, expected+EXPIRE_TIME_RANGE_MS)

enum ND_PACKET_TYPE {
  PACKET_TYPE_NORMAL = 0,
  PACKET_TYPE_BAD_LEN,
  PACKET_TYPE_DOUBLE_OPTION,
};

static char all_node_multicast_addr_s[] = "ff02::1";

static int pico_icmp6_checksum_success_flag = 1;

static int pico_ns_solicited_count = 0, pico_ns_unicast_count = 0, pico_ns_count = 0;

const uint8_t router_adv_mac[PICO_SIZE_ETH] = {
  0x00, 0x00, 0x00, 0x00, 0xa0, 0xa0
};
const char router_adv_prefix[] = "3ffe:501:ffff:100::";

static struct pico_icmp6_opt_prefix router_prefix_option = {
  .type = PICO_ND_OPT_PREFIX,
  .len = sizeof(struct pico_icmp6_opt_prefix) >> 3,
  .prefix_len = 64, /* Only /64 are forwarded */
  .res = 0,
  .aac = 1,
  .onlink = 1,
  .val_lifetime = 86400,
  .pref_lifetime = 14400,
  .reserved = 0,
};

Suite *pico_suite(void);

uint16_t pico_icmp6_checksum(struct pico_frame *f)
{
  IGNORE_PARAMETER(f);

  if (pico_icmp6_checksum_success_flag)
    return 0;

  return 1;
}

int pico_icmp6_router_solicitation(struct pico_device *dev, struct pico_ip6 *src, struct pico_ip6 *dst)
{
  IGNORE_PARAMETER(dev);
  IGNORE_PARAMETER(src);
  IGNORE_PARAMETER(dst);

  return 0;
}

int pico_icmp6_neighbor_solicitation(struct pico_device *dev, struct pico_ip6 *tgt, uint8_t type, struct pico_ip6 *dst)
{
  IGNORE_PARAMETER(dev);
  IGNORE_PARAMETER(tgt);
  IGNORE_PARAMETER(type);
  IGNORE_PARAMETER(dst);

  if (type == PICO_ICMP6_ND_UNICAST) {
    pico_ns_unicast_count++;
  } else if (type == PICO_ICMP6_ND_SOLICITED) {
    pico_ns_solicited_count++;
  }

  pico_ns_count++;

  return 0;
}

int pico_datalink_send(struct pico_frame *f) {
  IGNORE_PARAMETER(f);

  /* Always return success */
  return 1;
}

static struct pico_frame *make_router_adv(struct pico_device *dev, enum ND_PACKET_TYPE packet_type)
{
  /*
   * Router solicitation from ND tahi tests v6LC.2.2.2 Part B
   * has link layer addr option + prefix option
   */
  struct pico_frame *adv = NULL;
  struct pico_icmp6_hdr *icmp6_hdr = NULL;
  struct pico_icmp6_opt_lladdr *lladdr = NULL;
  struct pico_icmp6_opt_prefix *prefix = NULL;
  uint16_t len = 0;
  uint8_t *nxt_opt = NULL;
  uint8_t number_of_lladdr_options = 1;
  int i = 0;

  if (packet_type == PACKET_TYPE_DOUBLE_OPTION) {
    len = PICO_ICMP6HDR_ROUTER_ADV_SIZE + 2 * PICO_ICMP6_OPT_LLADDR_SIZE + sizeof(struct pico_icmp6_opt_prefix);
    number_of_lladdr_options = 2;
  } else {
    len = PICO_ICMP6HDR_ROUTER_ADV_SIZE + PICO_ICMP6_OPT_LLADDR_SIZE + sizeof(struct pico_icmp6_opt_prefix);
    number_of_lladdr_options = 1;
  }

  adv = pico_proto_ipv6.alloc(&pico_proto_ipv6, dev, len);
  fail_if(!adv);

  adv->payload = adv->transport_hdr + len;
  adv->payload_len = 0;

  icmp6_hdr = (struct pico_icmp6_hdr *)adv->transport_hdr;
  icmp6_hdr->type = PICO_ICMP6_ROUTER_ADV;
  icmp6_hdr->code = 0;
  icmp6_hdr->msg.info.router_adv.life_time = short_be(45);
  icmp6_hdr->msg.info.router_adv.hop = 64;
  nxt_opt = (uint8_t *)&icmp6_hdr->msg.info.router_adv + sizeof(struct router_adv_s);

  prefix =  (struct pico_icmp6_opt_prefix *)nxt_opt;
  prefix->type = router_prefix_option.type;
  if (packet_type == PACKET_TYPE_BAD_LEN) {
    prefix->len = 0;
  } else {
    prefix->len = router_prefix_option.len;
  }
  prefix->prefix_len = router_prefix_option.prefix_len;
  prefix->aac = router_prefix_option.aac;
  prefix->onlink = router_prefix_option.onlink;
  prefix->val_lifetime = router_prefix_option.val_lifetime;
  prefix->pref_lifetime = router_prefix_option.pref_lifetime;

  pico_string_to_ipv6(router_adv_prefix, prefix->prefix.addr);
  nxt_opt += (sizeof (struct pico_icmp6_opt_prefix));

  for (i = 0; i < number_of_lladdr_options; i++) {
    lladdr = (struct pico_icmp6_opt_lladdr *)nxt_opt;

    lladdr->type = PICO_ND_OPT_LLADDR_SRC;
    /*
     * lladdr option is 8 bytes long
     * sizeof(struct pico_icmp6_opt_lladdr) is 10 bytes big
     * but actually the size of this option should be 8 bytes
     * but below method works because: !!! 10/8 == 1 !!!
     */
    lladdr->len = sizeof(struct pico_icmp6_opt_lladdr) >> 3;

    memcpy(&lladdr->addr, &router_adv_mac, PICO_SIZE_ETH);
    /*
     * see above comment
     */
    nxt_opt += lladdr->len << 3;
  }

  icmp6_hdr->crc = short_be(pico_icmp6_checksum(adv));

  return adv;
}

START_TEST(tc_pico_ipv6_neighbor_compare)
{
  struct pico_ipv6_neighbor a = { 0 }, b = { 0 };
  struct pico_ip6 address_a = { 0 }, address_b = { 0 };

  /* Same addresses */
  a.address = address_a;
  b.address = address_b;
  fail_if(pico_ipv6_neighbor_compare(&a, &b) != 0, "Neighbours A and B have same ipv6 addr, not true?");

  /* a has different address */
  a.address.addr[0] = 1;
  fail_if(pico_ipv6_neighbor_compare(&a, &b) != 1, "Neighbour A has different ipv6 addr, not detected?");

  /* Reset */
  a.address = address_a;
  b.address = address_b;

  /* b has different address */
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

  /* a has different address */
  neighbor_a.address.addr[0] = 1;
  fail_if(pico_ipv6_router_compare(&a, &b) != 1, "Router A has different ipv6 addr, not detected?");

  /* Reset */
  neighbor_a.address = address_a;
  neighbor_b.address = address_b;

  /* b has different address */
  neighbor_b.address.addr[0] = 1;
  fail_if(pico_ipv6_router_compare(&a, &b) != -1, "Router B has different ipv6 addr, not detected?");
}
END_TEST
START_TEST(tc_pico_ipv6_nd_qcompare)
{
  struct pico_frame a = { 0 }, b = { 0 };
  struct pico_ipv6_hdr a_hdr = { 0 }, b_hdr =  { 0 };
  struct pico_ip6 a_dest_addr = { 0 }, b_dest_addr = { 0 };

  /* Same packets */
  a_hdr.dst = a_dest_addr;
  b_hdr.dst = b_dest_addr;

  a.net_hdr = (uint8_t *)&a_hdr;
  b.net_hdr = (uint8_t *)&b_hdr;

  fail_if(pico_ipv6_nd_qcompare(&a, &b) != 0, "Frames A and B have same ipv6 addr, not true?");

  /* a has different address */
  a_hdr.dst.addr[0] = 1;
  fail_if(pico_ipv6_nd_qcompare(&a, &b) != 1, "Frame A has different ipv6 addr, not detected?");

  /* Reset */
  a_hdr.dst = a_dest_addr;
  b_hdr.dst = b_dest_addr;

  /* b has different address */
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
START_TEST(tc_icmp6_initial_checks)
{
  struct pico_frame a = { 0 };
  struct pico_ipv6_hdr ipv6_hdr = { 0 };
  struct pico_icmp6_hdr icmp6_hdr = { 0 };


  fail_if(icmp6_initial_checks(NULL) != -1, "NULL arg gives bad return value");

  a.net_hdr = (uint8_t *)&ipv6_hdr;
  a.transport_hdr = (uint8_t *)&icmp6_hdr;

  /* Valid headers */
  ipv6_hdr.hop = 255;
  icmp6_hdr.code = 0;
  pico_icmp6_checksum_success_flag = 1;

  fail_if(icmp6_initial_checks(&a) != 0, "Valid headers should return success");

  /* Invalid checksum */
  pico_icmp6_checksum_success_flag = 0;
  fail_if(icmp6_initial_checks(&a) != -1, "Invalid checksum should return failure");

  /* Reset to valid */
  ipv6_hdr.hop = 255;
  icmp6_hdr.code = 0;
  pico_icmp6_checksum_success_flag = 1;

  /* Invalid icmp6 hdr code */
  icmp6_hdr.code = 1;           /* Anything but 0 is invalid */
  fail_if(icmp6_initial_checks(&a) != -1, "Invalid icmp6 code should return failure");

  /* Reset to valid */
  ipv6_hdr.hop = 255;
  icmp6_hdr.code = 0;
  pico_icmp6_checksum_success_flag = 1;

  /* Invalid hop count */
  ipv6_hdr.hop = 254;           /* Anything but 255 is invalid */
  fail_if(icmp6_initial_checks(&a) != -1, "Invalid hop count should return failure");
}
END_TEST
START_TEST(tc_pico_hw_addr_len)
{
  struct pico_device dummy_dev = { 0 };
  struct pico_icmp6_opt_lladdr opt = { 0 };

  dummy_dev.hostvars.lowpan_flags &= (uint8_t)(~PICO_6LP_FLAG_LOWPAN); /* Not a 6LP device */
  fail_if(pico_hw_addr_len(&dummy_dev, &opt) != PICO_SIZE_ETH, "HW addr len is different from ETH for non 6LP device");

  dummy_dev.hostvars.lowpan_flags = PICO_6LP_FLAG_LOWPAN; /* a 6LP device */
  opt.len = 1;                  /* short 6lowpan option */
  fail_if(pico_hw_addr_len(&dummy_dev, &opt) != SIZE_6LOWPAN_SHORT, "HW addr len is different from SIZE_6LOWPAN_SHORT for a 6LP device with optlen == 1");

  dummy_dev.hostvars.lowpan_flags = PICO_6LP_FLAG_LOWPAN; /* a 6LP device */
  opt.len = 0;                  /* extended 6lowpan option */
  fail_if(pico_hw_addr_len(&dummy_dev, &opt) != SIZE_6LOWPAN_EXT, "HW addr len is different from SIZE_6LOWPAN_SHORT for a 6LP device with optlen == 1");
}
END_TEST
START_TEST(tc_pico_nd_get_oldest_queued_frame)
{
  struct pico_frame a, b, c;
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };
  struct pico_ip6 addr_1 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x1b
    }
  };
  struct pico_ipv6_hdr hdr_0 = {0};
  struct pico_ipv6_hdr hdr_1 = {0};

  hdr_0.dst = addr_0;
  hdr_1.dst = addr_1;

  /* No queued frames yet */
  fail_if(pico_nd_get_oldest_queued_frame(&addr_0) != NULL, "No queued frames yet, should have returned NULL");
  fail_if(pico_nd_get_oldest_queued_frame(&addr_1) != NULL, "No queued frames yet, should have returned NULL");

  a.timestamp = 0;
  b.timestamp = 1;
  c.timestamp = 2;

  a.net_hdr = (uint8_t *)&hdr_0;
  b.net_hdr = (uint8_t *)&hdr_0;
  c.net_hdr = (uint8_t *)&hdr_0;

  pico_tree_insert(&IPV6NQueue, &a);
  pico_tree_insert(&IPV6NQueue, &b);
  pico_tree_insert(&IPV6NQueue, &c);

  /* Frames queued with same dest addresses */
  fail_if(pico_nd_get_oldest_queued_frame(&addr_0) != &a, "Queued frames in, shouldn't have returned NULL");
  fail_if(pico_nd_get_oldest_queued_frame(&addr_1) != NULL, "No queued frames for this dest yet, should have returned NULL");

  /* 2 packets with same timestamp */
  a.timestamp = 1;
  b.timestamp = 1;
  c.timestamp = 2;

  fail_if(pico_nd_get_oldest_queued_frame(&addr_0) != &a && pico_nd_get_oldest_queued_frame(&addr_0) != &b, "Queued frames in, shouldn't have returned NULL");
  fail_if(pico_nd_get_oldest_queued_frame(&addr_1) != NULL, "No queued frames for this dest yet, should have returned NULL");

  /* Frames queued with different dest addresses */
  a.timestamp = 0;
  b.timestamp = 1;
  c.timestamp = 2;

  a.net_hdr = (uint8_t *)&hdr_1;
  b.net_hdr = (uint8_t *)&hdr_0;
  c.net_hdr = (uint8_t *)&hdr_0;

  fail_if(pico_nd_get_oldest_queued_frame(&addr_1) != &a, "No queued frames for this dest yet, should have returned NULL");
  fail_if(pico_nd_get_oldest_queued_frame(&addr_0) != &b, "Queued frames in, shouldn't have returned NULL");

  pico_tree_delete(&IPV6NQueue, &a);
  pico_tree_delete(&IPV6NQueue, &b);
  pico_tree_delete(&IPV6NQueue, &c);
}
END_TEST
START_TEST(tc_ipv6_duplicate_detected)
{
  /* TODO: test this: static void ipv6_duplicate_detected(struct pico_ipv6_link *l) */
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

  /* Cleanup */
  pico_tree_delete(&NCache, &a);
  pico_tree_delete(&NCache, &b);
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

  /* Cleanup */
  pico_tree_delete(&RCache, &a);
  pico_tree_delete(&RCache, &b);
}
END_TEST
START_TEST(tc_pico_nd_get_default_router)
{
  struct pico_ipv6_router r0 = { 0 }, r1 = { 0 }, r2 = { 0 };
  struct pico_ipv6_neighbor n0 = { 0 }, n1 = { 0 }, n2 = { 0 };
  struct pico_ipv6_link link = { 0 };
  char ipstr0[] = "2001:0db8:130f:0000:0000:09c0:876a:130b";
  char ipstr1[] = "2001:1db8:130f:0000:0000:09c0:876a:130b";
  char ipstr2[] = "2001:b8:130f:0000:0000:09c0:876a:130b";

  /* Setup of routers */
  r0.router = &n0;
  r1.router = &n1;
  r2.router = &n2;
  r0.link = &link;
  r1.link = &link;
  r2.link = &link;
  pico_string_to_ipv6(ipstr0, r0.router->address.addr);
  pico_string_to_ipv6(ipstr1, r1.router->address.addr);
  pico_string_to_ipv6(ipstr2, r2.router->address.addr);

  /* No routers in Cache */
  fail_if(pico_nd_get_default_router() != NULL, "No router in RCache, should have returned NULL");

  /* Routers in rcache, but don't flag it as default router */
  pico_tree_insert(&RCache, &r0);
  pico_tree_insert(&RCache, &r1);
  pico_tree_insert(&RCache, &r2);
  fail_if(pico_nd_get_default_router() != NULL, "No default router in RCache, should have returned NULL");

  /* Flag one router as default */
  r1.is_default = 1;
  fail_if(pico_nd_get_default_router() != &r1, "Default router in RCache, should have been returned");

  /* Cleanup */
  pico_tree_delete(&RCache, &r0);
  pico_tree_delete(&RCache, &r1);
  pico_tree_delete(&RCache, &r2);
}
END_TEST
START_TEST(tc_pico_nd_set_new_expire_time)
{
  struct pico_ipv6_neighbor n = {
    0
  };
  struct pico_device d = { {0} };
  pico_time now = 0;

  n.dev = &d;

  d.hostvars.retranstime = 666;
  d.hostvars.reachabletime = PICO_ND_REACHABLE_TIME;
  /*
   * We will test if the expire time is between a certain range,
   * instead of comparing with the exact value set in the function
   *
   * This is to reduce machine/test-run dependency because of the use of PICO_TIME_MS()
   */

  n.state = PICO_ND_STATE_INCOMPLETE;
  pico_nd_set_new_expire_time(&n);
  now = PICO_TIME_MS();
  fail_unless(VALUE_BETWEEN_RANGE(n.expire, now + d.hostvars.retranstime - EXPIRE_TIME_RANGE_MS, now + d.hostvars.retranstime + EXPIRE_TIME_RANGE_MS));

  n.state = PICO_ND_STATE_REACHABLE;
  pico_nd_set_new_expire_time(&n);
  now = PICO_TIME_MS();
  fail_unless(VALUE_BETWEEN_RANGE(n.expire, now + d.hostvars.reachabletime - EXPIRE_TIME_RANGE_MS, now + d.hostvars.reachabletime + EXPIRE_TIME_RANGE_MS));

  n.state = PICO_ND_STATE_STALE;
  pico_nd_set_new_expire_time(&n);
  now = PICO_TIME_MS();
  fail_unless(VALUE_BETWEEN_RANGE(n.expire, now + PICO_ND_DELAY_FIRST_PROBE_TIME - EXPIRE_TIME_RANGE_MS, now + PICO_ND_DELAY_FIRST_PROBE_TIME + EXPIRE_TIME_RANGE_MS));

  n.state = PICO_ND_STATE_DELAY;
  pico_nd_set_new_expire_time(&n);
  now = PICO_TIME_MS();
  fail_unless(VALUE_BETWEEN_RANGE(n.expire, now + PICO_ND_DELAY_FIRST_PROBE_TIME - EXPIRE_TIME_RANGE_MS, now + PICO_ND_DELAY_FIRST_PROBE_TIME + EXPIRE_TIME_RANGE_MS));

  n.state = PICO_ND_STATE_PROBE;
  pico_nd_set_new_expire_time(&n);
  now = PICO_TIME_MS();
  fail_unless(VALUE_BETWEEN_RANGE(n.expire, now + d.hostvars.retranstime - EXPIRE_TIME_RANGE_MS, now + d.hostvars.retranstime + EXPIRE_TIME_RANGE_MS));
}
END_TEST
START_TEST(tc_pico_ipv6_assign_default_router_on_link)
{
  struct pico_ipv6_router *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL;
  struct pico_ipv6_neighbor *n0 = NULL, *n1 = NULL, *n2 = NULL, *n3 = NULL;
  struct pico_ipv6_link link0 = { 0 }, link1 = { 0 };
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };
  struct pico_ip6 addr_1 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x1b
    }
  };
  struct pico_ip6 addr_2 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x2b
    }
  };
  struct pico_ip6 addr_3 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x3b
    }
  };
  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  /* Setup of routers */
  n0 = pico_nd_create_entry(&addr_0, dummy_dev);
  n1 = pico_nd_create_entry(&addr_1, dummy_dev);
  n2 = pico_nd_create_entry(&addr_2, dummy_dev);
  n3 = pico_nd_create_entry(&addr_3, dummy_dev);

  r0 = PICO_ZALLOC(sizeof(struct pico_ipv6_router));
  r1 = PICO_ZALLOC(sizeof(struct pico_ipv6_router));
  r2 = PICO_ZALLOC(sizeof(struct pico_ipv6_router));
  r3 = PICO_ZALLOC(sizeof(struct pico_ipv6_router));

  r0->router = n0;
  r1->router = n1;
  r2->router = n2;
  r3->router = n3;
  r0->link = &link0;
  r1->link = &link0;
  r2->link = &link0;
  r3->link = &link1;             /* One router with different link */

  /* No routers in Cache */
  fail_if(pico_nd_get_default_router() != NULL, "No router in RCache, should have returned NULL");

  /* Routers in rcache, but don't flag it as default router */
  pico_tree_insert(&RCache, r0);
  pico_tree_insert(&RCache, r1);
  pico_tree_insert(&RCache, r2);
  pico_tree_insert(&RCache, r3);
  fail_if(pico_nd_get_default_router() != NULL, "No default router in RCache, should have returned NULL");

  pico_ipv6_assign_router_on_link(0, &link0); /* Don't assign default router */

  fail_if(pico_nd_get_default_router() != NULL, "No default router in RCache, should have returned NULL");

  pico_ipv6_assign_router_on_link(1, &link0); /* Assign default router */

  fail_if(pico_nd_get_default_router() == NULL, "Default router in RCache with link0, shouldn't have returned NULL");
  fail_if(pico_nd_get_default_router() == r3, "Default router in RCache with link0, shouldn't have returned router with link1");

  /* Cleanup */
  pico_nd_delete_entry(&n0->address);
  pico_nd_delete_entry(&n1->address);
  pico_nd_delete_entry(&n2->address);
  pico_nd_delete_entry(&n3->address);
  pico_device_destroy(dummy_dev);
}
END_TEST
START_TEST(tc_pico_ipv6_set_router_link)
{
  struct pico_ipv6_router r0 = { 0 }, r1 = { 0 }, r2 = { 0 }, r3 = { 0 };
  struct pico_ipv6_neighbor n0 = { 0 }, n1 = { 0 }, n2 = { 0 }, n3 = { 0 };
  struct pico_ipv6_link link0 = { 0 }, link1 = { 0 };
  char ipstr0[] = "2001:0db8:130f:0000:0000:09c0:876a:130b";
  char ipstr1[] = "2001:1db8:130f:0000:0000:09c0:876a:130b";
  char ipstr2[] = "2001:b8:130f:0000:0000:09c0:876a:130b";
  char ipstr3[] = "2001:8:130f:0000:0000:09c0:876a:130b";

  /* Setup of routers */
  r0.router = &n0;
  r1.router = &n1;
  r2.router = &n2;
  r3.router = &n3;
  pico_string_to_ipv6(ipstr0, r0.router->address.addr);
  pico_string_to_ipv6(ipstr1, r1.router->address.addr);
  pico_string_to_ipv6(ipstr2, r2.router->address.addr);
  pico_string_to_ipv6(ipstr3, r3.router->address.addr);

  /* NULL args */
  pico_ipv6_set_router_link(NULL, NULL);

  /* No routers in RCache */
  pico_ipv6_set_router_link(&r0.router->address, &link0);

  fail_if(r0.link == &link0, "Router not yet in RCache, link should not have been set");

  /* Routers in RCache */
  pico_tree_insert(&RCache, &r0);
  pico_tree_insert(&RCache, &r1);
  pico_tree_insert(&RCache, &r2);
  pico_tree_insert(&RCache, &r3);

  /* Setting router links */
  pico_ipv6_set_router_link(&r0.router->address, &link0);
  pico_ipv6_set_router_link(&r1.router->address, &link1);
  pico_ipv6_set_router_link(&r2.router->address, &link0);
  pico_ipv6_set_router_link(&r3.router->address, &link1);

  fail_if(r0.link != &link0, "Router in RCache, link should have been set");
  fail_if(r1.link != &link1, "Router in RCache, link should have been set");
  fail_if(r2.link != &link0, "Router in RCache, link should have been set");
  fail_if(r3.link != &link1, "Router in RCache, link should have been set");

  /* Cleanup */
  pico_tree_delete(&RCache, &r0);
  pico_tree_delete(&RCache, &r1);
  pico_tree_delete(&RCache, &r2);
  pico_tree_delete(&RCache, &r3);
}
END_TEST
START_TEST(tc_pico_ipv6_set_router_mtu)
{
  struct pico_ipv6_router r0 = { 0 }, r1 = { 0 }, r2 = { 0 }, r3 = { 0 };
  struct pico_ipv6_neighbor n0 = { 0 }, n1 = { 0 }, n2 = { 0 }, n3 = { 0 };
  struct pico_ipv6_link link0 = { 0 }, link1 = { 0 };
  uint32_t r0_mtu = 1500, r1_mtu = 2000, r2_mtu = 2500, r3_mtu = 3000;
  char ipstr0[] = "2001:0db8:130f:0000:0000:09c0:876a:130b";
  char ipstr1[] = "2001:1db8:130f:0000:0000:09c0:876a:130b";
  char ipstr2[] = "2001:b8:130f:0000:0000:09c0:876a:130b";
  char ipstr3[] = "2001:8:130f:0000:0000:09c0:876a:130b";

  /* Setup of routers */
  r0.router = &n0;
  r1.router = &n1;
  r2.router = &n2;
  r3.router = &n3;
  /* Setting router links */
  r0.link = &link0;
  r1.link = &link0;
  r2.link = &link0;
  r3.link = &link1;             /* One router with different link */
  pico_string_to_ipv6(ipstr0, r0.router->address.addr);
  pico_string_to_ipv6(ipstr1, r1.router->address.addr);
  pico_string_to_ipv6(ipstr2, r2.router->address.addr);
  pico_string_to_ipv6(ipstr3, r3.router->address.addr);

  /* NULL args */
  pico_ipv6_set_router_mtu(NULL, 0);

  /* No routers in RCache */
  pico_ipv6_set_router_mtu(&r0.router->address, r0_mtu);

  fail_if(r0.link->mtu == r0_mtu, "Router not yet in RCache, mtu should not have been set");

  /* Routers in RCache */
  pico_tree_insert(&RCache, &r0);
  pico_tree_insert(&RCache, &r1);
  pico_tree_insert(&RCache, &r2);
  pico_tree_insert(&RCache, &r3);

  /* Setting router mtu */
  /* TODO: should link->mtu change if we change mtu of non-default router?  */
  pico_ipv6_set_router_mtu(&r0.router->address, r0_mtu);
  fail_if(r0.link->mtu != r0_mtu, "Router in RCache, mtu should have been set");
  pico_ipv6_set_router_mtu(&r1.router->address, r1_mtu);
  fail_if(r1.link->mtu != r1_mtu, "Router in RCache, mtu should have been set");
  pico_ipv6_set_router_mtu(&r2.router->address, r2_mtu);
  fail_if(r2.link->mtu != r2_mtu, "Router in RCache, mtu should have been set");
  pico_ipv6_set_router_mtu(&r3.router->address, r3_mtu);
  fail_if(r3.link->mtu != r3_mtu, "Router in RCache, mtu should have been set");
  /* r3 and r2 have different links so setting mtu for r3 shouldn't affect r2 */
  fail_if(r2.link->mtu != r2_mtu, "Router in RCache, mtu should have been set");

  /* Cleanup */
  pico_tree_delete(&RCache, &r0);
  pico_tree_delete(&RCache, &r1);
  pico_tree_delete(&RCache, &r2);
  pico_tree_delete(&RCache, &r3);
}
END_TEST

static int frame_in_queued_frames(struct pico_frame *f)
{
  struct pico_tree_node *index = NULL;
  struct pico_frame *frame = NULL;
  int occurences = 0;

  pico_tree_foreach(index,&IPV6NQueue) {
    frame = index->keyValue;
    if (memcmp(frame, f, sizeof(*f)) == 0) {
      occurences++;
    }
  }

  return occurences;
}

START_TEST(tc_pico_ipv6_nd_postpone)
{
  struct pico_frame *frames[PICO_ND_MAX_FRAMES_QUEUED * 2] = { 0 };
  struct pico_ipv6_hdr hdrs[sizeof(frames)/sizeof(frames[0])] = { 0 };
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };
  struct pico_ip6 addr_1 = {
    .addr = {
      0x21, 0x21, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x1b
    }
  };
  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  int i = 0;

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  /*
   * Init frames
   */

  for (i = 0; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    frames[i] = pico_proto_ipv6.alloc(&pico_proto_ipv6, dummy_dev, 1);
    frames[i]->timestamp = (pico_time)i;
    frames[i]->net_hdr = (uint8_t *)&hdrs[i];
    hdrs[i].dst = addr_0;
  }

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&IPV6NQueue), "Test hasn't started, tree should be empty!");
  fail_unless(pico_tree_empty(&NCache), "Test hasn't started, no NCE should exist");

  {
    /*
     * First testcase:
     * - No NCE yet
     * - Postpone MAX frames
     * - Postpone MAX frames again (check if overwritten properly)
     */

    /* Postpone first PICO_ND_MAX_FRAMES_QUEUED */
    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      pico_ipv6_nd_postpone(frames[i]);
    }

    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should just be in queued frames tree once");
    }

    for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      fail_unless(frame_in_queued_frames(frames[i]) == 0, "Frame shouldn't be in queued frames tree");
    }

    /* Postpone next PICO_ND_MAX_FRAMES_QUEUED */
    for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      pico_ipv6_nd_postpone(frames[i]);
    }

    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      fail_unless(frame_in_queued_frames(frames[i]) == 0, "Frame shouldn't be in queued frames tree");
    }

    for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree only once");
    }

    pico_nd_delete_entry(&addr_0);
  }

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&IPV6NQueue), "Test hasn't started, tree should be empty!");
  fail_unless(pico_tree_empty(&NCache), "Test hasn't started, no NCE should exist");

  {
    /*
     * Second testcase:
     * - multiple NCEs already exists
     * - Postpone MAX frames for NCE 1
     * - Postpone MAX frames for NCE 2
     */
    pico_nd_create_entry(&addr_0, dummy_dev);
    pico_nd_create_entry(&addr_1, dummy_dev);

    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      hdrs[i].dst = addr_0;
    }

    for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      hdrs[i].dst = addr_1;
    }

    /* Postpone all frames */
    for (i = 0; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      pico_ipv6_nd_postpone(frames[i]);
    }

    for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
    }

    for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
      fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
    }

    pico_nd_delete_entry(&addr_0);
    pico_nd_delete_entry(&addr_1);
  }

  /* Cleanup */
  pico_device_destroy(dummy_dev);

  for (i = 0; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    pico_frame_discard(frames[i]);
  }
}
END_TEST
START_TEST(tc_pico_nd_clear_queued_packets)
{
  struct pico_frame *frames[2 * PICO_ND_MAX_FRAMES_QUEUED] = { 0 };
  struct pico_ipv6_hdr hdrs[sizeof(frames)/sizeof(frames[0])] = { 0 };
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };
  struct pico_ip6 addr_1 = {
    .addr = {
      0x21, 0x21, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x1b
    }
  };
  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  int i = 0;

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&IPV6NQueue), "Test hasn't started, tree should be empty!");

  /*
   * Init frames
   */
  for (i = 0; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    frames[i] = pico_proto_ipv6.alloc(&pico_proto_ipv6, dummy_dev, 1);
    frames[i]->timestamp = (pico_time)i;
    frames[i]->net_hdr = (uint8_t *)&hdrs[i];
    if (i < PICO_ND_MAX_FRAMES_QUEUED) {
      hdrs[i].dst = addr_0;
    } else {
      hdrs[i].dst = addr_1;
    }
    pico_tree_insert(&IPV6NQueue, frames[i]);
  }

  fail_if(pico_tree_empty(&IPV6NQueue), "Test started, tree shouldn't be empty!");

  for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
  }

  for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
  }

  pico_nd_clear_queued_packets(&addr_0);

  for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
  }

  pico_nd_clear_queued_packets(&addr_1);

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&IPV6NQueue), "Test is done, tree should be empty!");

  pico_device_destroy(dummy_dev);

  /* If a packet is not freed properly, asan should complain */
}
END_TEST
START_TEST(tc_pico_ipv6_nd_trigger_queued_packets)
{
  struct pico_frame *frames[2 * PICO_ND_MAX_FRAMES_QUEUED] = { 0 };
  struct pico_ipv6_hdr hdrs[sizeof(frames)/sizeof(frames[0])] = { 0 };
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };
  struct pico_ip6 addr_1 = {
    .addr = {
      0x21, 0x21, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x1b
    }
  };
  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  int i = 0;

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&IPV6NQueue), "Test hasn't started, tree should be empty!");

  /*
   * Init frames
   */
  for (i = 0; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    frames[i] = pico_proto_ipv6.alloc(&pico_proto_ipv6, dummy_dev, 1);
    frames[i]->timestamp = (pico_time)i;
    frames[i]->net_hdr = (uint8_t *)&hdrs[i];
    if (i < PICO_ND_MAX_FRAMES_QUEUED) {
      hdrs[i].dst = addr_0;
    } else {
      hdrs[i].dst = addr_1;
    }
    pico_tree_insert(&IPV6NQueue, frames[i]);
  }

  fail_if(pico_tree_empty(&IPV6NQueue), "Test started, tree shouldn't be empty!");

  for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
  }

  for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
  }

  pico_nd_trigger_queued_packets(&addr_0);

  for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 0, "Frame shouldn't be in queued frames tree");
  }

  for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 1, "Frame should be in queued frames tree");
  }

  pico_nd_trigger_queued_packets(&addr_1);

  for (i = 0; i < PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 0, "Frame shouldn't be in queued frames tree");
  }

  for (i = PICO_ND_MAX_FRAMES_QUEUED; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    fail_unless(frame_in_queued_frames(frames[i]) == 0, "Frame shouldn't be in queued frames tree");
  }

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&IPV6NQueue), "Test is done, tree should be empty!");

  pico_device_destroy(dummy_dev);

  for (i = 0; i < 2 * PICO_ND_MAX_FRAMES_QUEUED; ++i) {
    pico_frame_discard(frames[i]);
  }
}
END_TEST
START_TEST(tc_pico_nd_create_entry)
{
#define NUMBER_OF_NEIGHBORS (3)
  struct pico_ipv6_neighbor *n = NULL;
  struct pico_ip6 addr[NUMBER_OF_NEIGHBORS];
  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  int number_of_nce = 0, number_of_valid_nce = 0;
  struct pico_tree_node *index = NULL, *_tmp = NULL;
  int i = 0;
  pico_time expected;

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "Test hasn't started, no NCE should exist");

  /* Failing malloc */
  pico_set_mm_failure(1);
  fail_if(pico_nd_create_entry(&addr[i], dummy_dev) != NULL, "Created entry but malloc failed, should have returned NULL?");

  /* Sanity check, tree must still be empty */
  fail_unless(pico_tree_empty(&NCache), "Test started, but attempt to create NCE failed, tree should still be empty");

  for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
    addr[i].addr[0] = (uint8_t)i;
    pico_nd_create_entry(&addr[i], dummy_dev);
  }
  expected = PICO_TIME_MS() + ONE_MINUTE_MS;

  pico_tree_foreach(index,&NCache) {
    n = index->keyValue;

    for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
      if (pico_ipv6_compare(&n->address, &addr[i]) == 0) {
        if (n->dev == dummy_dev && n->state == PICO_ND_STATE_INCOMPLETE && TIME_CHECK(n->expire, expected)) {
          number_of_valid_nce++;
        }
      }
    }

    number_of_nce++;
  }

  fail_unless(number_of_nce == NUMBER_OF_NEIGHBORS, "We created NCEs, should be in the NCache tree");
  fail_unless(number_of_valid_nce == NUMBER_OF_NEIGHBORS, "We created NCEs, should all be in the NCache tree");

  /* Cleanup */
  pico_device_destroy(dummy_dev);
  pico_tree_foreach_safe(index, &NCache, _tmp)
  {
    n = index->keyValue;
    pico_tree_delete(&NCache, n);
    PICO_FREE(n);
  }

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "End of test, NCache should be empty");
}
END_TEST
START_TEST(tc_pico_nd_delete_entry)
{
#define NUMBER_OF_NEIGHBORS (3)
  struct pico_ipv6_neighbor *neighbors[NUMBER_OF_NEIGHBORS] = { 0 };
  struct pico_ipv6_router *routers[NUMBER_OF_NEIGHBORS] = { 0 };
  struct pico_frame *frames[NUMBER_OF_NEIGHBORS] = { 0 };
  struct pico_ipv6_hdr hdrs[NUMBER_OF_NEIGHBORS] = { 0 };
  struct pico_ip6 addr[NUMBER_OF_NEIGHBORS] = { 0 };
  struct pico_tree_node *index = NULL;
  int i = 0, number_of_nce = 0, number_of_rce = 0, number_of_frames = 0;

  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "Test hasn't started, no NCE should exist");
  fail_unless(pico_tree_empty(&RCache), "Test hasn't started, no RCE should exist");
  fail_unless(pico_tree_empty(&IPV6NQueue), "Test hasn't started, no queued frames should exist");

  /* Test 1
   * Create NUMBER_OF_NEIGHBORS NCE entries, then delete them
   */
  for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
    neighbors[i] = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
    addr[i].addr[0] = (uint8_t)i;
    neighbors[i]->address = addr[i];

    pico_tree_insert(&NCache, neighbors[i]);
  }

  for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
    pico_nd_delete_entry(&addr[i]);
  }

  pico_tree_foreach(index, &NCache)
  {
    number_of_nce++;
  }

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "NCE created and deleted, NCache should be empty");
  fail_if(number_of_nce, "All NCE should have been deleted");

  /* Reset */
  number_of_nce = 0;
  number_of_rce = 0;

  /* Test 2
   * Create NUMBER_OF_NEIGHBORS NCE,
   * Also create some RCE
   * then delete them
   */
  for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
    neighbors[i] = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
    routers[i] = PICO_ZALLOC(sizeof(struct pico_ipv6_router));

    routers[i]->router = neighbors[i];

    addr[i].addr[0] = (uint8_t)i;
    neighbors[i]->address = addr[i];
    neighbors[i]->is_router = 1;

    pico_tree_insert(&NCache, neighbors[i]);
    pico_tree_insert(&RCache, routers[i]);
  }

  pico_tree_foreach(index, &NCache)
  {
    number_of_nce++;
  }
  pico_tree_foreach(index, &RCache)
  {
    number_of_rce++;
  }

  fail_unless(number_of_nce == NUMBER_OF_NEIGHBORS, "NCEs should have been created");
  fail_unless(number_of_rce == NUMBER_OF_NEIGHBORS, "RCEs should have been created");

  for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
    pico_nd_delete_entry(&addr[i]);
  }

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "NCE created and deleted, NCache should be empty");
  fail_unless(pico_tree_empty(&RCache), "RCE created and deleted, NCache should be empty");

  /* Reset */
  number_of_nce = 0;
  number_of_rce = 0;

  /* Test 3
   * Create NUMBER_OF_NEIGHBORS NCE,
   * Also create some queued frames
   * then delete NCE
   */

  for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
    neighbors[i] = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));

    addr[i].addr[0] = (uint8_t)i;
    neighbors[i]->address = addr[i];

    pico_tree_insert(&NCache, neighbors[i]);


    frames[i] = pico_proto_ipv6.alloc(&pico_proto_ipv6, dummy_dev, 1);
    frames[i]->timestamp = (pico_time)i;
    frames[i]->net_hdr = (uint8_t *)&hdrs[i];
    hdrs[i].dst = addr[i];

    pico_tree_insert(&IPV6NQueue, frames[i]);
  }

  pico_tree_foreach(index, &NCache)
  {
    number_of_nce++;
  }

  pico_tree_foreach(index, &IPV6NQueue)
  {
    number_of_frames++;
  }

  fail_unless(number_of_nce == NUMBER_OF_NEIGHBORS, "NCEs should have been created");
  fail_unless(number_of_frames == NUMBER_OF_NEIGHBORS, "Frames should be in Queue tree");

  for (i = 0; i < NUMBER_OF_NEIGHBORS; ++i) {
    pico_nd_delete_entry(&addr[i]);
  }

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "All NCEs should have been deleted");
  fail_unless(pico_tree_empty(&IPV6NQueue), "All queued frames should have been deleted");

  pico_device_destroy(dummy_dev);
}
END_TEST
START_TEST(tc_pico_nd_create_rce)
{
  struct pico_ipv6_neighbor *n = NULL;
  struct pico_ipv6_router *r = NULL;

  /* Test 1: NULL args */
  fail_unless(pico_nd_create_rce(NULL) == NULL, "Providing NULL should return NULL");

  /* Test 2: Normal case */
  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&RCache), "Test hasn't started, tree should be empty");

  n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));

  r = pico_nd_create_rce(n);

  fail_unless(r, "RCE should have been created");
  fail_unless(n->is_router, "is_router flag should have been set");
  fail_if(pico_tree_empty(&RCache), "Test done, RCE should have been created");

  /* Cleanup */
  pico_tree_delete(&RCache, r);
  PICO_FREE(r);
  n->is_router = 0;

  /* Test 3: Malloc failure - 1 */
  pico_set_mm_failure(1);

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&RCache), "Test hasn't started, tree should be empty");

  r = pico_nd_create_rce(n);

  fail_if(r, "RCE shouldn't have been created");
  fail_if(n->is_router, "is_router flag shouldn't have been set");
  fail_unless(pico_tree_empty(&RCache), "Test done, RCE shouldn't have been created");

  /* Cleanup */
  n->is_router = 0;

  /* Test 4: Malloc failure - 2 */
  pico_set_mm_failure(2);

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&RCache), "Test hasn't started, tree should be empty");

  r = pico_nd_create_rce(n);

  fail_if(n->is_router, "is_router flag shouldn't have been set");
  fail_unless(pico_tree_empty(&RCache), "Test done, RCE shouldn't have been created");

  PICO_FREE(n);
}
END_TEST
START_TEST(tc_pico_nd_delete_rce)
{
  struct pico_ipv6_neighbor *n = NULL;
  struct pico_ipv6_router *r = NULL;

  /* Test 1: NULL args
   * This mustn't produce any side-effects
   */
  pico_nd_delete_rce(NULL);

  /* Test 2: Normal case */
  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&RCache), "Test hasn't started, tree should be empty");

  n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
  r = PICO_ZALLOC(sizeof(struct pico_ipv6_router));

  r->router = n;
  n->is_router = 1;
  pico_tree_insert(&RCache, r);

  /* Sanity check */
  fail_if(pico_tree_empty(&RCache), "Test started, RCE should have been created");

  pico_nd_delete_rce(r);

  fail_if(n->is_router, "is_router flag should have been cleared");
  fail_unless(pico_tree_empty(&RCache), "Test done, tree should be empty");

  PICO_FREE(n);
}
END_TEST
START_TEST(tc_pico_nd_discover)
{
  /* TODO:  */
   /* TODO: test this: static void pico_nd_discover(struct pico_ipv6_neighbor *n) */
}
END_TEST
START_TEST(tc_pico_nd_get_neighbor)
{
  /* TODO:  */
  /* TODO: test this: static struct pico_eth *pico_nd_get_neighbor(struct pico_ip6 *addr, struct pico_device *dev) */
}
END_TEST
START_TEST(tc_pico_nd_get)
{
  /* TODO: test this: static struct pico_eth *pico_nd_get(struct pico_ip6 *address, struct pico_device *dev) */
}
END_TEST
START_TEST(tc_pico_nd_get_length_of_options)
{
  struct pico_frame a = { 0 };
  struct pico_icmp6_hdr a_hdr = { 0 };
  uint8_t *option = NULL;
  const uint16_t dummy_transport_len = sizeof(*(&a_hdr));

  /* Init */
  a.transport_hdr = (uint8_t *)&a_hdr;
  a.transport_len = dummy_transport_len;

  a_hdr.type = PICO_ICMP6_ROUTER_SOL;
  fail_unless(pico_nd_get_length_of_options(&a, &option) == dummy_transport_len - PICO_ICMP6HDR_ROUTER_SOL_SIZE);
  fail_unless(option == (uint8_t *)&(a_hdr.msg.info.router_sol) + sizeof(struct router_sol_s));

  a_hdr.type = PICO_ICMP6_ROUTER_ADV;
  a.transport_len = dummy_transport_len;
  fail_unless(pico_nd_get_length_of_options(&a, &option) == dummy_transport_len - PICO_ICMP6HDR_ROUTER_ADV_SIZE);
  fail_unless(option == (uint8_t *)&(a_hdr.msg.info.router_adv) + sizeof(struct router_adv_s));

  a_hdr.type = PICO_ICMP6_NEIGH_SOL;
  a.transport_len = dummy_transport_len;
  fail_unless(pico_nd_get_length_of_options(&a, &option) == dummy_transport_len - PICO_ICMP6HDR_NEIGH_SOL_SIZE);
  fail_unless(option == (uint8_t *)&(a_hdr.msg.info.neigh_sol) + sizeof(struct neigh_sol_s));

  a_hdr.type = PICO_ICMP6_NEIGH_ADV;
  a.transport_len = dummy_transport_len;
  fail_unless(pico_nd_get_length_of_options(&a, &option) == dummy_transport_len - PICO_ICMP6HDR_NEIGH_ADV_SIZE);
  fail_unless(option == (uint8_t *)&(a_hdr.msg.info.neigh_adv) + sizeof(struct neigh_adv_s));

  a_hdr.type = PICO_ICMP6_REDIRECT;
  a.transport_len = dummy_transport_len;
  fail_unless(pico_nd_get_length_of_options(&a, &option) == dummy_transport_len - PICO_ICMP6HDR_REDIRECT_SIZE);
  fail_unless(option == (uint8_t *)&(a_hdr.msg.info.redirect) + sizeof(struct redirect_s));

  a_hdr.type = 0;
  a.transport_len = dummy_transport_len;
  fail_unless(pico_nd_get_length_of_options(&a, &option) == 0);
  fail_unless(!option);

  /* test if we can just get the length of the options */
  a_hdr.type = PICO_ICMP6_ROUTER_SOL;
  a.transport_len = dummy_transport_len;
  fail_unless(pico_nd_get_length_of_options(&a, NULL) == dummy_transport_len - PICO_ICMP6HDR_ROUTER_SOL_SIZE);
}
END_TEST
START_TEST(tc_get_neigh_option)
{
  struct pico_frame *f = NULL;
  struct pico_device *dummy_device = NULL;
  struct pico_ipv6_hdr ipv6_hdr = { 0 };
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x08, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  const char router_addr_s[] = "fe80::200:ff:fe00:a0a0";
  struct pico_icmp6_opt_lladdr opt_lladdr = {
    0
  };
  struct pico_icmp6_opt_prefix opt_prefix = {
    0
  };
  struct pico_ip6 temp = { 0 };
  struct redirect_s opt_redirect = { 0 };

  pico_string_to_ipv6(router_addr_s, ipv6_hdr.src.addr);
  pico_string_to_ipv6(all_node_multicast_addr_s, ipv6_hdr.dst.addr);
  ipv6_hdr.hop = 255;

  dummy_device = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_device, name, mac);

  /* Setup */
  f = make_router_adv(dummy_device, PACKET_TYPE_NORMAL);
  f->net_hdr = (uint8_t *)&ipv6_hdr;
  f->net_len = sizeof(struct pico_ipv6_hdr);

  /* Get neigh options from our RA (which has LL addr option and prefix option) */
  fail_unless(get_neigh_option(f, &opt_lladdr, PICO_ND_OPT_LLADDR_SRC) == 1, "our RA should have a valid LL addr option");
  fail_unless(get_neigh_option(f, &opt_prefix, PICO_ND_OPT_PREFIX) == 1, "our RA should have a valid prefix option");
  fail_unless(get_neigh_option(f, &opt_redirect, PICO_ND_OPT_REDIRECT) == 0, "our RA doesn't have a redirect option");

  /* Check if ll addr is valid */
  /* len is stored as a number of bytes */
  fail_unless(opt_lladdr.type == PICO_ND_OPT_LLADDR_SRC, "We didn't extract the LL addr properly");
  fail_unless(opt_lladdr.len == sizeof(struct pico_icmp6_opt_lladdr) >> 3, "We didn't extract the LL addr option properly");
  fail_if(memcmp(&router_adv_mac, opt_lladdr.addr.data, pico_hw_addr_len(dummy_device, &opt_lladdr)), "We didn't extract the LL addr properly");

  /* Check if prefix option is valid */
  fail_unless(opt_prefix.type == router_prefix_option.type);
  fail_unless(opt_prefix.len == router_prefix_option.len);
  fail_unless(opt_prefix.prefix_len == router_prefix_option.prefix_len);
  fail_unless(opt_prefix.res == router_prefix_option.res);
  fail_unless(opt_prefix.aac == router_prefix_option.aac);
  fail_unless(opt_prefix.onlink == router_prefix_option.onlink);
  fail_unless(opt_prefix.val_lifetime == router_prefix_option.val_lifetime);
  fail_unless(opt_prefix.reserved == router_prefix_option.reserved);

  pico_string_to_ipv6(router_adv_prefix, temp.addr);
  fail_unless(memcmp(&opt_prefix.prefix, &temp, sizeof(opt_prefix.prefix)) == 0);

  /* Cleanup */
  pico_frame_discard(f);

  /* Setup */
  f = make_router_adv(dummy_device, PACKET_TYPE_BAD_LEN);
  f->net_hdr = (uint8_t *)&ipv6_hdr;
  f->net_len = sizeof(struct pico_ipv6_hdr);

  /* Get neigh options from our RA (which has LL addr option and prefix option, one option has bad length field) */
  fail_unless(get_neigh_option(f, &opt_lladdr, PICO_ND_OPT_LLADDR_SRC) < 0, "our RA has a bad len field, should have returned failure");
  fail_unless(get_neigh_option(f, &opt_prefix, PICO_ND_OPT_PREFIX) < 0, "our RA has a bad len field, should have returned failure");

  /* Cleanup */
  pico_frame_discard(f);

  /* Setup */
  f = make_router_adv(dummy_device, PACKET_TYPE_DOUBLE_OPTION);
  f->net_hdr = (uint8_t *)&ipv6_hdr;
  f->net_len = sizeof(struct pico_ipv6_hdr);

  /* Get neigh options from our RA (which has 2 * LL addr option and prefix option) */
  fail_unless(get_neigh_option(f, &opt_prefix, PICO_ND_OPT_PREFIX) == 1, "our RA has a double option, but not the prefix option. So retrieving this should have returned success");
  fail_unless(get_neigh_option(f, &opt_lladdr, PICO_ND_OPT_LLADDR_SRC) < 0, "our RA has a double option, should have returned failure");

  pico_frame_discard(f);
  pico_device_destroy(dummy_device);
}
END_TEST
START_TEST(tc_pico_ipv6_neighbor_update)
{
  struct pico_ipv6_neighbor n = { 0 };
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };
  uint8_t initial_mac[PICO_SIZE_ETH] = {
    0x00, 0x00, 0x00, 0x00, 0xa0, 0xa0
  };
  uint8_t new_mac[PICO_SIZE_ETH] = {
    0x00, 0x00, 0x00, 0x00, 0xab, 0xab
  };
  struct pico_icmp6_opt_lladdr lladdr = { 0 };
  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  n.address = addr_0;
  memcpy(&n.hwaddr.mac, &initial_mac, PICO_SIZE_ETH);
  memcpy(&lladdr.addr, &new_mac, PICO_SIZE_ETH);

  /* Sanity check */
  fail_unless(memcmp(&n.hwaddr.mac, &initial_mac, PICO_SIZE_ETH) == 0, "Setup of mac addr failed?");

  pico_ipv6_neighbor_update(&n, &lladdr, dummy_dev);

  fail_unless(memcmp(&n.hwaddr.mac, &new_mac, PICO_SIZE_ETH) == 0, "Mac addr should have been updated");

  pico_device_destroy(dummy_dev);

  /* TODO: 6LOWPAN testing */
}
END_TEST
START_TEST(tc_pico_ipv6_neighbor_compare_stored)
{
  struct pico_ipv6_neighbor n = { 0 };
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };
  uint8_t initial_mac[PICO_SIZE_ETH] = {
    0x00, 0x00, 0x00, 0x00, 0xa0, 0xa0
  };
  uint8_t new_mac[PICO_SIZE_ETH] = {
    0x00, 0x00, 0x00, 0x00, 0xab, 0xab
  };
  struct pico_icmp6_opt_lladdr lladdr = { 0 };
  struct pico_device *dummy_dev = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);

  n.address = addr_0;
  memcpy(&n.hwaddr.mac, &initial_mac, PICO_SIZE_ETH);
  memcpy(&lladdr.addr, &initial_mac, PICO_SIZE_ETH);

  /* Sanity check */
  fail_unless(memcmp(&n.hwaddr.mac, &initial_mac, PICO_SIZE_ETH) == 0, "Setup of mac addr failed?");
  fail_unless(memcmp(&lladdr.addr, &initial_mac, PICO_SIZE_ETH) == 0, "Setup of mac addr failed?");

  fail_unless(pico_ipv6_neighbor_compare_stored(&n, &lladdr, dummy_dev) == 0, "Neighbor and lladdr opt have the same mac addr");

  memcpy(&n.hwaddr.mac, &initial_mac, PICO_SIZE_ETH);
  memcpy(&lladdr.addr, &new_mac, PICO_SIZE_ETH);

  fail_unless(pico_ipv6_neighbor_compare_stored(&n, &lladdr, dummy_dev) != 0, "Neighbor and lladdr opt do not have the same mac addr");

  pico_device_destroy(dummy_dev);

  /* TODO: 6LOWPAN testing */
}
END_TEST
START_TEST(tc_neigh_adv_reconfirm_router_option)
{
  struct pico_ipv6_neighbor *n = NULL;
  struct pico_ipv6_router *r = NULL;
  struct pico_ip6 addr_0 = {
    .addr = {
      0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }
  };

  n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
  n->address = addr_0;
  n->is_router = 1;

  r = PICO_ZALLOC(sizeof(struct pico_ipv6_router));
  r->router = n;

  /* Test 1: clearing of is_router flag, not in RCache */
  neigh_adv_reconfirm_router_option(n, 0);

  fail_if(n->is_router, "is_router flag should be cleared");

  /* Test 2: clearing of is_router flag, in RCache */

  n->is_router = 1;

  /* Sanity check, tree must be empty */
  fail_unless(pico_tree_empty(&RCache), "Test hasn't started, RCache should be empty");
  pico_tree_insert(&RCache, r);
  fail_if(pico_tree_empty(&RCache), "Test started, RCache shouldn't be empty");

  neigh_adv_reconfirm_router_option(n, 0);

  fail_if(n->is_router, "is_router flag should be cleared");
  fail_unless(pico_tree_empty(&RCache), "RCE should be deleted");

  /* Test 3: Setting of is_router flag */
  n->is_router = 0;

  fail_unless(pico_tree_empty(&RCache), "Test hasn't started, RCache should be empty");

  neigh_adv_reconfirm_router_option(n, 1);

  fail_unless(n->is_router, "is_router flag should be set");
  fail_if(pico_tree_empty(&RCache), "RCE should have been created");

  /* Test 4 (cleanup): clearing of is_router flag */
  neigh_adv_reconfirm_router_option(n, 0);

  fail_if(n->is_router, "is_router flag should be cleared");
  fail_unless(pico_tree_empty(&RCache), "RCE should have been deleted");

  PICO_FREE(n);
}
END_TEST
START_TEST(tc_neigh_adv_reconfirm_no_tlla)
{
  /* TODO:  */
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
START_TEST(tc_pico_ipv6_neighbor_from_sol_new)
{
  /* TODO:  */
  /* TODO: test this: static struct pico_ipv6_neighbor *pico_ipv6_neighbor_from_sol_new(struct pico_ip6 *ip, struct pico_icmp6_opt_lladdr *opt, struct pico_device *dev) */
}
END_TEST
START_TEST(tc_pico_ipv6_neighbor_from_unsolicited)
{
  /* TODO:  */
   /* TODO: test this: static void pico_ipv6_neighbor_from_unsolicited(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ipv6_router_from_unsolicited)
{
  /* TODO:  */
   /* TODO: test this: static void pico_ipv6_router_from_unsolicited(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_detect_dad)
{
   /* TODO: test this: static int neigh_sol_detect_dad(struct pico_frame *f) */
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
  /* TODO:  */
   /* TODO: test this: static int neigh_sol_validity_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_sol_process)
{
  /* TODO: test this: static int neigh_sol_process(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_neigh_sol_recv)
{
  /* TODO: test this: static int pico_nd_neigh_sol_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_router_prefix_option_valid)
{
  /* TODO:  */
  /* TODO: test this: static int pico_nd_router_prefix_option_valid(struct pico_device *dev, struct pico_icmp6_opt_prefix *prefix) */
}
END_TEST
START_TEST(tc_pico_nd_router_sol_recv)
{
  /* TODO:  */
   /* TODO: test this: static int pico_nd_router_sol_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_router_adv_validity_checks)
{
  /* TODO:  */
  /* TODO: test this: static int router_adv_validity_checks(struct pico_frame *f) */
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
START_TEST(tc_neigh_adv_option_len_validity_check)
{
  /* TODO:  */
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
START_TEST(tc_neigh_adv_checks)
{
  /* TODO: test this: static int neigh_adv_checks(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_neigh_adv_process)
{
  /* TODO: test this: static int neigh_adv_process(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_neigh_adv_recv)
{
   /* TODO: test this: static int pico_nd_neigh_adv_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_redirect_is_valid)
{
  /* TODO:  */
   /* TODO: test this: static int pico_nd_redirect_is_valid(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_redirect_process)
{
  /* TODO: test this: static int redirect_process(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_nd_redirect_recv)
{
   /* TODO: test this: static int pico_nd_redirect_recv(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_ipv6_check_nce_callback)
{
   /* TODO: test this: static void pico_ipv6_check_nce_callback(pico_time now, struct pico_ipv6_neighbor *n) */
}
END_TEST
START_TEST(tc_pico_ipv6_router_adv_timer_callback)
{
  /* TODO: test this: static void pico_ipv6_router_adv_timer_callback(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_ipv6_check_router_lifetime_callback)
{
   /* TODO: test this: static void pico_ipv6_check_router_lifetime_callback(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_ipv6_check_link_lifetime_expired)
{
   /* TODO: test this: static void pico_ipv6_check_link_lifetime_expired(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_ipv6_router_sol_timer)
{
   /* TODO: test this: static void pico_ipv6_router_sol_timer(pico_time now, void *arg){ */
}
END_TEST

START_TEST(tc_pico_ipv6_nd_timer_elapsed)
{
  struct pico_ipv6_neighbor *n = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  struct pico_device *dummy_dev = NULL;
  pico_time now = 0;
  pico_time expected;

  dummy_dev = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_dev, name, mac);
  dummy_dev->hostvars.retranstime = 1000;

  n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));

  /* Test case 1
   * PICO_ND_STATE_INCOMPLETE
   */
  /* Setup of neighbor */
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_INCOMPLETE;
  n->failure_uni_count = 0;
  n->failure_multi_count = 0;
  n->expire = 0;

  now = PICO_TIME_MS();
  pico_ipv6_nd_timer_elapsed(0, n);

  fail_unless(pico_ns_solicited_count == 1, "When in state INCOMPLETE (and failure counters of NCE==0), NS should have been sent");
  fail_unless(pico_ns_count == 1, "When in state INCOMPLETE (and failure counters of NCE==0), NS should have been sent only once");
  fail_unless(n->state == PICO_ND_STATE_INCOMPLETE, "State of NCE shouldn't have changed when INCOMPLETE");
  fail_unless(VALUE_BETWEEN_RANGE(n->expire, now + n->dev->hostvars.retranstime - EXPIRE_TIME_RANGE_MS, now + n->dev->hostvars.retranstime + EXPIRE_TIME_RANGE_MS));

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* Test case 2
   * PICO_ND_STATE_INCOMPLETE_SEARCHING
   */
  /* Setup of neighbor */
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_INCOMPLETE_SEARCHING;
  n->failure_uni_count = 0;
  n->failure_multi_count = 0;
  n->expire = 0;

  pico_ipv6_nd_timer_elapsed(0, n);
  expected = PICO_TIME_MS() + n->dev->hostvars.retranstime;

  fail_unless(pico_ns_solicited_count == 1, "When in state INCOMPLETE_SEARCHING (and failure counters of NCE==0), NS should have been sent");
  fail_unless(pico_ns_count == 1, "When in state INCOMPLETE_SEARCHING (and failure counters of NCE==0), NS should have been sent only once");
  fail_unless(n->state == PICO_ND_STATE_INCOMPLETE_SEARCHING, "State of NCE shouldn't have changed when INCOMPLETE_SEARCHING");
  fail_unless(TIME_CHECK(n->expire, expected));

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* Test case 3
   * PICO_ND_STATE_REACHABLE
   */
  /* Setup of neighbor */
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_REACHABLE;
  n->failure_uni_count = 0;
  n->failure_multi_count = 0;
  n->expire = 0;

  pico_ipv6_nd_timer_elapsed(0, n);

  fail_unless(pico_ns_unicast_count == 0, "When in state REACHABLE (and failure counters of NCE==0), NS shouldn't have been sent");
  fail_unless(pico_ns_count == 0, "When in state REACHABLE (and failure counters of NCE==0), NS shouldn't have been sent");
  fail_unless(n->state == PICO_ND_STATE_STALE, "State of NCE should have changed from REACHABLE to STALE");
  fail_if(n->expire != 0, "After switching from REACHABLE to STALE, expire time of NCE shouldn't have changed");

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* Test case 4
   * PICO_ND_STATE_STALE
   */
  /* Setup of neighbor */
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_STALE;
  n->failure_uni_count = 0;
  n->failure_multi_count = 0;
  n->expire = 0;

  pico_ipv6_nd_timer_elapsed(0, n);
  expected = PICO_TIME_MS() + PICO_ND_DELAY_FIRST_PROBE_TIME;

  fail_unless(pico_ns_unicast_count == 0, "When in state STALE (and failure counters of NCE==0), NS shouldn't have been sent");
  fail_unless(pico_ns_count == 0, "When in state STALE (and failure counters of NCE==0), NS shouldn't have been sent");
  fail_unless(n->state == PICO_ND_STATE_STALE, "State of NCE shouldn't have changed when STALE");
  fail_unless(TIME_CHECK(n->expire, expected));

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* Test case 5
   * PICO_ND_STATE_DELAY
   */
  /* Setup of neighbor */
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_DELAY;
  n->failure_uni_count = 0;
  n->failure_multi_count = 0;
  n->expire = 0;

  pico_ipv6_nd_timer_elapsed(0, n);

  fail_unless(pico_ns_unicast_count == 0, "When in state DELAY (and failure counters of NCE==0), NS shouldn't have been sent");
  fail_unless(pico_ns_count == 0, "When in state DELAY (and failure counters of NCE==0), NS shouldn't have been sent");
  fail_unless(n->state == PICO_ND_STATE_PROBE, "State of NCE should have changed from DELAY to PROBE");
  fail_if(n->expire != 0, "After switching from DELAY to PROBE, expire time of NCE shouldn't have changed");

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* Test case 6
   * PICO_ND_STATE_PROBE
   */
  /* Setup of neighbor */
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_PROBE;
  n->failure_uni_count = 0;
  n->failure_multi_count = 0;
  n->expire = 0;

  pico_ipv6_nd_timer_elapsed(0, n);
  expected = PICO_TIME_MS() + n->dev->hostvars.retranstime;

  fail_unless(pico_ns_unicast_count == 1, "When in state PROBE (and failure counters of NCE==0), NS should have been sent");
  fail_unless(pico_ns_count == 1, "When in state PROBE (and failure counters of NCE==0), NS should have been sent only once");
  fail_unless(n->state == PICO_ND_STATE_PROBE, "State of NCE shouldn't have changed when PROBE");
  fail_unless(TIME_CHECK(n->expire, expected));

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* Test case 7
   * PICO_ND_STATE_INCOMPLETE
   * - failure count is set to PICO_ND_MAX_MULTICAST_SOLICIT
   * NCE should be deleted
   */
  /* Setup of neighbor */
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_INCOMPLETE;
  n->failure_uni_count = 0;
  n->failure_multi_count = PICO_ND_MAX_MULTICAST_SOLICIT;
  n->expire = 0;
  pico_tree_insert(&NCache, n);

  /* Sanity check, tree must NOT be empty */
  fail_if(pico_tree_empty(&NCache), "There should be an NCE");

  pico_ipv6_nd_timer_elapsed(0, n);

  fail_unless(pico_ns_count == 0, "When in state PROBE (and failure counters of NCE==0), NS should have been sent only once");

  /* Tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "NCE should have been deleted");

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;


  /* Test case 8
   * PICO_ND_STATE_INCOMPLETE_SEARCHING
   * - failure count is set to PICO_ND_MAX_MULTICAST_SOLICIT
   * NCE should be deleted
   */
  /* Setup of neighbor */
  n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_INCOMPLETE_SEARCHING;
  n->failure_uni_count = 0;
  n->failure_multi_count = PICO_ND_MAX_MULTICAST_SOLICIT;
  n->expire = 0;
  pico_tree_insert(&NCache, n);

  /* Sanity check, tree must NOT be empty */
  fail_if(pico_tree_empty(&NCache), "There should be an NCE");

  pico_ipv6_nd_timer_elapsed(0, n);

  fail_unless(pico_ns_count == 0, "When in state PROBE (and failure counters of NCE==0), NS should have been sent only once");

  /* Tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "NCE should have been deleted");

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* Test case 9
   * PICO_ND_STATE_PROBE
   * - failure count is set to PICO_ND_MAX_MULTICAST_SOLICIT
   * NCE should be deleted
   */
  /* Setup of neighbor */
  n = PICO_ZALLOC(sizeof(struct pico_ipv6_neighbor));
  n->dev = dummy_dev;
  n->state = PICO_ND_STATE_PROBE;
  n->failure_uni_count = PICO_ND_MAX_MULTICAST_SOLICIT;
  n->failure_multi_count = 0;
  n->expire = 0;
  pico_tree_insert(&NCache, n);

  /* Sanity check, tree must NOT be empty */
  fail_if(pico_tree_empty(&NCache), "There should be an NCE");

  pico_ipv6_nd_timer_elapsed(0, n);

  fail_unless(pico_ns_count == 0, "When in state PROBE (and failure counters of NCE==0), NS should have been sent only once");

  /* Tree must be empty */
  fail_unless(pico_tree_empty(&NCache), "NCE should have been deleted");

  /* Reset */
  pico_ns_solicited_count = 0;
  pico_ns_unicast_count = 0;
  pico_ns_count = 0;

  /* PICO_FREE(n); */
  pico_device_destroy(dummy_dev);
}
END_TEST
START_TEST(tc_pico_nd_mtu)
{
    struct pico_device *dummy_device = PICO_ZALLOC(sizeof(struct pico_device));
    struct pico_frame *f = NULL;
    const uint8_t mac[PICO_SIZE_ETH] = {
    0x08, 0x00, 0x27, 0x39, 0xd0, 0xc6
    };
    const char * name = "nd_mtu";
    /* Packet 15 from IPv6_NDP.cap */
    const unsigned char pkt15[118] = {
    0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0xc2, 0x00,
    0x54, 0xf5, 0x00, 0x00, 0x86, 0xdd, 0x6e, 0x00,
    0x00, 0x00, 0x00, 0x40, 0x3a, 0xff, 0xfe, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
    0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00, 0xff, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00,
    0xc4, 0xfe, 0x40, 0x00, 0x07, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
    0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00, 0x05, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x03, 0x04,
    0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00, 0x00, 0x09,
    0x3a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01,
    0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    pico_device_init(dummy_device, name, mac);
    f = pico_frame_alloc(sizeof(pkt15));
    memcpy(f->buffer, pkt15, sizeof(pkt15));
    f->dev = dummy_device;
    f->net_hdr = f->buffer + PICO_SIZE_ETHHDR;
    f->net_len = PICO_SIZE_IP6HDR;
    f->transport_hdr = f->buffer + PICO_SIZE_ETHHDR + PICO_SIZE_IP6HDR;
    f->transport_len = sizeof(pkt15) - (PICO_SIZE_ETHHDR + PICO_SIZE_IP6HDR);

    pico_ipv6_nd_recv(f);

    {
    const struct pico_ipv6_hdr *hdr = (const struct pico_ipv6_hdr *)(pkt15 + PICO_SIZE_ETHHDR);
    struct pico_ipv6_router *test_router = pico_get_router_from_rcache(&(hdr->src));
    fail_if(test_router->link->mtu != 1500);

    /* Cleanup */
    pico_device_destroy(dummy_device);
    pico_nd_delete_entry(&(hdr->src));
    }
}
END_TEST
START_TEST(tc_pico_recv_ra)
{
  /* Context:
   * Clean env, no NCEs, no RCEs
   * We recv a RA, NCE has to be created, RCE has to be created, default router has to be set
   */
  struct pico_frame *f = NULL;
  struct pico_device *dummy_device = NULL;
  struct pico_ipv6_hdr ipv6_hdr = { 0 };
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x08, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  const char router_addr_s[] = "fe80::200:ff:fe00:a0a0";

  pico_string_to_ipv6(router_addr_s, ipv6_hdr.src.addr);
  pico_string_to_ipv6(all_node_multicast_addr_s, ipv6_hdr.dst.addr);
  ipv6_hdr.hop = 255;

  dummy_device = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_device, name, mac);

  f = make_router_adv(dummy_device, PACKET_TYPE_NORMAL);
  f->net_hdr = (uint8_t *)&ipv6_hdr;
  f->net_len = sizeof(struct pico_ipv6_hdr);

  /* Flag success */
  pico_icmp6_checksum_success_flag = 1;

  fail_if(pico_ipv6_nd_recv(f) != 0, "We passed a valid packet, should have returned SUCCESS");

  fail_if(pico_get_neighbor_from_ncache(&ipv6_hdr.src) == NULL, "RA recvd, NCE should have been created");
  fail_if(pico_get_router_from_rcache(&ipv6_hdr.src) == NULL, "RA recvd, RCE should have been created");
  fail_if(pico_nd_get_default_router() == NULL, "RA recvd, default router should have been set");

  /* Cleanup */
  pico_nd_delete_entry(&(ipv6_hdr.src));
  pico_device_destroy(dummy_device);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_ipv6_neighbor_compare = tcase_create("Unit test for pico_ipv6_neighbor_compare");
    TCase *TCase_pico_ipv6_router_compare = tcase_create("Unit test for pico_ipv6_router_compare");
    TCase *TCase_pico_ipv6_nd_qcompare = tcase_create("Unit test for pico_ipv6_nd_qcompare");
    TCase *TCase_icmp6_initial_checks = tcase_create("Unit test for icmp6_initial_checks");
    TCase *TCase_pico_hw_addr_len = tcase_create("Unit test for pico_hw_addr_len");
    TCase *TCase_pico_nd_get_oldest_queued_frame = tcase_create("Unit test for pico_nd_get_oldest_queued_frame");
    TCase *TCase_ipv6_duplicate_detected = tcase_create("Unit test for ipv6_duplicate_detected");
    TCase *TCase_pico_get_neighbor_from_ncache = tcase_create("Unit test for pico_get_neighbor_from_ncache");
    TCase *TCase_pico_get_router_from_rcache = tcase_create("Unit test for pico_get_router_from_rcache");
    TCase *TCase_pico_nd_get_default_router = tcase_create("Unit test for pico_nd_get_default_router");

    TCase *TCase_pico_ipv6_assign_default_router_on_link = tcase_create("Unit test for pico_ipv6_assign_default_router_on_link");
    TCase *TCase_pico_nd_get_length_of_options = tcase_create("Unit test for pico_nd_get_length_of_options");
    TCase *TCase_pico_ipv6_set_router_link = tcase_create("Unit test for pico_ipv6_set_router_link");
    TCase *TCase_pico_ipv6_set_router_mtu = tcase_create("Unit test for pico_ipv6_set_router_mtu");
    TCase *TCase_pico_nd_trigger_queued_packets = tcase_create("Unit test for pico_nd_trigger_queued_packets");
    TCase *TCase_pico_nd_set_new_expire_time = tcase_create("Unit test for pico_nd_set_new_expire_time");
    TCase *TCase_pico_nd_mtu = tcase_create("Unit test for pico_nd link mtu option");
    TCase *TCase_pico_nd_discover = tcase_create("Unit test for pico_nd_discover");
    TCase *TCase_get_neigh_option = tcase_create("Unit test for get_neigh_option");
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
    TCase *TCase_pico_ipv6_check_nce_callback = tcase_create("Unit test for pico_ipv6_check_nce_callback");
    TCase *TCase_pico_ipv6_check_router_lifetime_callback = tcase_create("Unit test for pico_ipv6_check_router_lifetime_callback");
    TCase *TCase_pico_ipv6_router_adv_timer_callback = tcase_create("Unit test for pico_ipv6_router_adv_timer_callback");
    TCase *TCase_pico_ipv6_check_link_lifetime_expired = tcase_create("Unit test for pico_ipv6_check_link_lifetime_expired");
    TCase *TCase_pico_ipv6_router_sol_timer = tcase_create("Unit test for pico_ipv6_router_sol_timer");

    TCase *TCase_functional_ra = tcase_create("Functional test for recv router solicitation");

    TCase *TCase_pico_ipv6_nd_timer_elapsed = tcase_create("Unit test for pico_ipv6_nd_timer_elapsed");
    TCase *TCase_pico_nd_router_prefix_option_valid = tcase_create("Unit test for pico_nd_router_prefix_option_valid");
    TCase *TCase_pico_ipv6_neighbor_from_sol_new = tcase_create("Unit test for pico_ipv6_neighbor_from_sol_new");
    TCase *TCase_pico_nd_get = tcase_create("Unit test for pico_nd_get");
    TCase *TCase_pico_nd_get_neighbor = tcase_create("Unit test for pico_nd_get_neighbor");
    TCase *TCase_pico_nd_delete_entry = tcase_create("Unit test for pico_nd_delete_entry");
    TCase *TCase_pico_nd_create_entry = tcase_create("Unit test for pico_nd_create_entry");
    TCase *TCase_pico_nd_clear_queued_packets = tcase_create("Unit test for pico_nd_clear_queued_packets");
    TCase *TCase_pico_ipv6_nd_postpone = tcase_create("Unit test for pico_ipv6_nd_postpone");

    TCase *TCase_pico_nd_delete_rce = tcase_create("Unit test for pico_nd_delete_rce");
    TCase *TCase_pico_nd_create_rce = tcase_create("Unit test for pico_nd_create_rce");

    tcase_add_test(TCase_functional_ra, tc_pico_recv_ra);
    suite_add_tcase(s, TCase_functional_ra);
    tcase_add_test(TCase_pico_ipv6_nd_timer_elapsed, tc_pico_ipv6_nd_timer_elapsed);
    suite_add_tcase(s, TCase_pico_ipv6_nd_timer_elapsed);
    tcase_add_test(TCase_pico_nd_router_prefix_option_valid, tc_pico_nd_router_prefix_option_valid);
    suite_add_tcase(s, TCase_pico_nd_router_prefix_option_valid);
    tcase_add_test(TCase_pico_ipv6_neighbor_from_sol_new, tc_pico_ipv6_neighbor_from_sol_new);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor_from_sol_new);

    tcase_add_test(TCase_pico_nd_get, tc_pico_nd_get);
    suite_add_tcase(s, TCase_pico_nd_get);
    tcase_add_test(TCase_pico_nd_get_neighbor, tc_pico_nd_get_neighbor);
    suite_add_tcase(s, TCase_pico_nd_get_neighbor);

    tcase_add_test(TCase_pico_nd_delete_entry, tc_pico_nd_delete_entry);
    suite_add_tcase(s, TCase_pico_nd_delete_entry);

    tcase_add_test(TCase_pico_nd_create_entry, tc_pico_nd_create_entry);
    suite_add_tcase(s, TCase_pico_nd_create_entry);

    tcase_add_test(TCase_pico_nd_clear_queued_packets, tc_pico_nd_clear_queued_packets);
    suite_add_tcase(s, TCase_pico_nd_clear_queued_packets);

    tcase_add_test(TCase_pico_ipv6_nd_postpone, tc_pico_ipv6_nd_postpone);
    suite_add_tcase(s, TCase_pico_ipv6_nd_postpone);

    tcase_add_test(TCase_pico_nd_delete_rce, tc_pico_nd_delete_rce);
    suite_add_tcase(s, TCase_pico_nd_delete_rce);

    tcase_add_test(TCase_pico_nd_create_rce, tc_pico_nd_create_rce);
    suite_add_tcase(s, TCase_pico_nd_create_rce);

    tcase_add_test(TCase_pico_ipv6_neighbor_compare, tc_pico_ipv6_neighbor_compare);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor_compare);
    tcase_add_test(TCase_pico_ipv6_router_compare, tc_pico_ipv6_router_compare);
    suite_add_tcase(s, TCase_pico_ipv6_router_compare);
    tcase_add_test(TCase_icmp6_initial_checks, tc_icmp6_initial_checks);
    suite_add_tcase(s, TCase_icmp6_initial_checks);
    tcase_add_test(TCase_pico_hw_addr_len, tc_pico_hw_addr_len);
    suite_add_tcase(s, TCase_pico_hw_addr_len);
    tcase_add_test(TCase_pico_nd_get_oldest_queued_frame, tc_pico_nd_get_oldest_queued_frame);
    suite_add_tcase(s, TCase_pico_nd_get_oldest_queued_frame);
    tcase_add_test(TCase_ipv6_duplicate_detected, tc_ipv6_duplicate_detected);
    suite_add_tcase(s, TCase_ipv6_duplicate_detected);
    tcase_add_test(TCase_pico_get_neighbor_from_ncache, tc_pico_get_neighbor_from_ncache);
    suite_add_tcase(s, TCase_pico_get_neighbor_from_ncache);
    tcase_add_test(TCase_pico_get_router_from_rcache, tc_pico_get_router_from_rcache);
    suite_add_tcase(s, TCase_pico_get_router_from_rcache);
    tcase_add_test(TCase_pico_nd_get_default_router, tc_pico_nd_get_default_router);
    suite_add_tcase(s, TCase_pico_nd_get_default_router);
    tcase_add_test(TCase_pico_ipv6_nd_qcompare, tc_pico_ipv6_nd_qcompare);
    suite_add_tcase(s, TCase_pico_ipv6_nd_qcompare);
    tcase_add_test(TCase_pico_nd_get_length_of_options, tc_pico_nd_get_length_of_options);
    suite_add_tcase(s, TCase_pico_nd_get_length_of_options);
    tcase_add_test(TCase_pico_ipv6_assign_default_router_on_link, tc_pico_ipv6_assign_default_router_on_link);
    suite_add_tcase(s, TCase_pico_ipv6_assign_default_router_on_link);
    tcase_add_test(TCase_pico_ipv6_set_router_link, tc_pico_ipv6_set_router_link);
    suite_add_tcase(s, TCase_pico_ipv6_set_router_link);
    tcase_add_test(TCase_pico_ipv6_set_router_mtu, tc_pico_ipv6_set_router_mtu);
    suite_add_tcase(s, TCase_pico_ipv6_set_router_mtu);
    tcase_add_test(TCase_pico_nd_trigger_queued_packets, tc_pico_ipv6_nd_trigger_queued_packets);
    suite_add_tcase(s, TCase_pico_nd_trigger_queued_packets);
    tcase_add_test(TCase_pico_nd_set_new_expire_time, tc_pico_nd_set_new_expire_time);
    suite_add_tcase(s, TCase_pico_nd_set_new_expire_time);
    tcase_add_test(TCase_pico_nd_mtu, tc_pico_nd_mtu);
    suite_add_tcase(s, TCase_pico_nd_mtu);
    tcase_add_test(TCase_pico_nd_discover, tc_pico_nd_discover);
    suite_add_tcase(s, TCase_pico_nd_discover);
    tcase_add_test(TCase_get_neigh_option, tc_get_neigh_option);
    suite_add_tcase(s, TCase_get_neigh_option);
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
    tcase_add_test(TCase_pico_ipv6_check_nce_callback, tc_pico_ipv6_check_nce_callback);
    suite_add_tcase(s, TCase_pico_ipv6_check_nce_callback);
    tcase_add_test(TCase_pico_ipv6_check_router_lifetime_callback, tc_pico_ipv6_check_router_lifetime_callback);
    suite_add_tcase(s, TCase_pico_ipv6_check_router_lifetime_callback);
    tcase_add_test(TCase_pico_ipv6_router_adv_timer_callback, tc_pico_ipv6_router_adv_timer_callback);
    suite_add_tcase(s, TCase_pico_ipv6_router_adv_timer_callback);
    tcase_add_test(TCase_pico_ipv6_check_link_lifetime_expired, tc_pico_ipv6_check_link_lifetime_expired);
    suite_add_tcase(s, TCase_pico_ipv6_check_link_lifetime_expired);
    tcase_add_test(TCase_pico_ipv6_router_sol_timer, tc_pico_ipv6_router_sol_timer);
    suite_add_tcase(s, TCase_pico_ipv6_router_sol_timer);
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
