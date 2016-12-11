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

static int pico_icmp6_checksum_success_flag = 1;

Suite *pico_suite(void);

uint16_t pico_icmp6_checksum(struct pico_frame *f)
{
  IGNORE_PARAMETER(f);

  if (pico_icmp6_checksum_success_flag)
    return 0;

  return 1;
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
START_TEST(tc_pico_nd_get_oldest_frame)
{
#define FRAME_COUNT (3)
  struct pico_frame a, b, c;
  struct pico_frame *frames[FRAME_COUNT] = { 0 };

  frames[0] = &a;
  frames[1] = &b;
  frames[2] = &c;

  fail_if(pico_nd_get_oldest_frame(frames, 0) != NULL, "Passing 0 should return NULL");

  fail_if(pico_nd_get_oldest_frame(NULL, FRAME_COUNT) != NULL, "Passing NULL should return NULL");

  a.timestamp = 0;
  b.timestamp = 1;
  c.timestamp = 2;

  fail_if(pico_nd_get_oldest_frame(frames, FRAME_COUNT) != &a, "Frame a has smallest timestamp == is oldest");

  /* 2 packets with same timestamp */
  a.timestamp = 3;
  b.timestamp = 2;
  c.timestamp = 2;

  fail_if(pico_nd_get_oldest_frame(frames, FRAME_COUNT) != &b, "Frames b and c have same timestamp, b is first in array so it should be returned first.");
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
  char ipstr1[] = "2001:db8:130f:0000:0000:09c0:876a:130b";
  char ipstr2[] = "2001:b8:130f:0000:0000:09c0:876a:130b";

  /* Setup of routers */
  r0.router = &n0;
  r1.router = &n1;
  r2.router = &n2;
  r0.link = &link;
  r1.link = &link;
  r2.link = &link;
  pico_string_to_ipv6(ipstr0, r0.router->address.addr);
  pico_string_to_ipv6(ipstr1, r0.router->address.addr);
  pico_string_to_ipv6(ipstr2, r1.router->address.addr);

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

START_TEST(tc_pico_recv_rs)
{
  /* Context:
   * Clean env, no NCEs, no RCEs
   * We recv a RA, NCE has to be created, RCE has to be created, default router has to be set
   * Using router solicitation from ND tahi tests v6LC.2.2.2 Part B
   */
  uint8_t packet_data[] = {
    0x33,0x33,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0xa0,0xa0,0x86,0xdd,0x60,0x00,
    0x00,0x00,0x00,0x38,0x3a,0xff,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,
    0x00,0xff,0xfe,0x00,0xa0,0xa0,0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x01,0x86,0x00,0xa0,0x49,0x40,0x00,0x07,0x08,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0xa0,0xa0,0x03,0x04,
    0x40,0xc0,0x00,0x27,0x8d,0x00,0x00,0x09,0x3a,0x80,0x00,0x00,0x00,0x00,0x3f,0xfe,
    0x05,0x01,0xff,0xff,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
  };
  struct pico_frame *f = NULL;
  struct pico_device *dummy_device = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x08, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "nd_test";
  struct pico_ipv6_hdr *ip = NULL;
  struct pico_ip6 temp_src = { 0 };

  /* Sanity check, no default router set */
  fail_if(pico_nd_get_default_router() != NULL, "No default router in RCache, should have returned NULL");

  f = pico_proto_ipv6.alloc(&pico_proto_ipv6, dummy_device, sizeof(packet_data));

  /* f = pico_frame_alloc(sizeof(packet_data)); */
  dummy_device = PICO_ZALLOC(sizeof(struct pico_device));

  pico_device_init(dummy_device, name, mac);

  memcpy(f->buffer, packet_data, sizeof(packet_data));
  f->dev = dummy_device;
  f->net_hdr = f->buffer + PICO_SIZE_ETHHDR;
  f->net_len = PICO_SIZE_IP6HDR;
  f->transport_hdr = f->buffer + PICO_SIZE_ETHHDR + PICO_SIZE_IP6HDR;
  f->transport_len = sizeof(packet_data) - (PICO_SIZE_ETHHDR + PICO_SIZE_IP6HDR);

  ip = (struct pico_ipv6_hdr *)f->net_hdr;

  /* Copy src addr because pico_ipv6_nd_recv includes an implicit pico_frame_discard */
  memcpy(&temp_src, &ip->src, sizeof(struct pico_ip6));

  pico_ipv6_nd_recv(f);

  fail_if(pico_get_neighbor_from_ncache(&temp_src) == NULL, "RA recvd, NCE should have been created");
  fail_if(pico_get_router_from_rcache(&temp_src) == NULL, "RA recvd, RCE should have been created");
  fail_if(pico_nd_get_default_router() == NULL, "RA recvd, default router should have been set");

  /* Cleanup */
  pico_nd_delete_entry(pico_get_neighbor_from_ncache(&(temp_src)));
  pico_device_destroy(dummy_device);
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
START_TEST(tc_pico_nd_set_new_expire_time)
{
  struct pico_ipv6_neighbor n = {
    0
  };
  struct pico_device d = { {0} };

  n.dev = &d;

  d.hostvars.retranstime = 666;

  n.state = PICO_ND_STATE_INCOMPLETE;
  pico_nd_set_new_expire_time(&n);
  fail_if(n.expire != PICO_TIME_MS() + d.hostvars.retranstime);

  n.state = PICO_ND_STATE_REACHABLE;
  pico_nd_set_new_expire_time(&n);
  fail_if(n.expire != PICO_TIME_MS() + PICO_ND_REACHABLE_TIME);

  n.state = PICO_ND_STATE_STALE;
  pico_nd_set_new_expire_time(&n);
  fail_if(n.expire != PICO_TIME_MS() + PICO_ND_DELAY_FIRST_PROBE_TIME);

  n.state = PICO_ND_STATE_DELAY;
  pico_nd_set_new_expire_time(&n);
  fail_if(n.expire != PICO_TIME_MS() + PICO_ND_DELAY_FIRST_PROBE_TIME);

  n.state = PICO_ND_STATE_PROBE;
  pico_nd_set_new_expire_time(&n);
  fail_if(n.expire != PICO_TIME_MS() + d.hostvars.retranstime);
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
    pico_nd_delete_entry(pico_get_neighbor_from_ncache(&(hdr->src)));
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
    TCase *TCase_icmp6_initial_checks = tcase_create("Unit test for icmp6_initial_checks");
    TCase *TCase_pico_hw_addr_len = tcase_create("Unit test for pico_hw_addr_len");
    TCase *TCase_pico_nd_get_oldest_frame = tcase_create("Unit test for pico_nd_get_oldest_frame");
    TCase *TCase_ipv6_duplicate_detected = tcase_create("Unit test for ipv6_duplicate_detected");
    TCase *TCase_pico_get_neighbor_from_ncache = tcase_create("Unit test for pico_get_neighbor_from_ncache");
    TCase *TCase_pico_get_router_from_rcache = tcase_create("Unit test for pico_get_router_from_rcache");
    TCase *TCase_pico_nd_get_default_router = tcase_create("Unit test for pico_nd_get_default_router");

    TCase *TCase_pico_ipv6_assign_default_router = tcase_create("Unit test for pico_ipv6_assign_default_router");
    TCase *TCase_pico_nd_get_length_of_options = tcase_create("Unit test for pico_nd_get_length_of_options");
    TCase *TCase_pico_ipv6_router_add_link = tcase_create("Unit test for pico_ipv6_router_add_link");
    TCase *TCase_pico_ipv6_nd_queued_trigger = tcase_create("Unit test for pico_ipv6_nd_queued_trigger");
    TCase *TCase_pico_ipv6_nd_unreachable = tcase_create("Unit test for pico_ipv6_nd_unreachable");
    TCase *TCase_pico_nd_set_new_expire_time = tcase_create("Unit test for pico_nd_set_new_expire_time");
    TCase *TCase_pico_nd_mtu = tcase_create("Unit test for pico_nd link mtu option");
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

    TCase *TCase_functional_rs = tcase_create("Functional test for recv router advertisement");

    tcase_add_test(TCase_functional_rs, tc_pico_recv_rs);
    suite_add_tcase(s, TCase_functional_rs);

    tcase_add_test(TCase_pico_ipv6_neighbor_compare, tc_pico_ipv6_neighbor_compare);
    suite_add_tcase(s, TCase_pico_ipv6_neighbor_compare);
    tcase_add_test(TCase_pico_ipv6_router_compare, tc_pico_ipv6_router_compare);
    suite_add_tcase(s, TCase_pico_ipv6_router_compare);
    tcase_add_test(TCase_icmp6_initial_checks, tc_icmp6_initial_checks);
    suite_add_tcase(s, TCase_icmp6_initial_checks);
    tcase_add_test(TCase_pico_hw_addr_len, tc_pico_hw_addr_len);
    suite_add_tcase(s, TCase_pico_hw_addr_len);
    tcase_add_test(TCase_pico_nd_get_oldest_frame, tc_pico_nd_get_oldest_frame);
    suite_add_tcase(s, TCase_pico_nd_get_oldest_frame);
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
    tcase_add_test(TCase_pico_ipv6_assign_default_router, tc_pico_ipv6_assign_default_router);
    suite_add_tcase(s, TCase_pico_ipv6_assign_default_router);
    tcase_add_test(TCase_pico_ipv6_router_add_link, tc_pico_ipv6_router_add_link);
    suite_add_tcase(s, TCase_pico_ipv6_router_add_link);
    tcase_add_test(TCase_pico_ipv6_nd_queued_trigger, tc_pico_ipv6_nd_queued_trigger);
    suite_add_tcase(s, TCase_pico_ipv6_nd_queued_trigger);
    tcase_add_test(TCase_pico_ipv6_nd_unreachable, tc_pico_ipv6_nd_unreachable);
    suite_add_tcase(s, TCase_pico_ipv6_nd_unreachable);
    tcase_add_test(TCase_pico_nd_set_new_expire_time, tc_pico_nd_set_new_expire_time);
    suite_add_tcase(s, TCase_pico_nd_set_new_expire_time);
    tcase_add_test(TCase_pico_nd_mtu, tc_pico_nd_mtu);
    suite_add_tcase(s, TCase_pico_nd_mtu);
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
