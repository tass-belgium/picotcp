#include <pico_stack.h>
#include <pico_tree.h>
#include <pico_socket.h>
#include <pico_aodv.h>
#include <pico_device.h>
#include <pico_ipv4.h>
#include "modules/pico_aodv.c"
#include "check.h"


START_TEST(tc_aodv_node_compare)
{
    struct pico_aodv_node a, b;
    a.dest.ip4.addr = long_be(1);
    b.dest.ip4.addr = long_be(2);

    fail_if(aodv_node_compare(&a, &b) >= 0);
    a.dest.ip4.addr = long_be(3);
    fail_if(aodv_node_compare(&a, &b) <= 0);
    b.dest.ip4.addr = long_be(3);
    fail_if(aodv_node_compare(&a, &b) != 0);
}
END_TEST

START_TEST(tc_aodv_dev_cmp)
{
    struct pico_device a, b;
    a.hash = 1;
    b.hash = 2;
    fail_if(aodv_dev_cmp(&a, &b) >= 0);
    a.hash = 3;
    fail_if(aodv_dev_cmp(&a, &b) <= 0);
    b.hash = 3;
    fail_if(aodv_dev_cmp(&a, &b) != 0);

}
END_TEST

START_TEST(tc_get_node_by_addr)
{
    struct pico_aodv_node a;
    union pico_address test;
    a.dest.ip4.addr = long_be(10);
    test.ip4.addr = long_be(10);

    pico_tree_insert(&aodv_nodes, &a);

    fail_if(get_node_by_addr(&test) != &a);
    pico_tree_delete(&aodv_nodes, &a);
    fail_if(get_node_by_addr(&test) != NULL);

}
END_TEST

static int set_bcast_link_called = 0;
void pico_ipv4_route_set_bcast_link(struct pico_ipv4_link *link)
{
    fail_if(link);
    set_bcast_link_called++;
}

START_TEST(tc_pico_aodv_set_dev)
{
    struct pico_device *dev = NULL;
    pico_aodv_set_dev(dev);
    fail_if(set_bcast_link_called != 1);
}
END_TEST

START_TEST(tc_aodv_peer_refresh)
{
   /* TODO: test this: static int aodv_peer_refresh(struct pico_aodv_node *node, uint32_t seq) */
    struct pico_aodv_node node;
    memset(&node, 0, sizeof(node));
    node.dseq = 0xFFFF;
    fail_if(aodv_peer_refresh(&node, 10) != 0); /* should succeed, because SYNC flag is not yet set... */
    fail_if(node.flags & PICO_AODV_NODE_SYNC == 0); /* Flag should be set after last call... */
    fail_if(aodv_peer_refresh(&node, 5) == 0); /* should FAIL, because seq number is lower...  */
    fail_if(aodv_peer_refresh(&node, 10) == 0); /* should FAIL, because seq number is still the same...  */
    fail_if(aodv_peer_refresh(&node, 15) != 0); /* should succeed, because seq number is now bigger...  */
    fail_if(node.dseq != 15);
}
END_TEST

static int called_route_add = 0;
static uint32_t route_add_gw = 0u;
static int route_add_metric = 0;
int pico_ipv4_route_add(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link)
{
    called_route_add++;
    route_add_gw = gateway.addr;
    route_add_metric = metric;
    return 0;
}

START_TEST(tc_aodv_elect_route)
{
    struct pico_aodv_node node;
    union pico_address gateway;
    memset(&node, 0, sizeof(node));
    gateway.ip4.addr = 0x55555555;

    called_route_add = 0;
    aodv_elect_route(&node, NULL, 150, NULL);
    fail_if(called_route_add != 1); /* Not active, should succeed */
    fail_if(route_add_gw != 0u);
    fail_if(route_add_metric != 1);

    called_route_add = 0;
    route_add_metric = 0;
    route_add_gw = 0u;
    node.flags = PICO_AODV_NODE_ROUTE_DOWN | PICO_AODV_NODE_ROUTE_UP;
    aodv_elect_route(&node, &gateway, 150, NULL);
    fail_if(called_route_add != 0); /* Already active, existing metric is lower */
    
    called_route_add = 0;
    route_add_metric = 0;
    route_add_gw = 0u;
    node.metric = 22;
    aodv_elect_route(&node, &gateway, 15, NULL);
    fail_if(called_route_add != 1); /* Already active, existing metric is higher */
    fail_if(route_add_metric != 16);
    fail_if(route_add_gw != 0x55555555);

}
END_TEST

START_TEST(tc_aodv_peer_new)
{
    union pico_address addr;
    struct pico_aodv_node *new;
    addr.ip4.addr = 0x44444444;
    new = aodv_peer_new(&addr);
    fail_if(!new);
    fail_if(!get_node_by_addr(&addr));
    pico_set_mm_failure(1);
    new = aodv_peer_new(&addr);
    fail_if(new);
}
END_TEST
START_TEST(tc_aodv_peer_eval)
{
    union pico_address addr;
    struct pico_aodv_node *node = NULL;
    /* Case 0: Creation */
    addr.ip4.addr = 0x11224433;
    node = aodv_peer_eval(&addr, 0, 0);
    fail_if(!node);
    fail_if((node->flags & PICO_AODV_NODE_SYNC) != 0); /* Not synced! */

    /* Case 1: retrieve, unsynced */
    node->metric = 42;
    node = aodv_peer_eval(&addr, 0, 0); /* Should get existing node! */
    fail_if(!node);
    fail_if(node->metric != 42);
    fail_if((node->flags & PICO_AODV_NODE_SYNC) != 0); /* Not synced! */


    /* Case 2: new node, invalid allocation */
    addr.ip4.addr = 0x11224455;
    pico_set_mm_failure(1);
    node = aodv_peer_eval(&addr, long_be(10), 1);
    fail_if(node);

    /* Case 3: existing node, setting the new sequence */
    addr.ip4.addr = 0x11224433;
    node = aodv_peer_eval(&addr, long_be(10), 1); /* Should get existing node! */
    fail_if(node->metric != 42);
    fail_if((node->flags & PICO_AODV_NODE_SYNC) == 0);
    fail_if(node->dseq!= 10);
}
END_TEST

START_TEST(tc_aodv_lifetime)
{
    struct pico_aodv_node node;
    pico_time now = PICO_TIME_MS();
    memset(&node, 0, sizeof(node));
    fail_if(aodv_lifetime(&node) == 0);
    fail_if(node.last_seen < now);
    node.last_seen = now - AODV_ACTIVE_ROUTE_TIMEOUT;
    fail_if(aodv_lifetime(&node) != 0);
}
END_TEST

START_TEST(tc_aodv_send_reply)
{
   /* TODO: test this: static void aodv_send_reply(struct pico_aodv_node *node, struct pico_aodv_rreq *req, int node_is_local, struct pico_msginfo *info) */
}
END_TEST
START_TEST(tc_aodv_send_req)
{
   /* TODO: test this: static int aodv_send_req(struct pico_aodv_node *node); */
}
END_TEST
START_TEST(tc_aodv_reverse_path_discover)
{
   /* TODO: test this: static void aodv_reverse_path_discover(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_aodv_recv_valid_rreq)
{
   /* TODO: test this: static void aodv_recv_valid_rreq(struct pico_aodv_node *node, struct pico_aodv_rreq *req, struct pico_msginfo *info) */
}
END_TEST
START_TEST(tc_aodv_parse_rreq)
{
   /* TODO: test this: static void aodv_parse_rreq(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo) */
}
END_TEST
START_TEST(tc_aodv_parse_rrep)
{
   /* TODO: test this: static void aodv_parse_rrep(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo) */
}
END_TEST
START_TEST(tc_aodv_parse_rerr)
{
   /* TODO: test this: static void aodv_parse_rerr(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo) */
}
END_TEST
START_TEST(tc_aodv_parse_rack)
{
   /* TODO: test this: static void aodv_parse_rack(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo) */
}
END_TEST
START_TEST(tc_pico_aodv_parse)
{
   /* TODO: test this: static void pico_aodv_parse(union pico_address *from, uint8_t *buf, int len, struct pico_msginfo *msginfo) */
}
END_TEST
START_TEST(tc_pico_aodv_socket_callback)
{
   /* TODO: test this: static void pico_aodv_socket_callback(uint16_t ev, struct pico_socket *s) */
}
END_TEST
START_TEST(tc_aodv_make_rreq)
{
   /* TODO: test this: static void aodv_make_rreq(struct pico_aodv_node *node, struct pico_aodv_rreq *req) */
}
END_TEST
START_TEST(tc_aodv_retrans_rreq)
{
   /* TODO: test this: static void aodv_retrans_rreq(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_pico_aodv_expired)
{
   /* TODO: test this: static void pico_aodv_expired(struct pico_aodv_node *node) */
}
END_TEST
START_TEST(tc_pico_aodv_collector)
{
   /* TODO: test this: static void pico_aodv_collector(pico_time now, void *arg) */
}
END_TEST


Suite *pico_suite(void)                       
{
    Suite *s = suite_create("PicoTCP");             

    TCase *TCase_aodv_node_compare = tcase_create("Unit test for aodv_node_compare");
    TCase *TCase_aodv_dev_cmp = tcase_create("Unit test for aodv_dev_cmp");
    TCase *TCase_get_node_by_addr = tcase_create("Unit test for get_node_by_addr");
    TCase *TCase_pico_aodv_set_dev = tcase_create("Unit test for pico_aodv_set_dev");
    TCase *TCase_aodv_peer_refresh = tcase_create("Unit test for aodv_peer_refresh");
    TCase *TCase_aodv_elect_route = tcase_create("Unit test for aodv_elect_route");
    TCase *TCase_aodv_peer_new = tcase_create("Unit test for aodv_peer_new");
    TCase *TCase_aodv_peer_eval = tcase_create("Unit test for aodv_peer_eval");
    TCase *TCase_aodv_lifetime = tcase_create("Unit test for aodv_lifetime");
    TCase *TCase_aodv_send_reply = tcase_create("Unit test for aodv_send_reply");
    TCase *TCase_aodv_send_req = tcase_create("Unit test for aodv_send_req");
    TCase *TCase_aodv_reverse_path_discover = tcase_create("Unit test for aodv_reverse_path_discover");
    TCase *TCase_aodv_recv_valid_rreq = tcase_create("Unit test for aodv_recv_valid_rreq");
    TCase *TCase_aodv_parse_rreq = tcase_create("Unit test for aodv_parse_rreq");
    TCase *TCase_aodv_parse_rrep = tcase_create("Unit test for aodv_parse_rrep");
    TCase *TCase_aodv_parse_rerr = tcase_create("Unit test for aodv_parse_rerr");
    TCase *TCase_aodv_parse_rack = tcase_create("Unit test for aodv_parse_rack");
    TCase *TCase_pico_aodv_parse = tcase_create("Unit test for pico_aodv_parse");
    TCase *TCase_pico_aodv_socket_callback = tcase_create("Unit test for pico_aodv_socket_callback");
    TCase *TCase_aodv_make_rreq = tcase_create("Unit test for aodv_make_rreq");
    TCase *TCase_aodv_retrans_rreq = tcase_create("Unit test for aodv_retrans_rreq");
    TCase *TCase_pico_aodv_expired = tcase_create("Unit test for pico_aodv_expired");
    TCase *TCase_pico_aodv_collector = tcase_create("Unit test for pico_aodv_collector");


    tcase_add_test(TCase_aodv_node_compare, tc_aodv_node_compare);
    suite_add_tcase(s, TCase_aodv_node_compare);
    tcase_add_test(TCase_aodv_dev_cmp, tc_aodv_dev_cmp);
    suite_add_tcase(s, TCase_aodv_dev_cmp);
    tcase_add_test(TCase_get_node_by_addr, tc_get_node_by_addr);
    suite_add_tcase(s, TCase_get_node_by_addr);
    tcase_add_test(TCase_pico_aodv_set_dev, tc_pico_aodv_set_dev);
    suite_add_tcase(s, TCase_pico_aodv_set_dev);
    tcase_add_test(TCase_aodv_peer_refresh, tc_aodv_peer_refresh);
    suite_add_tcase(s, TCase_aodv_peer_refresh);
    tcase_add_test(TCase_aodv_elect_route, tc_aodv_elect_route);
    suite_add_tcase(s, TCase_aodv_elect_route);
    tcase_add_test(TCase_aodv_peer_new, tc_aodv_peer_new);
    suite_add_tcase(s, TCase_aodv_peer_new);
    tcase_add_test(TCase_aodv_peer_eval, tc_aodv_peer_eval);
    suite_add_tcase(s, TCase_aodv_peer_eval);
    tcase_add_test(TCase_aodv_lifetime, tc_aodv_lifetime);
    suite_add_tcase(s, TCase_aodv_lifetime);
    tcase_add_test(TCase_aodv_send_reply, tc_aodv_send_reply);
    suite_add_tcase(s, TCase_aodv_send_reply);
    tcase_add_test(TCase_aodv_send_req, tc_aodv_send_req);
    suite_add_tcase(s, TCase_aodv_send_req);
    tcase_add_test(TCase_aodv_reverse_path_discover, tc_aodv_reverse_path_discover);
    suite_add_tcase(s, TCase_aodv_reverse_path_discover);
    tcase_add_test(TCase_aodv_recv_valid_rreq, tc_aodv_recv_valid_rreq);
    suite_add_tcase(s, TCase_aodv_recv_valid_rreq);
    tcase_add_test(TCase_aodv_parse_rreq, tc_aodv_parse_rreq);
    suite_add_tcase(s, TCase_aodv_parse_rreq);
    tcase_add_test(TCase_aodv_parse_rrep, tc_aodv_parse_rrep);
    suite_add_tcase(s, TCase_aodv_parse_rrep);
    tcase_add_test(TCase_aodv_parse_rerr, tc_aodv_parse_rerr);
    suite_add_tcase(s, TCase_aodv_parse_rerr);
    tcase_add_test(TCase_aodv_parse_rack, tc_aodv_parse_rack);
    suite_add_tcase(s, TCase_aodv_parse_rack);
    tcase_add_test(TCase_pico_aodv_parse, tc_pico_aodv_parse);
    suite_add_tcase(s, TCase_pico_aodv_parse);
    tcase_add_test(TCase_pico_aodv_socket_callback, tc_pico_aodv_socket_callback);
    suite_add_tcase(s, TCase_pico_aodv_socket_callback);
    tcase_add_test(TCase_aodv_make_rreq, tc_aodv_make_rreq);
    suite_add_tcase(s, TCase_aodv_make_rreq);
    tcase_add_test(TCase_aodv_retrans_rreq, tc_aodv_retrans_rreq);
    suite_add_tcase(s, TCase_aodv_retrans_rreq);
    tcase_add_test(TCase_pico_aodv_expired, tc_pico_aodv_expired);
    suite_add_tcase(s, TCase_pico_aodv_expired);
    tcase_add_test(TCase_pico_aodv_collector, tc_pico_aodv_collector);
    suite_add_tcase(s, TCase_pico_aodv_collector);
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
