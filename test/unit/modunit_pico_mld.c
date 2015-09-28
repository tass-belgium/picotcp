#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_stack.h"
#include "pico_socket.h"
#include "pico_queue.h"
#include "pico_tree.h"
#include "modules/pico_mld.c"
#include "check.h"

Suite *pico_suite(void);
struct pico_timer *pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg) 
{
    IGNORE_PARAMETER(expire);
    IGNORE_PARAMETER(timer);
    IGNORE_PARAMETER(arg);
    return NULL;
}

START_TEST(tc_pico_mld_fill_hopbyhop)
{
    struct pico_ipv6_hbhoption *hbh = NULL;
    // Not-null case tested by unit_ipv6.c
    fail_if(pico_mld_fill_hopbyhop(hbh) != NULL);
}
END_TEST
START_TEST(tc_pico_mld_check_hopbyhop)
{
    struct pico_ipv6_hbhoption *hbh = NULL;
    struct pico_ipv6_hbhoption _hbh;
    uint8_t *p;
    uint8_t options[8] = { PICO_PROTO_ICMP6, 0, PICO_IPV6_EXTHDR_OPT_ROUTER_ALERT,\
                                    PICO_IPV6_EXTHDR_OPT_ROUTER_ALERT_DATALEN,0,0,1,0 };
    int i = 0;
    int test = 0;
    fail_if(pico_mld_check_hopbyhop(hbh) != -1);
    _hbh.type = 1;
    _hbh.len = 0;
    fail_if(pico_mld_check_hopbyhop(&_hbh) != -1);
    _hbh.type = PICO_PROTO_ICMP6;
    _hbh.len = 1;
    fail_if(pico_mld_check_hopbyhop(&_hbh) != -1);

    hbh = (struct pico_ipv6_hbhoption *) PICO_ZALLOC(sizeof(struct pico_ipv6_hbhoption)+ 7);
    hbh->type = PICO_PROTO_ICMP6;
    hbh->len = 0;
    for(test = 0; test<7; test++) {
        p = (uint8_t *)hbh + sizeof(struct pico_ipv6_hbhoption);
        for(i = 0; i<6; i++ ) {
            if(i != test)
                *(p++) = options[i+2];
            else
                *(p++) = 9;
        }
        if(test != 6)
            fail_if(pico_mld_check_hopbyhop(hbh) != -1);
        else
            fail_if(pico_mld_check_hopbyhop(hbh) != 0);
    }
}
END_TEST
START_TEST(tc_pico_mld_report_expired)
{
    struct mld_timer t;
    struct pico_ip6 zero = {{0}};
    t.mcast_link = zero;
    t.mcast_group = zero;
    //void function, just check for side effects
    pico_mld_report_expired(&t);
}
END_TEST
START_TEST(tc_mldt_type_compare) 
{
    struct mld_timer a;
    struct mld_timer b;
    a.type = 1;
    b.type = 2;
    fail_if(mldt_type_compare(&a,&b) != -1);
    fail_if(mldt_type_compare(&b,&a) != 1);
    fail_if(mld_timer_cmp(&b,&a) != 1);
}
END_TEST
START_TEST(tc_pico_mld_analyse_packet) {
/*    struct pico_frame *f = pico_frame_alloc(200);
    struct pico_device dev= {{0}};
    struct pico_ip6 addr = {{0}};
    struct pico_ipv6_hdr ip6 ={ 0, 0 , 0 , 10, {{0}}, {{0}} };
    struct pico_ipv6_hbhoption *hbh = PICO_ZALLOC(sizeof(struct pico_ipv6_hbhoption)+10);

    pico_ipv6_link_add(&dev, addr, addr);
    fail_if(pico_mld_analyse_packet(f) != NULL); 
    f->dev = &dev;
    f->net_hdr = (uint8_t *)&ip6;
    f->transport_hdr = (uint8_t *)&ip6;
    fail_if(pico_mld_analyse_packet(f) != NULL);
    ip6.hop = 1;
    pico_mld_fill_hopbyhop(hbh);
    hbh->type = 99;
    f->transport_hdr = (uint8_t *)hbh;
    fail_if(pico_mld_analyse_packet(f) != NULL);*/
}
END_TEST
Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_mld_fill_hopbyhop = tcase_create("Unit test for pico_mld_fill_hopbyhop");
    TCase *TCase_pico_mld_check_hopbyhop = tcase_create("Unit test for pico_mld_check_hopbyhop");
    TCase *TCase_pico_mld_report_expired = tcase_create("Unit test for pico_mld_report_expired");
    TCase *TCase_mldt_type_compare = tcase_create("Unit test for mldt_type_compare");
    TCase *TCase_pico_mld_analyse_packet = tcase_create("Unit test for pico_mld_analyse_packet");
    
    tcase_add_test(TCase_pico_mld_fill_hopbyhop, tc_pico_mld_fill_hopbyhop);
    suite_add_tcase(s, TCase_pico_mld_fill_hopbyhop);
    tcase_add_test(TCase_pico_mld_check_hopbyhop, tc_pico_mld_check_hopbyhop);
    suite_add_tcase(s, TCase_pico_mld_check_hopbyhop);
    tcase_add_test(TCase_pico_mld_report_expired, tc_pico_mld_report_expired);
    suite_add_tcase(s, TCase_pico_mld_report_expired);
    tcase_add_test(TCase_mldt_type_compare, tc_mldt_type_compare);
    suite_add_tcase(s, TCase_mldt_type_compare);
    tcase_add_test(TCase_pico_mld_analyse_packet, tc_pico_mld_analyse_packet);
    suite_add_tcase(s, TCase_pico_mld_analyse_packet);
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
