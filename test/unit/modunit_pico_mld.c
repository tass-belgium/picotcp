#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_stack.h"
#include "pico_socket.h"
#include "pico_queue.h"
#include "pico_tree.h"
#include "modules/pico_mld.c"
#include "check.h"
#include "pico_dev_null.c"
Suite *pico_suite(void);
uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg) 
{
    IGNORE_PARAMETER(expire);
    IGNORE_PARAMETER(timer);
    IGNORE_PARAMETER(arg);
    return NULL;
}
int mock_callback(struct mld_timer *t) {
    IGNORE_PARAMETER(t);
    return 0;
}
static int mcast_filter_cmp_ipv6(void *ka, void *kb)
{
    union pico_address *a = ka, *b = kb;
    return memcmp(&a->ip6, &b->ip6, sizeof(struct pico_ip6));
}
static int mcast_sources_cmp_ipv6(void *ka, void *kb)
{
    union pico_address *a = ka, *b = kb;
    return memcmp(&a->ip6, &b->ip6, sizeof(struct pico_ip6));
}
PICO_TREE_DECLARE(_MCASTFilter, mcast_filter_cmp_ipv6);

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
START_TEST(tc_pico_mld_v1querier_expired)
{
    struct mld_timer t;
    struct pico_ip6 addr = {{0}};
    struct pico_device *dev = pico_null_create("dummy2");
    struct pico_frame *f = pico_frame_alloc(sizeof(struct pico_frame));
    t.f = f;
    pico_string_to_ipv6("AAAA::1", addr.addr);
    //void function, just check for side effects
    //No link
    pico_mld_v1querier_expired(&t); 
    f->dev = dev;
    pico_ipv6_link_add(dev, addr, addr);
    pico_mld_v1querier_expired(&t); 
}
END_TEST
START_TEST(tc_pico_mld_send_report) 
{
    struct pico_frame *f;
    struct pico_device *dev = pico_null_create("dummy1");
    struct pico_ip6 addr;
    struct pico_ipv6_link *link;
    struct mld_parameters p;
    f = pico_proto_ipv6.alloc(&pico_proto_ipv6, sizeof(struct mldv2_report)+MLD_ROUTER_ALERT_LEN+sizeof(struct mldv2_group_record) +(0 *sizeof(struct pico_ip6)));
    pico_string_to_ipv6("AAAA::1", addr.addr);
    p.mcast_link = addr;
    //No link
    fail_if(pico_mld_send_report(&p, f) != -1); 
    link = pico_ipv6_link_add(dev, addr, addr);
    p.event = 0;
    link->mcast_compatibility = PICO_MLDV1;
    fail_if(pico_mld_send_report(&p, f) != 0); 
    link->mcast_compatibility = 99;
    fail_if(pico_mld_send_report(&p, f) != -1); 
}
END_TEST
START_TEST(tc_pico_mld_report_expired)
{
    struct mld_timer t;
    struct pico_ip6 zero = {{0}};
    struct mld_parameters p;
    t.mcast_link = zero;
    t.mcast_group = zero;
    p.mcast_link = zero;
    p.mcast_group = zero;
    //void function, just check for side effects
    pico_mld_report_expired(&t);
    //pico_tree_insert(&MLDParameters, &p);
    //pico_mld_report_expired(&t);
}
END_TEST
START_TEST(tc_pico_mld_delete_parameter)
{
    struct mld_parameters p;
    fail_if(pico_mld_delete_parameter(&p) != -1);
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
START_TEST(tc_pico_mld_is_checksum_valid) {
    struct pico_frame *f;
    f = pico_proto_ipv6.alloc(&pico_proto_ipv6, sizeof(struct mldv2_report)+MLD_ROUTER_ALERT_LEN+sizeof(struct mldv2_group_record) +(0 *sizeof(struct pico_ip6)));
    fail_if(pico_mld_is_checksum_valid(f) == 1);
}
END_TEST
START_TEST(tc_pico_mld_find_parameter) {
    struct pico_ip6 mcast_link, mcast_group;
    struct mld_parameters test = {
        0
    };
    fail_if(pico_mld_find_parameter(NULL,NULL) != NULL);
    pico_string_to_ipv6("AAAA::1", mcast_link.addr);
    fail_if(pico_mld_find_parameter(&mcast_link,NULL) != NULL);
    pico_string_to_ipv6("AAAA::2", mcast_group.addr);
    fail_if(pico_mld_find_parameter(&mcast_link,&mcast_group) != NULL);
    test.mcast_link = mcast_link;
    test.mcast_group = mcast_group;
    pico_tree_insert(&MLDParameters, &test);

    fail_if(pico_mld_find_parameter(&mcast_link,&mcast_group) == NULL);
}
END_TEST
START_TEST(tc_pico_mld_timer_expired)
{
    struct mld_timer *t,*s;
    t = PICO_ZALLOC(sizeof(struct mld_timer));
    t->stopped = MLD_TIMER_STOPPED;
    t->type = 0;
    pico_string_to_ipv6("AAAA::1", t->mcast_link.addr);
    pico_string_to_ipv6("AAAA::1", t->mcast_group.addr);
    //void function, just check for side effects
    pico_mld_timer_expired(NULL, (void *)t);
    pico_tree_insert(&MLDTimers, t);
    s = PICO_ZALLOC(sizeof(struct mld_timer));
    memcpy(s,t,sizeof(struct mld_timer)); // t will be freed next test
    pico_mld_timer_expired(NULL, (void *)t); /* will be freed */
    s->stopped++;
    s->start = PICO_TIME_MS()*2;
    s->type++;
    pico_tree_insert(&MLDTimers, s);
    t = PICO_ZALLOC(sizeof(struct mld_timer));
    memcpy(t,s,sizeof(struct mld_timer)); // s will be freed next test
    pico_mld_timer_expired(NULL, (void *)s); /* s will be freed */
    t->mld_callback = mock_callback;
    pico_mld_timer_expired(NULL, (void *)t); /* t will be freed */
}
END_TEST
START_TEST(tc_pico_mld_send_done) {
    struct mld_parameters p;
    fail_if(pico_mld_send_done(&p, NULL) != 0);
}
END_TEST
START_TEST(tc_mld_stsdifs) 
{
    struct mld_parameters *p;
    struct pico_device *dev = pico_null_create("dummy3");
    struct pico_ipv6_link *link;
    struct pico_ipv6_mcast_group g; 
    struct mldv2_report *report;
    struct mld_timer t;
    //Building example frame
    p = PICO_ZALLOC(sizeof(struct mld_parameters));
    pico_string_to_ipv6("AAAA::1", p->mcast_link.addr);
    pico_string_to_ipv6("FF00::e007:707", p->mcast_group.addr);
    //no link
    fail_if(mld_stsdifs(p) != -1);
    link = pico_ipv6_link_add(dev, p->mcast_link, p->mcast_link);
    link->mcast_compatibility = PICO_MLDV1;
    // no timer
    fail_if(mld_stsdifs(p) != -1);
    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    pico_tree_insert(&MLDTimers, &t);
    fail_if(mld_stsdifs(p) != 0);
    //set flag
    pico_mld_flag = 1;
    fail_if(mld_stsdifs(p) != 0);
}
END_TEST
START_TEST(tc_mld_srsf) 
{
    struct mld_parameters *p;
    struct pico_device *dev = pico_null_create("dummy3");
    struct pico_ipv6_link *link;
    struct pico_ipv6_mcast_group g; 
    struct mldv2_report *report;
    struct mld_timer t;
    //Building example frame
    
    p = PICO_ZALLOC(sizeof(struct mld_parameters));
    pico_string_to_ipv6("AAAA::1", p->mcast_link.addr);
    pico_string_to_ipv6("FF00::e007:707", p->mcast_group.addr);
    fail_if(mld_srsf(p) != -1);
}
END_TEST

START_TEST(tc_mld_srst) 
{
    struct mld_parameters *p;
    struct pico_device *dev = pico_null_create("dummy3");
    struct pico_ipv6_link *link;
    struct pico_ipv6_mcast_group g; 
    struct mldv2_report *report;
    struct mld_timer t;
    //Building example frame
    
    p = PICO_ZALLOC(sizeof(struct mld_parameters));
    pico_string_to_ipv6("AAAA::1", p->mcast_link.addr);
    pico_string_to_ipv6("FF00::e007:707", p->mcast_group.addr);
    p->MCASTFilter = &_MCASTFilter;
    p->filter_mode = 0;
    g.filter_mode = 0;   
    g.mcast_addr = p->mcast_group;
    g.MCASTSources.root = &LEAF;
    g.MCASTSources.compare = mcast_sources_cmp_ipv6;

    pico_tree_insert(&MLDParameters, p);
    //no link
    fail_if(mld_srst(p) != -1);
    link = pico_ipv6_link_add(dev, p->mcast_link, p->mcast_link);
    link->mcast_compatibility = PICO_MLDV1;
    // invalid proto
    fail_if(mld_srst(p) != -1);
    link->mcast_compatibility = PICO_MLDV2;
    pico_tree_insert(link->MCASTGroups, &g);
    
    fail_if(mld_srst(p) != 0);
}
END_TEST
START_TEST(tc_mld_mrsrrt) 
{
    struct mld_parameters *p;
    struct pico_device *dev = pico_null_create("dummy3");
    struct pico_ipv6_link *link;
    struct pico_tree *filter = PICO_ZALLOC(sizeof(struct pico_tree));
    int i,j, _i,_j,result;
    struct pico_ipv6_mcast_group g; 
    struct mldv2_report *report;
    //Building example frame
    p = PICO_ZALLOC(sizeof(struct mld_parameters));
    pico_string_to_ipv6("AAAA::1", p->mcast_link.addr);
    pico_string_to_ipv6("FF00::e007:707", p->mcast_group.addr);
    //no link
    fail_if(mld_mrsrrt(p) != -1);
    link = pico_ipv6_link_add(dev, p->mcast_link, p->mcast_link);
    link->mcast_compatibility = PICO_MLDV1;
    // wrong proto
    fail_if(mld_mrsrrt(p) != -1);
    link->mcast_compatibility = PICO_MLDV2;
    p->f = pico_proto_ipv6.alloc(&pico_proto_ipv6, sizeof(struct mldv2_report)+MLD_ROUTER_ALERT_LEN+sizeof(struct mldv2_group_record) +(0 *sizeof(struct pico_ip6)));
    fail_if(mld_mrsrrt(p) != -1);
    
}
END_TEST
START_TEST(tc_pico_mld_process_in) {
    struct mld_parameters *p;
    struct pico_device *dev = pico_null_create("dummy3");
    struct pico_ipv6_link *link;
    struct pico_tree *filter = PICO_ZALLOC(sizeof(struct pico_tree));
    int i,j, _i,_j,result;
    struct pico_ipv6_mcast_group g; 
    struct mldv2_report *report;
    //Building example frame
    p = PICO_ZALLOC(sizeof(struct mld_parameters));
    pico_string_to_ipv6("AAAA::1", p->mcast_link.addr);
    pico_string_to_ipv6("FF00::e007:707", p->mcast_group.addr);
    //no link
    fail_if(pico_mld_generate_report(p) != -1);
    link = pico_ipv6_link_add(dev, p->mcast_link, p->mcast_link);
    pico_string_to_ipv6("AAAA::1", p->mcast_group.addr);
    fail_if(pico_mld_generate_report(p) != -1);
    pico_string_to_ipv6("FF00::e007:707", p->mcast_group.addr);
    link->mcast_compatibility = PICO_MLDV1;
    g.mcast_addr = p->mcast_group;
    g.MCASTSources.root = &LEAF;
    g.MCASTSources.compare = mcast_sources_cmp_ipv6;
    // No mcastsources tree
    link->mcast_compatibility = PICO_MLDV2;
    fail_if(pico_mld_generate_report(p) != -1);
    pico_tree_insert(link->MCASTGroups, &g);
    pico_tree_insert(&MLDParameters, p);
    
    link->mcast_compatibility = 99;
    fail_if(pico_mld_generate_report(p) != -1);
    link->mcast_compatibility = PICO_MLDV1;
    fail_if(pico_mld_generate_report(p) != 0);
    link->mcast_compatibility = PICO_MLDV2;
    for(_j =0; _j<3; _j++) {   //FILTER
        (_j == 2) ? (result = -1) : (result = 0);
        for(_i=0; _i<3; _i++) {  //FILTER
            if(_i == 2) result = -1;
            for(i = 0; i<3; i++) {  //STATES
                for(j = 0; j<6; j++) { //EVENTS
                    p->MCASTFilter = &_MCASTFilter;
                    p->filter_mode = _i;
                    g.filter_mode = _j;
                    if(p->event == MLD_EVENT_DELETE_GROUP || p->event == MLD_EVENT_QUERY_RECV)
                        p->event++;
                    fail_if(pico_mld_generate_report(p) != result);
                    p->state = i;
                    p->event = j;
                    if(result != -1 && p->f) {//in some combinations, no frame is created
                        report = p->f->transport_hdr + MLD_ROUTER_ALERT_LEN;
                        report->crc = short_be(pico_icmp6_checksum(p->f));
                        fail_if(pico_mld_process_in(p->f) != 0);
                    }
                }
            }
        }
    }
}
END_TEST
START_TEST(tc_mld_rtimrtct) {
    struct mld_timer *t = PICO_ZALLOC(sizeof(struct mld_timer));
    struct pico_device *dev = pico_null_create("dummy0");
    struct mld_parameters p;
    pico_string_to_ipv6("AAAA::1", t->mcast_link.addr);
    pico_string_to_ipv6("AAAA::1", t->mcast_group.addr);
    p.mcast_link = t->mcast_link;
    p.mcast_group = t->mcast_group;
    t->type = MLD_TIMER_GROUP_REPORT;
    //not in tree
    fail_if(mld_rtimrtct(&p) != -1);
    pico_mld_timer_start(t);
    fail_if(mld_rtimrtct(&p) != 0);
}
END_TEST

START_TEST(tc_mld_stcl) {
    struct mld_timer *t = PICO_ZALLOC(sizeof(struct mld_timer));
    struct pico_device *dev = pico_null_create("dummy0");
    struct mld_parameters p;
    pico_string_to_ipv6("AAAA::1", t->mcast_link.addr);
    pico_string_to_ipv6("AAAA::1", t->mcast_group.addr);
    p.mcast_link = t->mcast_link;
    p.mcast_group = t->mcast_group;
    t->type = MLD_TIMER_GROUP_REPORT;
    //not in tree
    fail_if(mld_stcl(&p) != -1);
    pico_mld_timer_start(t);
    fail_if(mld_stcl(&p) != 0);
}
END_TEST
START_TEST(tc_pico_mld_compatibility_mode) {
    struct pico_frame *f;
    struct pico_device *dev = pico_null_create("ummy1");
    struct pico_ip6 addr;

    f = pico_proto_ipv6.alloc(&pico_proto_ipv6, sizeof(struct mldv2_report)+MLD_ROUTER_ALERT_LEN+sizeof(struct mldv2_group_record) +(0 *sizeof(struct pico_ip6)));
    pico_string_to_ipv6("AAAA::1", addr.addr);
    //No link
    fail_if(pico_mld_compatibility_mode(f) != -1); 
    pico_ipv6_link_add(dev, addr, addr);
    f->dev = dev;
    //MLDv2 query
    f->buffer_len = 28 + PICO_SIZE_IP6HDR + MLD_ROUTER_ALERT_LEN;
    fail_if(pico_mld_compatibility_mode(f) != 0); 
    //MLDv1 query
    f->buffer_len = 24 + PICO_SIZE_IP6HDR + MLD_ROUTER_ALERT_LEN;
    fail_if(pico_mld_compatibility_mode(f) != 0);
    //Invalid Query 
    f->buffer_len = 25 + PICO_SIZE_IP6HDR + MLD_ROUTER_ALERT_LEN;
    fail_if(pico_mld_compatibility_mode(f) == 0);
    //MLDv2 query + timer amready running
    f->dev->eth = dev;
    f->buffer_len = 28 + PICO_SIZE_IP6HDR + MLD_ROUTER_ALERT_LEN+PICO_SIZE_ETHHDR;
    fail_if(pico_mld_compatibility_mode(f) != -1); 
}
END_TEST
START_TEST(tc_pico_mld_timer_reset) {
    struct mld_timer t;
    pico_string_to_ipv6("AAAA::1", t.mcast_link.addr);
    pico_string_to_ipv6("AAAA::1", t.mcast_group.addr);
    t.type = 0;
    fail_if(pico_mld_timer_reset(&t)!=-1);
}
END_TEST
START_TEST(tc_pico_mld_state_change) {
    struct pico_ip6 mcast_link, mcast_group;
    struct mld_parameters p;
    pico_string_to_ipv6("AAAA::1", mcast_link.addr);
    pico_string_to_ipv6("AAAA::1", mcast_group.addr);
    p.mcast_link = mcast_link;
    p.mcast_group = mcast_group;
    
    fail_if(pico_mld_state_change(NULL, &mcast_group, 0,NULL, PICO_MLD_STATE_CREATE) != -1);
    fail_if(pico_mld_state_change(&mcast_link, &mcast_group, 0,NULL, PICO_MLD_STATE_CREATE) != -1);
    fail_if(pico_mld_state_change(&mcast_link, &mcast_group, 0,NULL, 99) != -1);
    pico_tree_insert(&MLDParameters, &p);
    fail_if(pico_mld_state_change(&mcast_link, &mcast_group, 0,NULL, 99) != -1);
}
END_TEST
START_TEST(tc_pico_mld_analyse_packet) {
    struct pico_frame *f;

    struct pico_device *dev = pico_null_create("dummy0");
    struct pico_ip6 addr;
    struct pico_ip6 local;
    struct pico_ipv6_hdr *ip6;
    struct pico_ipv6_hbhoption *hbh;
    struct pico_icmp6_hdr *mld;
    f = pico_proto_ipv6.alloc(&pico_proto_ipv6, sizeof(struct mld_message)+MLD_ROUTER_ALERT_LEN);
    pico_string_to_ipv6("AAAA::1", addr.addr);
    pico_string_to_ipv6("FE80::1", local.addr);
    //No link
    fail_if(pico_mld_analyse_packet(f) != NULL); 
    pico_ipv6_link_add(dev, addr, addr);
    f->dev = dev;
    ip6 = f->net_hdr;
    ip6->hop == 99;
    // Incorrect hop
    fail_if(pico_mld_analyse_packet(f) != NULL);
    ip6->hop = 1;
    hbh = f->transport_hdr;
    pico_mld_fill_hopbyhop(hbh);
    hbh->type = 99;
    //incorrect hop by hop
    fail_if(pico_mld_analyse_packet(f) != NULL);
    pico_mld_fill_hopbyhop(hbh);
    ip6->src = addr;
    //Not link local
    fail_if(pico_mld_analyse_packet(f) != NULL);
    memcpy(&ip6->src, PICO_IP6_ANY, sizeof(struct pico_ip6));
    fail_if(pico_mld_analyse_packet(f) != NULL);
    ip6->src = local;
    mld = (struct pico_icmp6_hdr *) (f->transport_hdr+MLD_ROUTER_ALERT_LEN);
    mld->type = 0;
    
    //wrong type
    fail_if(pico_mld_analyse_packet(f) != NULL);

    // all correct
    mld->type = PICO_MLD_QUERY;
    fail_if(pico_mld_analyse_packet(f) == NULL);
    mld->type = PICO_MLD_REPORT;
    fail_if(pico_mld_analyse_packet(f) == NULL);
    mld->type = PICO_MLD_DONE;
    fail_if(pico_mld_analyse_packet(f) == NULL);
    mld->type = PICO_MLD_REPORTV2;
    fail_if(pico_mld_analyse_packet(f) == NULL);
}
END_TEST
START_TEST(tc_pico_mld_discard) {
    mld_discard(NULL);
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
    TCase *TCase_pico_mld_discard = tcase_create("Unit test for pico_mld_discard");
    TCase *TCase_pico_mld_compatibility_mode = tcase_create("Unit test for pico_mld_compatibility");
    TCase *TCase_pico_mld_v1querier_expired = tcase_create("Unit test for pico_mld_v1querier_expired");
    TCase *TCase_pico_mld_delete_parameter = tcase_create("Unit test for pico_mld_delete_parameter");
    TCase *TCase_pico_mld_timer_expired = tcase_create("Unit test for pico_mld_timer_expired");
    TCase *TCase_pico_mld_timer_reset = tcase_create("Unit test for pico_mld_timer_reset");
    TCase *TCase_pico_mld_send_done = tcase_create("Unit test for pico_mld_send_done");
    TCase *TCase_pico_mld_is_checksum_valid = tcase_create("Unit test for pico_mld_is_checksum");
    TCase *TCase_pico_mld_find_parameter = tcase_create("Unit test for pico_mld_find_parameter");
    TCase *TCase_pico_mld_state_change = tcase_create("Unit test for pico_mld_state_change");
    TCase *TCase_mld_srst = tcase_create("Unit test for pico_mld_srst");
    TCase *TCase_mld_stcl = tcase_create("Unit test for pico_mld_stcl");
    TCase *TCase_pico_mld_process_in = tcase_create("Unit test for pico_mld_process_in");
    TCase *TCase_pico_mld_send_report = tcase_create("Unit test for pico_mld_send_report");
    TCase *TCase_mld_stsdifs = tcase_create("Unit test for mld_stsdifs");
    TCase *TCase_mld_srsf = tcase_create("Unit test for mld_srsf");
    TCase *TCase_mld_rtimrtct = tcase_create("Unit test for mld_rtimrtct");
    TCase *TCase_mld_mrsrrt = tcase_create("Unit test for mld_mrsrrt");
    
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
    tcase_add_test(TCase_pico_mld_discard, tc_pico_mld_discard);
    suite_add_tcase(s, TCase_pico_mld_discard);
    tcase_add_test(TCase_pico_mld_compatibility_mode, tc_pico_mld_compatibility_mode);
    suite_add_tcase(s, TCase_pico_mld_compatibility_mode);
    tcase_add_test(TCase_pico_mld_v1querier_expired, tc_pico_mld_v1querier_expired);
    suite_add_tcase(s, TCase_pico_mld_v1querier_expired);
    tcase_add_test(TCase_pico_mld_delete_parameter, tc_pico_mld_delete_parameter);
    suite_add_tcase(s, TCase_pico_mld_delete_parameter);
    tcase_add_test(TCase_pico_mld_timer_expired, tc_pico_mld_timer_expired);
    suite_add_tcase(s, TCase_pico_mld_timer_expired);
    tcase_add_test(TCase_pico_mld_timer_reset, tc_pico_mld_timer_reset);
    suite_add_tcase(s, TCase_pico_mld_timer_reset);
    tcase_add_test(TCase_pico_mld_send_done, tc_pico_mld_send_done);
    suite_add_tcase(s, TCase_pico_mld_send_done);
    tcase_add_test(TCase_pico_mld_is_checksum_valid, tc_pico_mld_is_checksum_valid);
    suite_add_tcase(s, TCase_pico_mld_is_checksum_valid);
    tcase_add_test(TCase_pico_mld_find_parameter, tc_pico_mld_find_parameter);
    suite_add_tcase(s, TCase_pico_mld_find_parameter);
    tcase_add_test(TCase_pico_mld_state_change, tc_pico_mld_state_change);
    suite_add_tcase(s, TCase_pico_mld_state_change);
    tcase_add_test(TCase_mld_srst, tc_mld_srst);
    suite_add_tcase(s, TCase_mld_srst);
    tcase_add_test(TCase_mld_stcl, tc_mld_stcl);
    suite_add_tcase(s, TCase_mld_stcl);
    tcase_add_test(TCase_pico_mld_process_in, tc_pico_mld_process_in);
    suite_add_tcase(s, TCase_pico_mld_process_in);
    tcase_add_test(TCase_pico_mld_send_report, tc_pico_mld_send_report);
    suite_add_tcase(s, TCase_pico_mld_send_report);
    tcase_add_test(TCase_mld_stsdifs, tc_mld_stsdifs);
    suite_add_tcase(s, TCase_mld_stsdifs);
    tcase_add_test(TCase_mld_srsf, tc_mld_srsf);
    suite_add_tcase(s, TCase_mld_srsf);
    tcase_add_test(TCase_mld_rtimrtct, tc_mld_rtimrtct);
    suite_add_tcase(s, TCase_mld_rtimrtct);
    tcase_add_test(TCase_mld_mrsrrt, tc_mld_mrsrrt);
    suite_add_tcase(s, TCase_mld_mrsrrt);
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
