#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_stack.h"
#include "pico_socket.h"
#include "pico_queue.h"
#include "pico_tree.h"
#include "modules/pico_igmp.c"
#include "check.h"
#include "pico_dev_null.c"

Suite *pico_suite(void);
void mock_callback(struct igmp_timer *t);

static uint32_t timers_added = 0;
uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    IGNORE_PARAMETER(expire);
    IGNORE_PARAMETER(timer);
    IGNORE_PARAMETER(arg);
    return ++timers_added;
}

void mock_callback(struct igmp_timer *t)
{
    IGNORE_PARAMETER(t);
}
static int mcast_filter_cmp(void *ka, void *kb)
{
    union pico_address *a = ka, *b = kb;
    if (a->ip4.addr < b->ip4.addr)
        return -1;

    if (a->ip4.addr > b->ip4.addr)
        return 1;

    return 0;
}
static int mcast_sources_cmp(void *ka, void *kb)
{
    union pico_address *a = ka, *b = kb;
    if (a->ip4.addr < b->ip4.addr)
        return -1;

    if (a->ip4.addr > b->ip4.addr)
        return 1;

    return 0;
}
static PICO_TREE_DECLARE(_MCASTFilter, mcast_filter_cmp);
START_TEST(tc_pico_igmp_report_expired)
{
    struct igmp_timer *t = PICO_ZALLOC(sizeof(struct igmp_timer));
    struct pico_ip4 zero = {0};
    t->mcast_link = zero;
    t->mcast_group = zero;
    /* void function, just check for side effects */
    pico_igmp_report_expired(t);
}
END_TEST
START_TEST(tc_igmpt_type_compare)
{
    struct igmp_timer a;
    struct igmp_timer b;
    a.type = 1;
    b.type = 2;
    fail_if(igmpt_type_compare(&a, &b) != -1);
    fail_if(igmpt_type_compare(&b, &a) != 1);
    fail_if(igmp_timer_cmp(&b, &a) != 1);
}
END_TEST
START_TEST(tc_pico_igmp_state_change)
{
    struct pico_ip4 mcast_link, mcast_group;
    pico_string_to_ipv4("192.168.1.1", &mcast_link.addr);
    pico_string_to_ipv4("224.7.7.7", &mcast_group.addr);
    fail_if(pico_igmp_state_change(&mcast_link, &mcast_group, 0, NULL, 99) != -1);
    fail_if(pico_igmp_state_change(&mcast_link, &mcast_group, 0, NULL, PICO_IGMP_STATE_CREATE) != 0);
}
END_TEST
START_TEST(tc_pico_igmp_timer_expired)
{
    struct igmp_timer *t, *s;
    t = PICO_ZALLOC(sizeof(struct igmp_timer));
    t->stopped = IGMP_TIMER_STOPPED;
    t->type = 0;
    pico_string_to_ipv4("192.168.1.1", &t->mcast_link.addr);
    pico_string_to_ipv4("244.7.7.7", &t->mcast_group.addr);
    /* void function, just check for side effects */
    pico_igmp_timer_expired(0, (void *)t);
    pico_tree_insert(&IGMPTimers, t);
    s = PICO_ZALLOC(sizeof(struct igmp_timer));
    memcpy(s,t,sizeof(struct igmp_timer)); // t will be freed next test
    pico_igmp_timer_expired(0, (void *)t); /* t is freed here */
    s->stopped++;
    s->start = PICO_TIME_MS()*2;
    s->type++;
    pico_tree_insert(&IGMPTimers, s);
    t = PICO_ZALLOC(sizeof(struct igmp_timer));
    memcpy(t,s,sizeof(struct igmp_timer)); // s will be freed next test
    pico_igmp_timer_expired(0, (void *)s); /* s is freed here */
    t->callback = mock_callback;
    pico_igmp_timer_expired(0, (void *)t);
}
END_TEST
START_TEST(tc_pico_igmp_v2querier_expired)
{
    struct igmp_timer *t = PICO_ZALLOC(sizeof(struct igmp_timer));
    struct pico_ip4 addr = {0};
    struct pico_device *dev = pico_null_create("dummy2");
    struct pico_frame *f = pico_frame_alloc(sizeof(struct pico_frame));
    t->f = f;
    pico_string_to_ipv4("192.168.1.1", &(addr.addr));
    /* void function, just check for side effects */
    /* No link */
    pico_igmp_v2querier_expired(t);
    f->dev = dev;
    pico_ipv4_link_add(dev, addr, addr);
    pico_igmp_v2querier_expired(t);
}
END_TEST
START_TEST(tc_pico_igmp_delete_parameter)
{
    struct mcast_parameters p;
    fail_if(pico_igmp_delete_parameter(&p) != -1);
}
END_TEST
START_TEST(tc_pico_igmp_process_in)
{
    struct mcast_parameters *p;
    struct pico_device *dev = pico_null_create("dummy3");
    struct pico_ipv4_link *link;
    uint8_t i, j, _i, _j;
    int result;
    struct pico_mcast_group g;
    /* Building example frame */
    p = PICO_ZALLOC(sizeof(struct mcast_parameters));
    pico_string_to_ipv4("192.168.1.1", &p->mcast_link.ip4.addr);
    pico_string_to_ipv4("244.7.7.7", &p->mcast_group.ip4.addr);
    /* no link */
    fail_if(pico_igmp_generate_report(p) != -1);

    pico_ipv4_link_add(dev, p->mcast_link.ip4, p->mcast_link.ip4);
    link = pico_ipv4_link_get(&p->mcast_link.ip4);
    link->mcast_compatibility = PICO_IGMPV2;
    g.mcast_addr.ip4 = p->mcast_group.ip4;
    g.MCASTSources.root = &LEAF;
    g.MCASTSources.compare = mcast_sources_cmp;
    /* No mcastsources tree */
    link->mcast_compatibility = PICO_IGMPV3;
    fail_if(pico_igmp_generate_report(p) != -1);
    pico_tree_insert(link->MCASTGroups, &g);
    pico_tree_insert(&IGMPParameters, p);

    link->mcast_compatibility = 99;
    fail_if(pico_igmp_generate_report(p) != -1);
    link->mcast_compatibility = PICO_IGMPV2;
    fail_if(pico_igmp_generate_report(p) != 0);
    link->mcast_compatibility = PICO_IGMPV3;
    for(_j = 0; _j < 3; _j++) {   /* FILTER */
        (_j == 2) ? (result = -1) : (result = 0);
        for(_i = 0; _i < 3; _i++) {  /* FILTER */
            if(_i == 2) result = -1;

            for(i = 0; i < 3; i++) {  /* STATES */
                for(j = 0; j < 6; j++) { /* EVENTS */
                    p->MCASTFilter = &_MCASTFilter;
                    p->filter_mode = _i;
                    g.filter_mode = _j;
                    if(p->event == IGMP_EVENT_DELETE_GROUP || p->event == IGMP_EVENT_QUERY_RECV)
                        p->event++;

                    fail_if(pico_igmp_generate_report(p) != result);
                    p->state = i;
                    p->event = j;
                    if(result != -1 && p->f) /* in some combinations, no frame is created */
                        fail_if(pico_igmp_process_in(NULL, p->f) != 0);
                }
            }
        }
    }
}
END_TEST
START_TEST(tc_pico_igmp_find_parameter)
{
    struct pico_ip4 mcast_link, mcast_group;
    struct mcast_parameters test = {
        0
    };
    fail_if(pico_igmp_find_parameter(NULL, NULL) != NULL);
    pico_string_to_ipv4("192.168.1.1", &mcast_link.addr);
    fail_if(pico_igmp_find_parameter(&mcast_link, NULL) != NULL);
    pico_string_to_ipv4("192.168.1.2", &mcast_group.addr);
    fail_if(pico_igmp_find_parameter(&mcast_link, &mcast_group) != NULL);
    test.mcast_link.ip4 = mcast_link;
    test.mcast_group.ip4 = mcast_group;
    pico_tree_insert(&IGMPParameters, &test);

    fail_if(pico_igmp_find_parameter(&mcast_link, &mcast_group) == NULL);
}
END_TEST
START_TEST(tc_pico_igmp_compatibility_mode)
{
    struct pico_frame *f;
    struct pico_device *dev = pico_null_create("dummy1");
    struct pico_ip4 addr;
    struct pico_ipv4_hdr *hdr;
    struct igmp_message *query;
    uint8_t ihl = 24;
    f = pico_proto_ipv4.alloc(&pico_proto_ipv4, dev, sizeof(struct igmpv3_report) + sizeof(struct igmpv3_group_record) + (0 * sizeof(struct pico_ip4)));
    pico_string_to_ipv4("192.168.1.2", &addr.addr);
    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    ihl = (uint8_t)((hdr->vhl & 0x0F) * 4); /* IHL is in 32bit words */
    query = (struct igmp_message *) f->transport_hdr;
    /* No link */
    fail_if(pico_igmp_compatibility_mode(f) != -1);
    pico_ipv4_link_add(dev, addr, addr);
    f->dev = dev;
    /* Igmpv3 query */
    hdr->len = short_be((uint16_t)(12 + ihl));
    fail_if(pico_igmp_compatibility_mode(f) != 0);
    /* Igmpv2 query */
    hdr->len = short_be((uint16_t)(8 + ihl));
    query->max_resp_time = 0;
    fail_if(pico_igmp_compatibility_mode(f) == 0);
    query->max_resp_time = 1;
    fail_if(pico_igmp_compatibility_mode(f) != 0);
    /* Invalid Query */
    hdr->len = short_be((uint16_t)(9 + ihl));
    fail_if(pico_igmp_compatibility_mode(f) == 0);
}
END_TEST
START_TEST(tc_pico_igmp_analyse_packet)
{
    struct pico_frame *f;
    struct pico_device *dev = pico_null_create("dummy0");
    struct pico_ip4 addr;
    struct igmp_message *igmp;
    f = pico_proto_ipv4.alloc(&pico_proto_ipv4, dev, sizeof(struct igmp_message));
    pico_string_to_ipv4("192.168.1.1", &addr.addr);
    /* No link */
    fail_if(pico_igmp_analyse_packet(f) != NULL);
    pico_ipv4_link_add(dev, addr, addr);
    f->dev = dev;

    igmp = (struct igmp_message *) (f->transport_hdr);
    igmp->type = 0;
    /* wrong type */
    fail_if(pico_igmp_analyse_packet(f) != NULL);

    /* all correct */
    igmp->type = IGMP_TYPE_MEM_QUERY;
    fail_if(pico_igmp_analyse_packet(f) == NULL);
    igmp->type = IGMP_TYPE_MEM_REPORT_V1;
    fail_if(pico_igmp_analyse_packet(f) == NULL);
    igmp->type = IGMP_TYPE_MEM_REPORT_V2;
    fail_if(pico_igmp_analyse_packet(f) == NULL);
    igmp->type = IGMP_TYPE_MEM_REPORT_V3;
    fail_if(pico_igmp_analyse_packet(f) == NULL);
}
END_TEST
START_TEST(tc_pico_igmp_discard)
{
    /* TODO */
}
END_TEST
START_TEST(tc_srst)
{
    struct mcast_parameters p;
    struct pico_device *dev = pico_null_create("dummy0");
    struct pico_ipv4_link *link;

    pico_string_to_ipv4("192.168.1.1", &p.mcast_link.ip4.addr);
    /* no link */
    fail_if(srst(&p) != -1);
    pico_ipv4_link_add(dev, p.mcast_link.ip4, p.mcast_link.ip4);
    link = pico_ipv4_link_get(&p.mcast_link.ip4);
    /* Not supported protocol for this call */
    link->mcast_compatibility = PICO_IGMPV2;
    fail_if(srst(&p) != -1);
    link->mcast_compatibility = PICO_IGMPV3;
    fail_if(srst(&p) != -1);
}
END_TEST
START_TEST(tc_stcl)
{
    struct igmp_timer *t = PICO_ZALLOC(sizeof(struct igmp_timer));
    struct mcast_parameters p;

    pico_string_to_ipv4("192.168.1.10", &t->mcast_link.addr);
    pico_string_to_ipv4("244.7.7.7", &t->mcast_group.addr);
    p.mcast_link.ip4 = t->mcast_link;
    p.mcast_group.ip4 = t->mcast_group;
    t->type = IGMP_TIMER_GROUP_REPORT;
    /* not in tree */
    fail_if(stcl(&p) != -1);
    pico_igmp_timer_start(t);
    fail_if(stcl(&p) != 0);
}
END_TEST

Suite *pico_suite(void)
{

    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_igmp_report_expired = tcase_create("Unit test for pico_igmp_report_expired");
    TCase *TCase_igmpt_type_compare = tcase_create("Unit test for igmpt_type_compare");
    TCase *TCase_pico_igmp_analyse_packet = tcase_create("Unit test for pico_igmp_analyse_packet");
    TCase *TCase_pico_igmp_discard = tcase_create("Unit test for pico_igmp_discard");
    TCase *TCase_pico_igmp_compatibility_mode = tcase_create("Unit test for pico_igmp_compatibility");
    TCase *TCase_pico_igmp_state_change = tcase_create("Unit test for pico_igmp_state_change");
    TCase *TCase_pico_igmp_process_in = tcase_create("Unit test for pico_igmp_process_in");
    TCase *TCase_pico_igmp_timer_expired = tcase_create("Unit test for pico_igmp_timer_expired");
    TCase *TCase_pico_igmp_delete_parameter = tcase_create("Unit test for pico_igmp_delete_parameter");
    TCase *TCase_pico_igmp_find_parameter = tcase_create("Unit test for pico_igmp_find_parameter");
    TCase *TCase_stcl = tcase_create("Unit test for stcl");
    TCase *TCase_srst = tcase_create("Unit test for srst");
    TCase *TCase_pico_igmp_v2querier_expired = tcase_create("Unit test for pico_igmp_v2_querier_expired");

    tcase_add_test(TCase_pico_igmp_report_expired, tc_pico_igmp_report_expired);
    suite_add_tcase(s, TCase_pico_igmp_report_expired);
    tcase_add_test(TCase_igmpt_type_compare, tc_igmpt_type_compare);
    suite_add_tcase(s, TCase_igmpt_type_compare);
    tcase_add_test(TCase_pico_igmp_analyse_packet, tc_pico_igmp_analyse_packet);
    suite_add_tcase(s, TCase_pico_igmp_analyse_packet);
    tcase_add_test(TCase_pico_igmp_discard, tc_pico_igmp_discard);
    suite_add_tcase(s, TCase_pico_igmp_discard);
    tcase_add_test(TCase_pico_igmp_compatibility_mode, tc_pico_igmp_compatibility_mode);
    suite_add_tcase(s, TCase_pico_igmp_compatibility_mode);
    suite_add_tcase(s, TCase_pico_igmp_state_change);
    tcase_add_test(TCase_pico_igmp_state_change, tc_pico_igmp_state_change);
    suite_add_tcase(s, TCase_pico_igmp_process_in);
    tcase_add_test(TCase_pico_igmp_process_in, tc_pico_igmp_process_in);
    suite_add_tcase(s, TCase_pico_igmp_timer_expired);
    tcase_add_test(TCase_pico_igmp_timer_expired, tc_pico_igmp_timer_expired);
    suite_add_tcase(s, TCase_pico_igmp_delete_parameter);
    tcase_add_test(TCase_pico_igmp_delete_parameter, tc_pico_igmp_delete_parameter);
    suite_add_tcase(s, TCase_pico_igmp_find_parameter);
    tcase_add_test(TCase_pico_igmp_find_parameter, tc_pico_igmp_find_parameter);
    suite_add_tcase(s, TCase_stcl);
    tcase_add_test(TCase_stcl, tc_stcl);
    suite_add_tcase(s, TCase_srst);
    tcase_add_test(TCase_srst, tc_srst);
    suite_add_tcase(s, TCase_pico_igmp_v2querier_expired);
    tcase_add_test(TCase_pico_igmp_v2querier_expired, tc_pico_igmp_v2querier_expired);
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
