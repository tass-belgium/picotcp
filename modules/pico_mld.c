/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   RFC 2710 3019 3590 3810 4604 6636 

   Authors: Roel Postelmans
 *********************************************************************/

#include "pico_stack.h"
#include "pico_ipv6.h"
#include "pico_mld.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_frame.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "pico_socket.h"
#include "pico_icmp6.h"
#include "pico_dns_client.h"
#include "pico_mld.h"
#define mld_dbg printf
#define PICO_MLD_LISTENER_QUERY          130
#define PICO_MLD_LISTENER_REPORT         131
#define PICO_MLD_LISTENER_REDUCTION      132

/* MLD groups */
#define MLD_ALL_HOST_GROUP               "FF01:0:0:0:0:0:0:1" 
#define MLD_ALL_ROUTER_GROUP             "FF01:0:0:0:0:0:0:2" 
#define MLD_TIMER_STOPPED                (1)
uint8_t pico_mld_flag = 0;

PACKED_STRUCT_DEF mld_message {
	uint8_t type;
	uint8_t code;
	uint16_t crc;
	uint16_t max_resp_delay;
	uint16_t reserved;
	struct pico_ip6 mcast_group;
};

typedef int (*mld_callback) (struct mld_parameters *);
static int pico_mld_process_event(struct mld_parameters *p); 
static struct mld_parameters *pico_mld_find_parameter(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group);

/* queues */
static struct pico_queue mld_in = {
    0
};
static struct pico_queue mld_out = {
    0
};
static void pico_mld_report_expired(struct mld_timer *t)
{
    struct mld_parameters *p = NULL;

    p = pico_mld_find_parameter(&t->mcast_link, &t->mcast_group);
    if (!p)
        return;

    p->event = MLD_EVENT_TIMER_EXPIRED;
    pico_mld_process_event(p);
}
static inline int mldparm_group_compare(struct mld_parameters *a,  struct mld_parameters *b)
{
    return pico_ipv6_compare(&a->mcast_group, &b->mcast_group);
}

static inline int mldparm_link_compare(struct mld_parameters *a,  struct mld_parameters *b)
{
    return pico_ipv6_compare(&a->mcast_link, &b->mcast_link);
}


static int mld_parameters_cmp(void *ka, void *kb)
{
    struct mld_parameters *a = ka, *b = kb;
    int cmp = mldparm_group_compare(a, b);
    if (cmp)
        return cmp;

    return mldparm_link_compare(a, b);
}
static inline int mldt_type_compare(struct mld_timer *a,  struct mld_timer *b)
{
    if (a->type < b->type)
        return -1;

    if (a->type > b->type)
        return 1;

    return 0;
}


static inline int mldt_group_compare(struct mld_timer *a,  struct mld_timer *b)
{
    return pico_ipv6_compare(&a->mcast_group, &b->mcast_group);
}

static inline int mldt_link_compare(struct mld_timer *a,  struct mld_timer *b)
{
    return pico_ipv4_compare(&a->mcast_link, &b->mcast_link);
}
PICO_TREE_DECLARE(MLDParameters, mld_parameters_cmp);
static int mld_timer_cmp(void *ka, void *kb)
{
    struct mld_timer *a = ka, *b = kb;
    int cmp = mldt_type_compare(a, b);
    if (cmp)
        return cmp;

    cmp = mldt_group_compare(a, b);
    if (cmp)
        return cmp;

    return mldt_link_compare(a, b);

}
static int pico_mld_delete_parameter(struct mld_parameters *p)
{
    if (pico_tree_delete(&MLDParameters, p))
        PICO_FREE(p);
    else
        return -1;

    return 0;
}
PICO_TREE_DECLARE(MLDTimers, mld_timer_cmp);
static void pico_mld_timer_expired(pico_time now, void *arg)
{
    struct mld_timer *t = NULL, *timer = NULL, test = {
        0
    };

    IGNORE_PARAMETER(now);
    t = (struct mld_timer *)arg;
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    mld_dbg("MLD: timer expired for %08X link %08X type %u, delay %lu\n", t->mcast_group.addr, t->mcast_link.addr, t->type, t->delay);
    timer = pico_tree_findKey(&MLDTimers, &test);
    if (!timer) {
        return;
    }

    if (timer->stopped == MLD_TIMER_STOPPED) {
        PICO_FREE(t);
        return;
    }

    if (timer->start + timer->delay < PICO_TIME_MS()) {
        pico_tree_delete(&MLDTimers, timer);
        if (timer->mld_callback)
            timer->mld_callback(timer);

        PICO_FREE(timer);
    } else {
        mld_dbg("MLD: restart timer for %08X, delay %lu, new delay %lu\n", t->mcast_group.addr, t->delay,  (timer->start + timer->delay) - PICO_TIME_MS());
        pico_timer_add((timer->start + timer->delay) - PICO_TIME_MS(), &pico_mld_timer_expired, timer);
    }

    return;
}

static int pico_mld_timer_reset(struct mld_timer *t)
{
    struct mld_timer *timer = NULL, test = {
        0
    };

    mld_dbg("MLD: reset timer for %08X, delay %lu\n", t->mcast_group.addr, t->delay);
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&MLDTimers, &test);
    if (!timer)
        return -1;

    *timer = *t;
    timer->start = PICO_TIME_MS();
    return 0;
}

static int pico_mld_timer_start(struct mld_timer *t)
{
    struct mld_timer *timer = NULL, test = {
        0
    };

    mld_dbg("MLD: start timer for %08X link %08X type %u, delay %lu\n", t->mcast_group.addr, t->mcast_link.addr, t->type, t->delay);
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&MLDTimers, &test);
    if (timer)
        return pico_mld_timer_reset(t);

    timer = PICO_ZALLOC(sizeof(struct mld_timer));
    if (!timer) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    *timer = *t;
    timer->start = PICO_TIME_MS();

    pico_tree_insert(&MLDTimers, timer);
    pico_timer_add(timer->delay, &pico_mld_timer_expired, timer);
    return 0;
}

static int pico_mld_timer_stop(struct mld_timer *t)
{
    struct mld_timer *timer = NULL, test = {
        0
    };

    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&MLDTimers, &test);
    if (!timer)
        return 0;

    mld_dbg("MLD: stop timer for %08X, delay %lu\n", timer->mcast_group.addr, timer->delay);
    timer->stopped = MLD_TIMER_STOPPED;
    return 0;
}

static int pico_mld_timer_is_running(struct mld_timer *t)
{
    struct mld_timer *timer = NULL, test = {
        0
    };

    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&MLDTimers, &test);
    if (timer)
        return 1;

    return 0;
}

static struct mld_timer *pico_mld_find_timer(uint8_t type, struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group)
{
    struct mld_timer test = {
        0
    };

    test.type = type;
    memcpy(&test.mcast_link, mcast_link, sizeof(struct pico_ip6));
    memcpy(&test.mcast_group, mcast_group, sizeof(struct pico_ip6));
    return pico_tree_findKey(&MLDTimers, &test);
}


static struct mld_parameters *pico_mld_find_parameter(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group)
{
    struct mld_parameters test = {
        0
    };
    if (!mcast_link || !mcast_group)
        return NULL;
    uint8_t i;
    for(i = 0; i< sizeof(struct pico_ip6); i++) {
        test.mcast_link.addr[i] = mcast_link->addr[i];
        test.mcast_group.addr[i] = mcast_group->addr[i];
    }
    return pico_tree_findKey(&MLDParameters, &test);
}	
static int pico_mld_is_checksum_valid(struct pico_frame *f) {
    if( pico_icmp6_checksum(f) == 0)
        return 1;
    mld_dbg("ICMP6 (MLD) : invalid checksum\n");
    return 0;
}
/* RFC 3810 $8 */
static int pico_mld_compatibility_mode(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_ipv6_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_hbhoption * hbh = NULL; 
    /*struct mld_timer t = {
        0
    };*/
    uint16_t len, datalen; 
   link = pico_ipv6_link_by_dev(f->dev);
    if (!link)
        return -1;
    ipv6_hdr = (struct pico_ipv6_hdr *) f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *) f->transport_hdr;
    
    len = (uint16_t) (short_be(ipv6_hdr->len) +f->transport_len);
    datalen = (uint16_t)(f->buffer_len - PICO_SIZE_IP6HDR);
    if (f->dev->eth) {
        datalen = (uint16_t)(datalen - PICO_SIZE_ETHHDR);
    } 
    datalen -= IP_OPTION_ROUTER_ALERT_LEN ; 
    mld_dbg("MLD: LEN = %u, OCTETS = %u\n", short_be(ipv6_hdr->len), datalen);
    if( datalen >= 28) {
        /* MLDv2 */
        //link->mcast_compatibility = PICO_MLDV2;
        mld_dbg("MLD Compatibility: v2\n");
    } else if( datalen == 24) {
        /* MLDv1 */
        //link->mcast_compatibility = PICO_MLDV1;
        mld_dbg("MLD Compatibility: v1\n");
    } else {
        /* invalid query, silently ignored */
        return -1;
    }
    return 0;
}

int pico_mld_state_change(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group, uint8_t filter_mode, struct pico_tree *_MCASTFilter, uint8_t state)
{
    struct mld_parameters *p = NULL;
    struct pico_ip6 ipv6;
    pico_string_to_ipv6(MLD_ALL_HOST_GROUP, &ipv6);

    if (!memcmp(&mcast_group->addr, &ipv6, sizeof(struct pico_ip6)))
        return 0;

    p = pico_mld_find_parameter(mcast_link, mcast_group);
    if (!p && state == PICO_MLD_STATE_CREATE) {
        p = PICO_ZALLOC(sizeof(struct mld_parameters));
        if (!p) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if (!mcast_link || !mcast_group) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        p->state = MLD_STATE_NON_LISTENER;
        p->mcast_link = *mcast_link;
        p->mcast_group = *mcast_group;
        pico_tree_insert(&MLDParameters, p);
        char *tmp= PICO_ZALLOC(50);
        pico_ipv6_to_string(tmp, mcast_link->addr);
    } else if (!p) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (state) {
    case PICO_MLD_STATE_CREATE:
        p->event = MLD_EVENT_CREATE_GROUP;
        break;

    case PICO_MLD_STATE_UPDATE:
        p->event = MLD_EVENT_UPDATE_GROUP;
        break;

    case PICO_MLD_STATE_DELETE:
        p->event = MLD_EVENT_DELETE_GROUP;
        break;

    default:
        return -1;
    }
    p->filter_mode = filter_mode;
    p->MCASTFilter = _MCASTFilter;
    return pico_mld_process_event(p);
}


/* finite state machine caller */
static int pico_mld_process_event(struct mld_parameters *p);

static struct mld_parameters *pico_mld_analyse_packet(struct pico_frame *f)
{
    struct pico_icmp6_hdr *hdr = (struct pico_icmp6_hdr *) f->transport_hdr;
    struct pico_ipv6_hdr *ipv6_hdr = (struct pico_ipv6_hdr *) f->net_hdr;
    struct pico_ipv6_link *link = NULL;
    struct mld_parameters *p = NULL;
    uint8_t general_query = 1;
    struct pico_ip6 mcast_group = {
        0
    };
    struct mld_message *mld_report = hdr;
    
    link = pico_ipv6_link_by_dev(f->dev);
    if(!link) 
        return NULL;

    uint32_t i;
    for(i = 0; i < sizeof(struct pico_ip6); i++) {
        mcast_group.addr[i] = mld_report->mcast_group.addr[i];
        if(mcast_group.addr[i] != 0)
            general_query = 0;
    }

    /* Package check */
    if(ipv6_hdr->hop != MLD_HOP_LIMIT) {
        mld_dbg("MLD: Hop limit > 1, ignoring frame\n");
        return NULL;
    }
    struct pico_ipv6_exthdr *hbh = ipv6_hdr+ipv6_hdr->nxthdr;
    if(hbh->ext.routing.routtype != 0) {
        mld_dbg("MLD: Router Alert option is not set\n");
        return NULL;
    }
    if(!pico_ipv6_is_linklocal(ipv6_hdr->src.addr) || pico_ipv6_is_unspecified(ipv6_hdr->src.addr) ) {
        mld_dbg("MLD Source is invalid link-local address\n");
        return NULL;
    }
    /* end package check */

    p = pico_mld_find_parameter(&link->address, &mcast_group); 
   
    if(!p) {
        mld_dbg("Alloc-ing MLD parameters\n");
        p = PICO_ZALLOC(sizeof(struct mld_parameters));
        if(!p)
            return NULL;
        p->state = MLD_STATE_NON_LISTENER;
        for(i = 0; i< sizeof(struct pico_ip6); i++) 
            p->mcast_link.addr[i] = link->address.addr[i];
        pico_tree_insert(&MLDParameters,p);
    } 
    mld_dbg("Analyse package, type = %d\n", hdr->type);
    switch(hdr->type) {
    case PICO_MLD_QUERY:
        //p->max_resp_time = hdr->msg.info.mld.max_response_time;
        p->event = MLD_EVENT_QUERY_RECV;
        break;
    case PICO_MLD_REPORT:
        p->event = MLD_EVENT_REPORT_RECV;
        break;
    case PICO_MLD_DONE:
        p->event = MLD_EVENT_DONE_RECV;
        break;
    case PICO_MLD_REPORTV2:
        p->event = MLD_EVENT_REPORT_RECV;
        break;
    }
    p->f = f; 
    p->general_query = general_query;
    return p;
}
int pico_mld_process_in(struct pico_frame *f)
{
    struct mld_parameters *p = NULL;
   
    mld_dbg("CHECKSUM 0x%X\n" , pico_icmp6_checksum(f) );
    if (!pico_mld_is_checksum_valid(f))
        goto out;
    if (pico_mld_compatibility_mode(f) < 0)
        goto out;
    p = pico_mld_analyse_packet(f);
    if (!p)
        goto out;
    return pico_mld_process_event(p);

out:
    mld_dbg("FRAME DISCARD\n");
    pico_frame_discard(f);
    return 0;
}



static int8_t pico_mld_send_done(struct mld_parameters *p, struct pico_frame *f) {
    return 0;
}
#define IPV6_MAX_STRLEN \
        sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
static int pico_mld_send_report(struct mld_parameters *p, struct pico_frame *f)
{
    struct pico_ip6 dst = {
        0
    };
    struct pico_ip6 mcast_group = {
        0
    };
    struct pico_ipv6_link *link = NULL;
    link = pico_ipv6_link_get(&p->mcast_link);
    if (!link)
        return -1;

    memcpy(&mcast_group.addr,&p->mcast_group.addr, sizeof(struct pico_ip6));
    switch (link->mcast_compatibility) {
    case PICO_MLDV1:
        if (p->event == MLD_EVENT_STOP_LISTENING)
            pico_string_to_ipv6(MLD_ALL_ROUTER_GROUP, &dst.addr);
        else 
            memcpy(&dst.addr, &mcast_group.addr, sizeof(struct pico_ip6));

        break;
/*
    case PICO_MLDV2:
        dst.addr = MLDV3_ALL_ROUTER_GROUP;
        break;
*/
    default:
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;
    }
    /*TODO*/

    mld_dbg("MLD: send membership report on group TODO to TODO\n");
    pico_ipv6_frame_push(f, NULL, &dst, PICO_PROTO_ICMP6,0);
    return 0;
}

static int8_t pico_mld_generate_report(struct mld_parameters *p)
{
    struct pico_ipv6_link *link = NULL;
    int i = 0;
    link = pico_ipv6_link_get(&p->mcast_link);
    if (!link) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if( !pico_ipv6_is_multicast(p->mcast_group.addr) ) {
        return -1;
    }
    switch (link->mcast_compatibility) {

    case PICO_MLDV1:
    {
        struct mld_message *report = NULL; 
        uint8_t report_type = PICO_MLD_REPORT;

        p->f = pico_proto_ipv6.alloc(&pico_proto_ipv6, IP_OPTION_ROUTER_ALERT_LEN + sizeof(struct mld_message));
        p->f->net_len = (uint16_t)(p->f->net_len + IP_OPTION_ROUTER_ALERT_LEN);
        //p->f->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
        //p->f->transport_len = (uint16_t)(p->f->transport_len - IP_OPTION_ROUTER_ALERT_LEN);
        p->f->dev = pico_ipv6_link_find(&p->mcast_link);
        /* p->f->len is correctly set by alloc */

        report = (struct mld_message *)p->f->transport_hdr;
        report->type = report_type;
        report->max_resp_delay = MLD_DEFAULT_MAX_RESPONSE_TIME;
        report->mcast_group = p->mcast_group;

        report->crc = 0;
        report->crc = short_be(pico_icmp6_checksum(p->f));
        break;
    }

    
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    return 0;
}
/* stop timer, send done if flag set */
static int mld_stsdifs(struct mld_parameters *p)
{
    struct mld_timer t = {
        0
    };

    mld_dbg("MLD: event = stop listening | action = stop timer, send done if flag set\n");

    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    if (pico_mld_timer_stop(&t) < 0)
        return -1;

    /* Send done if flag is set */
    if (pico_mld_flag && pico_mld_send_done(p, p->f) < 0)
        return -1;

    pico_mld_delete_parameter(p);
    mld_dbg("MLD: new state = Non-Listener\n");
    return 0;
}
/* send report, set flag, start timer */
static int mld_srsfst(struct mld_parameters *p)
{
    struct mld_timer t = {
        0
    };
    struct pico_frame *copy_frame = NULL;
    uint8_t i;
    mld_dbg("MLD: event = start listening | action = send report, set flag, start timer\n");

    p->last_host = MLD_HOST_LAST;
    if (pico_mld_generate_report(p) < 0)
        return -1;
    if (!p->f)
        return 0;
    copy_frame = pico_frame_copy(p->f);
    if (!copy_frame) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    if (pico_mld_send_report(p, copy_frame) < 0)
        return -1;

    t.type = MLD_TIMER_V1_REPORT;
    for(i=0; i<sizeof(struct pico_ip6); i++) {
        t.mcast_link.addr[i] = p->mcast_link.addr[i];
        t.mcast_group.addr[i] = p->mcast_group.addr[i];
    }
    t.delay = (pico_rand() % (MLD_UNSOLICITED_REPORT_INTERVAL * 10000));
    t.f = p->f;
    t.mld_callback = pico_mld_report_expired;
    pico_mld_timer_start(&t);
    pico_mld_flag = 1;
    p->state = MLD_STATE_DELAYING_LISTENER;
    mld_dbg("MLD: new state = Delaying Listener\n");
    return 0;
}
/* send done if flag set */
static int mld_sdifs(struct mld_parameters *p)
{
    mld_dbg("MLD: event stop listenings | action = send done if flag set\n");

    /* Send done if flag is set */
    if (pico_mld_flag && pico_mld_send_done(p, p->f) < 0)
        return -1;

    pico_mld_delete_parameter(p);
    mld_dbg("MLD: new state = Non-Listener\n");
    return 0;
}

/* start timer */
static int mld_st(struct mld_parameters *p)
{
    struct mld_timer t = {
        0
    };

    mld_dbg("MLD: event = query received | action = start timer\n");

    if (pico_mld_generate_report(p) < 0) {
        mld_dbg("Failed to generate report\n");
        return -1;
    }

    if (!p->f) {
        mld_dbg("No pending frame\n");
        return -1;
    }

    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    t.delay = (pico_rand() % ((1u + p->max_resp_time) * 100u));
    t.f = p->f;
    t.mld_callback = pico_mld_report_expired;
    pico_mld_timer_start(&t);

    p->state = MLD_STATE_DELAYING_LISTENER;
    mld_dbg("MLD: new state = delaying member\n");
    return 0;
}

/* stop timer, clear flag */
static int mld_stcl(struct mld_parameters *p)
{
    struct mld_timer t = {
        0
    };

    mld_dbg("MLD: event = report received | action = stop timer, clear flag\n");

    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    if (pico_mld_timer_stop(&t) < 0)
        return -1;
    pico_mld_flag = 0;
    p->last_host = MLD_HOST_NOT_LAST;
    p->state = MLD_STATE_IDLE_LISTENER;
    mld_dbg("MLD: new state = Idle Listener\n");
    return 0;
}
/* send report, set flag */
static int mld_srsf(struct mld_parameters *p)
{
    mld_dbg("MLD: event = timer expired | action = send report, set flag\n");

    if (pico_mld_send_report(p, p->f) < 0)
        return -1;
    pico_mld_flag = 1;
    p->state = MLD_STATE_IDLE_LISTENER;
    mld_dbg("MLD: new state = Idle Listener\n");
    return 0;
}
/* reset timer if max response time < current timer */
static int mld_rtimrtct(struct mld_parameters *p)
{
    struct mld_timer *t = NULL;
    uint32_t current_timer = 0;

    mld_dbg("MLD: event = query received | action = reset timer if max response time < current timer\n");

    t = pico_mld_find_timer(MLD_TIMER_GROUP_REPORT, &p->mcast_link, &p->mcast_group);
    if (!t)
        return -1;

    current_timer = (uint32_t)(t->start + t->delay - PICO_TIME_MS());
    if ((p->max_resp_time * 100u) < current_timer) { /* max_resp_time in units of 1/10 seconds */
        t->delay = pico_rand() % ((1u + p->max_resp_time) * 100u);
        pico_mld_timer_reset(t);
    }
    /* State is already Delaying Listener*/
    /*
    p->state = MLD_STATE_DELAYING_LISTENER;
    mld_dbg("MLD: new state = Delaying Listener\n");
    */
    return 0;
}
static int mld_discard(struct mld_parameters *p)
{
    mld_dbg("MLD: ignore and mld_discard frame\n");
    //pico_frame_discard(p->f);
    return 0;
}


    
/* finite state machine table */
static const mld_callback mld_state_diagram[3][6] =
{ /* event                    |Query received  |Done reveive |Report receive |Timer expired  | Stop Listening  | Start listening */
/* state Non-Member      */
/* none listener*/          { mld_discard ,         mld_srsfst,       mld_discard,        mld_discard,         mld_discard,          mld_srsfst},
/* idle listener */         {   mld_st ,         mld_discard,       mld_discard,        mld_discard,           mld_sdifs,          mld_discard },
/* delaying listener     */ { mld_rtimrtct,         mld_discard,          mld_stcl,           mld_srsf,         mld_stsdifs,          mld_discard }
};

static int pico_mld_process_event(struct mld_parameters *p) {
    struct pico_tree_node *index= NULL;
    struct mld_parameters *_p;
    char ipv6[PICO_IPV6_STRING];
    
    pico_ipv6_to_string(ipv6, p->mcast_group.addr);
    mld_dbg("MLD: process event on group address %s\n", ipv6);
    if (p->event == MLD_EVENT_QUERY_RECV && p->general_query) { /* general query */
        pico_tree_foreach(index, &MLDParameters) {
            _p = index->keyValue;
            _p->max_resp_time = p->max_resp_time;
            _p->event = MLD_EVENT_QUERY_RECV;
            mld_dbg("MLD: for each mcast_group = %08X | state = %u\n", ipv6, _p->state);
            return mld_state_diagram[_p->state][_p->event](_p);
        }
    } else {
        mld_dbg("MLD: state = %u (0: non-listener - 1: delaying listener - 2: idle listener) event = %u\n", p->state, p->event);
       return mld_state_diagram[p->state][p->event](p);
    }
    return 0;
}
