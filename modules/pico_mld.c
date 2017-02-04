/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

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
#include "pico_constants.h"
#include "pico_mcast.h"

#if defined(PICO_SUPPORT_MLD) && defined(PICO_SUPPORT_IPV6) && defined(PICO_SUPPORT_MCAST)

#ifdef DEBUG_MLD
#define mld_dbg dbg
#else
#define mld_dbg(...) do {} while(0)
#endif

/* MLD groups */
#define MLD_ALL_HOST_GROUP               "FF01:0:0:0:0:0:0:1"
#define MLD_ALL_ROUTER_GROUP             "FF01:0:0:0:0:0:0:2"
#define MLDV2_ALL_ROUTER_GROUP           "FF02:0:0:0:0:0:0:16"
#define MLD_ROUTER_ALERT_LEN             (8)

static uint8_t pico_mld_flag = 0;

PACKED_STRUCT_DEF mld_message {
    uint8_t type;
    uint8_t code;
    uint16_t crc;
    uint16_t max_resp_delay;
    uint16_t reserved;
    struct pico_ip6 mcast_group;
};
PACKED_STRUCT_DEF mldv2_group_record {
    uint8_t type;
    uint8_t aux;
    uint16_t nbr_src;
    struct pico_ip6 mcast_group;
    struct pico_ip6 src[1];
};
PACKED_STRUCT_DEF mldv2_report {
    uint8_t type;
    uint8_t res;
    uint16_t crc;
    uint16_t res1;
    uint16_t nbr_gr;
    struct mldv2_group_record record[1];
};
PACKED_STRUCT_DEF mldv2_query {
    uint8_t type;
    uint8_t code;
    uint16_t crc;
    uint16_t max_resp_delay;
    uint16_t res;
    struct pico_ip6 mcast_group;
    uint8_t rsq;
    uint8_t qqic;
    uint16_t nbr_src;
    struct pico_ip6 source_addr[1];
};
typedef int (*mld_callback)(struct mcast_parameters *);
static int pico_mld_process_event(struct mcast_parameters *p);
static struct mcast_parameters *pico_mld_find_parameter(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group);

static uint8_t *pico_mld_fill_hopbyhop(struct pico_ipv6_hbhoption *hbh)
{
    uint8_t *p;
    if(hbh == NULL)
        return NULL;

    hbh->type = PICO_PROTO_ICMP6;
    hbh->len = 0;
    /* ROUTER ALERT, RFC2711 */
    p = (uint8_t *)hbh + sizeof(struct pico_ipv6_hbhoption);
    *(p++) = PICO_IPV6_EXTHDR_OPT_ROUTER_ALERT;
    *(p++) = PICO_IPV6_EXTHDR_OPT_ROUTER_ALERT_DATALEN;
    *(p++) = 0;
    *(p++) = 0;
    /* PadN allignment with N=2 */
    *(p++) = 1;
    *(p++) = 0; /* N-2 */
    return p;
}
static int pico_mld_check_hopbyhop(struct pico_ipv6_hbhoption *hbh)
{
    uint8_t options[8] = {
        PICO_PROTO_ICMP6, 0, PICO_IPV6_EXTHDR_OPT_ROUTER_ALERT, \
        PICO_IPV6_EXTHDR_OPT_ROUTER_ALERT_DATALEN, 0, 0, 1, 0
    };
    int i;
    uint8_t *p;
    if(hbh == NULL)
        return -1;

    if(hbh->type != options[0] || hbh->len != options[1])
        return -1;

    p = (uint8_t *)hbh + sizeof(struct pico_ipv6_hbhoption);
    for(i = 0; i < MLD_ROUTER_ALERT_LEN - 2; i++) {
        if( *(p + i) != options[i + 2])
            return -1;
    }
    return 0;
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
    return pico_ipv6_compare(&a->mcast_link, &b->mcast_link);
}
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
static void pico_mld_report_expired(struct mld_timer *t)
{
    struct mcast_parameters *p = NULL;

    p = pico_mld_find_parameter(&t->mcast_link, &t->mcast_group);
    if (!p)
        return;

    p->event = MLD_EVENT_TIMER_EXPIRED;
    pico_mld_process_event(p);
}
static PICO_TREE_DECLARE(MLDTimers, mld_timer_cmp);
static void pico_mld_v1querier_expired(struct mld_timer *t)
{
    struct pico_ipv6_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;

    link = pico_ipv6_link_by_dev(t->f->dev);
    if (!link)
        return;

    /* When changing compatibility mode, cancel all pending response
     * and retransmission timers.
     */
    pico_tree_foreach_safe(index, &MLDTimers, _tmp)
    {
        ((struct mld_timer *)index->keyValue)->stopped = MLD_TIMER_STOPPED;
        pico_tree_delete(&MLDTimers, index->keyValue);
    }
    mld_dbg("MLD: switch to compatibility mode MLDv2\n");
    link->mcast_compatibility = PICO_MLDV2;
    return;
}


static inline int mldparm_group_compare(struct mcast_parameters *a,  struct mcast_parameters *b)
{
    return pico_ipv6_compare(&a->mcast_group.ip6, &b->mcast_group.ip6);
}
static inline int mldparm_link_compare(struct mcast_parameters *a,  struct mcast_parameters *b)
{
    return pico_ipv6_compare(&a->mcast_link.ip6, &b->mcast_link.ip6);
}
static int mcast_parameters_cmp(void *ka, void *kb)
{
    struct mcast_parameters *a = ka, *b = kb;
    int cmp = mldparm_group_compare(a, b);
    if (cmp)
        return cmp;

    return mldparm_link_compare(a, b);
}

static PICO_TREE_DECLARE(MLDParameters, mcast_parameters_cmp);

static int pico_mld_delete_parameter(struct mcast_parameters *p)
{
    if (pico_tree_delete(&MLDParameters, p))
        PICO_FREE(p);
    else
        return -1;

    return 0;
}
static void pico_mld_timer_expired(pico_time now, void *arg)
{
    struct mld_timer *t = NULL, *timer = NULL, test = {
        0
    };
#ifdef DEBUG_MLD
    char ipstr[PICO_IPV6_STRING] = {
        0
    },   grpstr[PICO_IPV6_STRING] = {
        0
    };
#endif

    IGNORE_PARAMETER(now);
    t = (struct mld_timer *)arg;
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
#ifdef DEBUG_MLD
    pico_ipv6_to_string(ipstr, t->mcast_link.addr);
    pico_ipv6_to_string(grpstr, t->mcast_group.addr);
    mld_dbg("MLD: timer expired for %s link %s type %u, delay %lu\n", grpstr, ipstr, t->type, (uint64_t) t->delay);
#endif
    timer = pico_tree_findKey(&MLDTimers, &test);
    if (!timer) {
        return;
    }

    if (timer->stopped == MLD_TIMER_STOPPED) {
        pico_tree_delete(&MLDTimers, timer);
        PICO_FREE(t);
        return;
    }

    if (timer->start + timer->delay < PICO_TIME_MS()) {
        pico_tree_delete(&MLDTimers, timer);
        if (timer->mld_callback)
            timer->mld_callback(timer);

        PICO_FREE(timer);
    } else {
#ifdef DEBUG_MLD
        mld_dbg("MLD: restart timer for %s, delay %lu, new delay %lu\n", grpstr, t->delay,  (timer->start + timer->delay) - PICO_TIME_MS());
#endif
        if (!pico_timer_add((timer->start + timer->delay) - PICO_TIME_MS(), &pico_mld_timer_expired, timer)) {
            mld_dbg("MLD: Failed to start expiration timer\n");
            pico_tree_delete(&MLDTimers, timer);
            PICO_FREE(timer);
        }
    }

    return;
}

static int pico_mld_timer_reset(struct mld_timer *t)
{
    struct mld_timer *timer = NULL, test = {
        0
    };
#ifdef DEBUG_MLD
    char grpstr[PICO_IPV6_STRING] = {
        0
    };
    pico_ipv6_to_string(grpstr, t->mcast_group.addr);
    mld_dbg("MLD: reset timer for %s, delay %lu\n", grpstr, t->delay);
#endif
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
#ifdef DEBUG_MLD
    char ipstr[PICO_IPV6_STRING] = {
        0
    },   grpstr[PICO_IPV6_STRING] = {
        0
    };
    pico_ipv6_to_string(ipstr, t->mcast_link.addr);
    pico_ipv6_to_string(grpstr, t->mcast_group.addr);
    mld_dbg("MLD: start timer for %s link %s type %u, delay %lu\n", grpstr, ipstr, t->type, t->delay);
#endif
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
    if (pico_tree_insert(&MLDTimers, timer)) {
        mld_dbg("MLD: Failed to insert timer into tree\n");
        return -1;
	}

    if (!pico_timer_add(timer->delay, &pico_mld_timer_expired, timer)) {
        mld_dbg("MLD: Failed to start expiration timer\n");
        pico_tree_delete(&MLDTimers, timer);
        PICO_FREE(timer);
        return -1;
    }
    return 0;
}

static int pico_mld_timer_stop(struct mld_timer *t)
{
    struct mld_timer *timer = NULL, test = {
        0
    };
#ifdef DEBUG_MLD
    char grpstr[PICO_IPV6_STRING] = {
        0
    };
#endif
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&MLDTimers, &test);
    if (!timer)
        return -1;

#ifdef DEBUG_MLD
    pico_ipv6_to_string(grpstr, timer->mcast_group.addr);
    mld_dbg("MLD: stop timer for %s, delay %lu\n", grpstr, timer->delay);
#endif
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
    test.mcast_link = *mcast_link;
    test.mcast_group = *mcast_group;
    return pico_tree_findKey(&MLDTimers, &test);
}

static int mld_sources_cmp(void *ka, void *kb)
{
    struct pico_ip6 *a = ka, *b = kb;
    return pico_ipv6_compare(a, b);
}

static PICO_TREE_DECLARE(MLDAllow, mld_sources_cmp);
static PICO_TREE_DECLARE(MLDBlock, mld_sources_cmp);

static struct mcast_parameters *pico_mld_find_parameter(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group)
{
    struct mcast_parameters test = {
        0
    };
    if (!mcast_link || !mcast_group)
        return NULL;

    test.mcast_link.ip6 = *mcast_link;
    test.mcast_group.ip6 = *mcast_group;
    return pico_tree_findKey(&MLDParameters, &test);
}
static int pico_mld_is_checksum_valid(struct pico_frame *f)
{
    if( pico_icmp6_checksum(f) == 0)
        return 1;

    mld_dbg("ICMP6 (MLD) : invalid checksum\n");
    return 0;
}
uint16_t pico_mld_checksum(struct pico_frame *f)
{
    struct pico_ipv6_pseudo_hdr pseudo;
    struct pico_ipv6_hdr *ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    struct mldv2_report *icmp6_hdr = (struct mldv2_report *)(f->transport_hdr + MLD_ROUTER_ALERT_LEN);
    uint16_t len = (uint16_t) (f->transport_len - MLD_ROUTER_ALERT_LEN);

    pseudo.src = ipv6_hdr->src;
    pseudo.dst = ipv6_hdr->dst;
    pseudo.len = long_be(len);
    pseudo.nxthdr = PICO_PROTO_ICMP6;

    pseudo.zero[0] = 0;
    pseudo.zero[1] = 0;
    pseudo.zero[2] = 0;
    return pico_dualbuffer_checksum(&pseudo, sizeof(struct pico_ipv6_pseudo_hdr), icmp6_hdr, len);
}
/* RFC 3810 $8 */
static int pico_mld_compatibility_mode(struct pico_frame *f)
{
    struct pico_ipv6_link *link = NULL;
    struct mld_timer t = {
        0
    };
    uint16_t datalen;
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_icmp6_hdr *hdr = (struct pico_icmp6_hdr *) (f->transport_hdr + MLD_ROUTER_ALERT_LEN);
    struct mcast_parameters *p = NULL;
    struct pico_ip6 mcast_group = {{
                                       0
                                   }};
    struct mld_message *mld_report = (struct mld_message *) hdr;

    link = pico_ipv6_link_by_dev(f->dev);
    if (!link)
        return -1;

    datalen = (uint16_t)(f->buffer_len - PICO_SIZE_IP6HDR - MLD_ROUTER_ALERT_LEN);
    if (f->dev->eth) {
        datalen = (uint16_t)(datalen - PICO_SIZE_ETHHDR);
    }

    if( datalen >= 28) {
        /* MLDv2 */
        t.type = MLD_TIMER_V2_QUERIER;
        if (pico_mld_timer_is_running(&t)) { /* MLDv1 querier present timer still running */
            mld_dbg("Timer is already running\n");
            return -1;
        } else {
            link->mcast_compatibility = PICO_MLDV2;
            mld_dbg("MLD Compatibility: v2\n");
            return 0;
        }
    } else if( datalen == 24) {
        pico_tree_foreach_safe(index, &MLDTimers, _tmp)
        {
            ((struct mld_timer *)index->keyValue)->stopped = MLD_TIMER_STOPPED;
            pico_tree_delete(&MLDTimers, index->keyValue);
        }
        mld_dbg("MLD: switch to compatibility mode MLDv1\n");
        link->mcast_compatibility = PICO_MLDV1;

        /* Reset states to prevent deadlock */
        mcast_group = mld_report->mcast_group;
        p = pico_mld_find_parameter(&link->address, &mcast_group);
        if(p) {
            p->state = MLD_STATE_NON_LISTENER;
            p->event = MLD_EVENT_START_LISTENING;
        }

        t.type = MLD_TIMER_V1_QUERIER;
        t.delay = (pico_time) ((MLD_ROBUSTNESS * link->mcast_last_query_interval) + MLD_QUERY_RESPONSE_INTERVAL) * 1000;
        t.f = f;
        t.mld_callback = pico_mld_v1querier_expired;
        if (pico_mld_timer_start(&t) < 0)
            return -1;
    } else {
        /* invalid query, silently ignored */
        return -1;
    }

    return 0;
}

int pico_mld_state_change(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group, uint8_t filter_mode, struct pico_tree *_MCASTFilter, uint8_t state)
{
    struct mcast_parameters *p = NULL;
    struct pico_ip6 ipv6;

    pico_string_to_ipv6(MLD_ALL_HOST_GROUP, &ipv6.addr[0]);

    if (!memcmp(&mcast_group->addr, &ipv6, sizeof(struct pico_ip6)))
        return 0;

    p = pico_mld_find_parameter(mcast_link, mcast_group);
    if (!p && state == PICO_MLD_STATE_CREATE) {
        p = PICO_ZALLOC(sizeof(struct mcast_parameters));
        if (!p) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if (!mcast_link || !mcast_group) {
            pico_err = PICO_ERR_EINVAL;
            PICO_FREE(p);
            return -1;
        }

        p->state = MLD_STATE_NON_LISTENER;
        p->mcast_link.ip6 = *mcast_link;
        p->mcast_group.ip6 = *mcast_group;
        if(pico_tree_insert(&MLDParameters, p)){
			PICO_FREE(p);
			return -1;
		}
    } else if (!p) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (state) {
    case PICO_MLD_STATE_CREATE:
        p->event = MLD_EVENT_START_LISTENING;
        break;

    case PICO_MLD_STATE_UPDATE:
        p->event = MLD_EVENT_UPDATE_GROUP;
        break;

    case PICO_MLD_STATE_DELETE:
        p->event = MLD_EVENT_STOP_LISTENING;
        break;
    default:
        return -1;
    }
    p->filter_mode = filter_mode;
    p->MCASTFilter = _MCASTFilter;
    return pico_mld_process_event(p);
}
/* finite state machine caller */
static int pico_mld_process_event(struct mcast_parameters *p);

static struct mcast_parameters *pico_mld_analyse_packet(struct pico_frame *f)
{
    struct pico_icmp6_hdr *hdr = (struct pico_icmp6_hdr *) (f->transport_hdr + MLD_ROUTER_ALERT_LEN);
    struct pico_ipv6_hdr *ipv6_hdr = (struct pico_ipv6_hdr *) f->net_hdr;
    struct pico_ipv6_link *link = NULL;
    struct mcast_parameters *p = NULL;
    struct pico_ip6 mcast_group = {{
                                       0
                                   }};
    struct mld_message *mld_report = (struct mld_message *) hdr;
    struct pico_ipv6_exthdr *hbh;

    link = pico_ipv6_link_by_dev(f->dev);
    if(!link)
        return NULL;

    mcast_group = mld_report->mcast_group;
    /* Package check */
    if(ipv6_hdr->hop != MLD_HOP_LIMIT) {
        mld_dbg("MLD: Hop limit > 1, ignoring frame\n");
        return NULL;
    }

    hbh = (struct pico_ipv6_exthdr *) (f->transport_hdr);
    if(pico_mld_check_hopbyhop((struct pico_ipv6_hbhoption *)hbh) < 0) {
        mld_dbg("MLD: Router Alert option is not set\n");
        return NULL;
    }

    if(!pico_ipv6_is_linklocal(ipv6_hdr->src.addr) || pico_ipv6_is_unspecified(ipv6_hdr->src.addr)) {
        mld_dbg("MLD Source is invalid link-local address\n");
        return NULL;
    }

    /* end package check */
    p = pico_mld_find_parameter(&link->address, &mcast_group);
    if(!p) {
        mld_dbg("Alloc-ing MLD parameters\n");
        p = PICO_ZALLOC(sizeof(struct mcast_parameters));
        if(!p)
            return NULL;

        p->state = MLD_STATE_NON_LISTENER;
        p->mcast_link.ip6 = link->address;
        if (pico_tree_insert(&MLDParameters, p)) {
			PICO_FREE(p);
			return NULL;
		}
    }

    mld_dbg("Analyse package, type = %d\n", hdr->type);
    switch(hdr->type) {
    case PICO_MLD_QUERY:
        p->max_resp_time = mld_report->max_resp_delay;
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
    default:
        return NULL;
    }
    p->f = f;
    return p;
}
int pico_mld_process_in(struct pico_frame *f)
{
    struct mcast_parameters *p = NULL;

    if (!pico_mld_is_checksum_valid(f))
        goto out;

    if (pico_mld_compatibility_mode(f) < 0)
        goto out;

    if((p = pico_mld_analyse_packet(f)) == NULL)
        goto out;

    return pico_mld_process_event(p);
out:
    mld_dbg("FRAME DISCARD\n");
    pico_frame_discard(f);
    return 0;
}



static int8_t pico_mld_send_done(struct mcast_parameters *p, struct pico_frame *f)
{
    struct mld_message *report = NULL;
    uint8_t report_type = PICO_MLD_DONE;
    struct pico_device *dev = NULL;
    struct pico_ipv6_exthdr *hbh;
    struct pico_ip6 dst = {{ 0 }};
#ifdef DEBUG_MLD
    char ipstr[PICO_IPV6_STRING] = {
        0
    },  grpstr[PICO_IPV6_STRING] = {
        0
    };
#endif
    IGNORE_PARAMETER(f);
    pico_string_to_ipv6(MLD_ALL_ROUTER_GROUP, &dst.addr[0]);
    dev = pico_ipv6_link_find(&p->mcast_link.ip6);
    p->f = pico_proto_ipv6.alloc(&pico_proto_ipv6, dev, sizeof(struct mld_message) + MLD_ROUTER_ALERT_LEN);
    /* p->f->len is correctly set by alloc */
    hbh = (struct pico_ipv6_exthdr *)(p->f->transport_hdr);
    report = (struct mld_message *)(pico_mld_fill_hopbyhop((struct pico_ipv6_hbhoption*)hbh));
    if(!report) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    report->type = report_type;
    report->max_resp_delay = 0;
    report->mcast_group = p->mcast_group.ip6;

    report->crc = 0;
    /* Checksum done in ipv6 module, no need to do it twice */
    /* report->crc = short_be(pico_icmp6_checksum(p->f)); */
#ifdef DEBUG_MLD
    pico_ipv6_to_string(ipstr, dst.addr);
    pico_ipv6_to_string(grpstr, report->mcast_group.addr);
    mld_dbg("MLD: send membership done on group %s to %s\n", grpstr, ipstr);
#endif
    pico_ipv6_frame_push(p->f, NULL, &dst, 0, 0);
    return 0;
}

static int pico_mld_send_report(struct mcast_parameters *p, struct pico_frame *f)
{
    struct pico_ip6 dst = {{
                               0
                           }};
    struct pico_ip6 mcast_group = {{
                                       0
                                   }};
#ifdef DEBUG_MLD
    char ipstr[PICO_IPV6_STRING] = {
        0
    },  grpstr[PICO_IPV6_STRING] = {
        0
    };
#endif
    struct pico_ipv6_link *link = NULL;
    link = pico_ipv6_link_get(&p->mcast_link.ip6);
    if (!link)
        return -1;

    mcast_group = p->mcast_group.ip6;
    switch (link->mcast_compatibility) {
    case PICO_MLDV1:
        if (p->event == MLD_EVENT_STOP_LISTENING)
            pico_string_to_ipv6(MLD_ALL_ROUTER_GROUP, &dst.addr[0]);
        else
            dst = mcast_group;

        break;
    case PICO_MLDV2:
        pico_string_to_ipv6(MLDV2_ALL_ROUTER_GROUP, &dst.addr[0]);
        break;
    default:
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;
    }
#ifdef DEBUG_MLD
    pico_ipv6_to_string(ipstr, dst.addr);
    pico_ipv6_to_string(grpstr, mcast_group.addr);
    mld_dbg("MLD: send membership report on group %s to %s\n", grpstr, ipstr);
#endif
    pico_ipv6_frame_push(f, NULL, &dst, 0, 0);
    return 0;
}
static int8_t pico_mldv2_generate_report(struct mcast_filter_parameters *filter, struct mcast_parameters *p)
{
    struct mldv2_report *report = NULL;
    struct mldv2_group_record *record = NULL;
    struct pico_tree_node *index = NULL;
    struct pico_ipv6_hbhoption *hbh;
    struct pico_device *dev = NULL;
    uint16_t len = 0;
    uint16_t i = 0;
    /* RFC3810 $5.1.10 */
    if(filter->sources > MLD_MAX_SOURCES) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    len = (uint16_t)(sizeof(struct mldv2_report) + sizeof(struct mldv2_group_record) \
                     + (filter->sources * sizeof(struct pico_ip6)) + MLD_ROUTER_ALERT_LEN);
    len = (uint16_t)(len - sizeof(struct pico_ip6));
    dev = pico_ipv6_link_find(&p->mcast_link.ip6);
    p->f = pico_proto_ipv6.alloc(&pico_proto_ipv6, dev, len);
    /* p->f->len is correctly set by alloc */

    hbh = (struct pico_ipv6_hbhoption *) p->f->transport_hdr;
    report = (struct mldv2_report *)(pico_mld_fill_hopbyhop(hbh));
    report->type = PICO_MLD_REPORTV2;
    report->res = 0;
    report->crc = 0;
    report->res1 = 0;
    report->nbr_gr = short_be(1);

    record = &report->record[0];
    record->type = filter->record_type;
    record->aux = 0;
    record->nbr_src = short_be(filter->sources);
    record->mcast_group = p->mcast_group.ip6;
    if (filter->filter && !pico_tree_empty(filter->filter)) {
        i = 0;
        pico_tree_foreach(index, filter->filter)
        {
            record->src[i] = (*(struct pico_ip6 *)index->keyValue);
            i++;
        }
    }

    if(i != filter->sources) {
        return -1;
    }

    /* Checksum done in ipv6 module, no need to do it twice */
    /* report->crc= short_be(pico_mld_checksum(p->f)); */
    return 0;
}
static int8_t pico_mldv2_generate_filter(struct mcast_filter_parameters *filter, struct mcast_parameters *p)
{
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_tree *MLDFilter = NULL;
    struct pico_ipv6_link *link = (struct pico_ipv6_link*) filter->link;
    filter->p = (struct mcast_parameters *)p;
    filter->allow = &MLDAllow;
    filter->block = &MLDBlock;
    filter->filter = MLDFilter;
    filter->sources = 0;
    filter->proto = PICO_MLDV2;
    test.mcast_addr = p->mcast_group;
    g = pico_tree_findKey(link->MCASTGroups, &test);
    if (!g) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    filter->g = (struct pico_mcast_group *)g;
    return pico_mcast_generate_filter(filter, p);

}
static int8_t pico_mldv1_generate_report(struct mcast_parameters *p)
{
    struct mld_message *report = NULL;
    uint8_t report_type = PICO_MLD_REPORT;
    struct pico_ipv6_exthdr *hbh;
    struct pico_device *dev = pico_ipv6_link_find(&p->mcast_link.ip6);
    p->f = pico_proto_ipv6.alloc(&pico_proto_ipv6, dev, sizeof(struct mld_message) + MLD_ROUTER_ALERT_LEN );
    /* p->f->len is correctly set by alloc */

    hbh = (struct pico_ipv6_exthdr *)(p->f->transport_hdr);
    report = (struct mld_message *)(pico_mld_fill_hopbyhop((struct pico_ipv6_hbhoption *)hbh));
    report->type = report_type;
    report->max_resp_delay = MLD_DEFAULT_MAX_RESPONSE_TIME;
    report->mcast_group = p->mcast_group.ip6;

    report->crc = 0;
    /* Checksum done in ipv6 module, no need to do it twice */
    /* report->crc = short_be(pico_icmp6_checksum(p->f)); */
    return 0;
}
static int8_t pico_mld_generate_report(struct mcast_parameters *p)
{
    struct mcast_filter_parameters filter;
    int8_t result;
    filter.link = (union pico_link *)pico_ipv6_link_get(&p->mcast_link.ip6);
    if( !filter.link || !pico_ipv6_is_multicast(p->mcast_group.ip6.addr)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (filter.link->ipv6.mcast_compatibility) {

    case PICO_MLDV1: {
        return pico_mldv1_generate_report(p);
    }
    case PICO_MLDV2: {
        result = pico_mldv2_generate_filter(&filter, p);
        if(result < 0)
            return -1;

        if(result != MCAST_NO_REPORT)
            return pico_mldv2_generate_report(&filter, p);
    }
    break;
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;
}
/* stop timer, send done if flag set */
static int mld_stsdifs(struct mcast_parameters *p)
{
    struct mld_timer t = {
        0
    };
    struct pico_ipv6_link *link = NULL;
    struct pico_frame *copy_frame = NULL;
    link = pico_ipv6_link_get(&p->mcast_link.ip6);
    if (!link)
        return -1;

    mld_dbg("MLD: event = stop listening | action = stop timer, send done if flag set\n");

    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link.ip6;
    t.mcast_group = p->mcast_group.ip6;
    if (pico_mld_timer_stop(&t) < 0)
        return -1;

    switch(link->mcast_compatibility) {
    case PICO_MLDV2:
        if (pico_mld_generate_report(p) < 0) {
            return -1;
        }

        copy_frame = pico_frame_copy(p->f);
        if (!copy_frame) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if (pico_mld_send_report(p, copy_frame) < 0) {
            return -1;
        }

        break;
    case PICO_MLDV1:
        /* Send done if flag is set */
        if (pico_mld_flag && pico_mld_send_done(p, p->f) < 0)
            return -1;

        break;
    }

    pico_mld_delete_parameter(p);
    mld_dbg("MLD: new state = Non-Listener\n");
    return 0;
}
/* send report, set flag, start timer */
static int mld_srsfst(struct mcast_parameters *p)
{
    struct mld_timer t = {
        0
    };
    struct pico_frame *copy_frame = NULL;
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

    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link.ip6;
    t.mcast_group = p->mcast_group.ip6;

    t.delay = (pico_rand() % (MLD_UNSOLICITED_REPORT_INTERVAL * 10000));
    t.f = p->f;
    t.mld_callback = pico_mld_report_expired;

    if (pico_mld_timer_start(&t) < 0)
        return -1;

    pico_mld_flag = 1;
    p->state = MLD_STATE_DELAYING_LISTENER;
    mld_dbg("MLD: new state = Delaying Listener\n");
    return 0;
}

/* stop timer, clear flag */
static int mld_stcl(struct mcast_parameters *p)
{
    struct mld_timer t = {
        0
    };

    mld_dbg("MLD: event = report received | action = stop timer, clear flag\n");

    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link.ip6;
    t.mcast_group = p->mcast_group.ip6;
    if (pico_mld_timer_stop(&t) < 0)
        return -1;

    pico_mld_flag = 0;
    p->last_host = MLD_HOST_NOT_LAST;
    p->state = MLD_STATE_IDLE_LISTENER;
    mld_dbg("MLD: new state = Idle Listener\n");
    return 0;
}
/* send report, set flag */
static int mld_srsf(struct mcast_parameters *p)
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
static int mld_rtimrtct(struct mcast_parameters *p)
{
    struct mld_timer *t = NULL;
    uint32_t current_timer = 0;

    mld_dbg("MLD: event = query received | action = reset timer if max response time < current timer\n");

    t = pico_mld_find_timer(MLD_TIMER_GROUP_REPORT, &p->mcast_link.ip6, &p->mcast_group.ip6);
    if (!t)
        return -1;

    current_timer = (uint32_t)(t->start + t->delay - PICO_TIME_MS());
    if ((p->max_resp_time * 100u) < current_timer) { /* max_resp_time in units of 1/10 seconds */
        t->delay = pico_rand() % ((1u + p->max_resp_time) * 100u);
        pico_mld_timer_reset(t);
    }

    p->state = MLD_STATE_DELAYING_LISTENER;
    mld_dbg("MLD: new state = Delaying Listener\n");
    return 0;
}
/* merge report, send report, reset timer (MLDv2 only) */
static int mld_mrsrrt(struct mcast_parameters *p)
{
    struct mld_timer *t = NULL;
    struct pico_frame *copy_frame = NULL;
    struct pico_ipv6_link *link = NULL;
    mld_dbg("MLD: event = update group | action = merge report, send report, reset timer (MLDv2 only)\n");

    link = pico_ipv6_link_get(&p->mcast_link.ip6);
    if (!link)
        return -1;

    if (link->mcast_compatibility != PICO_MLDV2) {
        mld_dbg("MLD: no MLDv3 compatible router on network\n");
        return -1;
    }

    /* XXX: merge with pending report rfc 3376 $5.1 */

    copy_frame = pico_frame_copy(p->f);
    if (!copy_frame)
        return -1;

    if (pico_mld_send_report(p, copy_frame) < 0)
        return -1;

    t = pico_mld_find_timer(MLD_TIMER_GROUP_REPORT, &p->mcast_link.ip6, &p->mcast_group.ip6);
    if (!t)
        return -1;

    t->delay = (pico_rand() % (MLD_UNSOLICITED_REPORT_INTERVAL * 10000));
    pico_mld_timer_reset(t);

    p->state = MLD_STATE_DELAYING_LISTENER;
    mld_dbg("MLD: new state = delaying member\n");
    return 0;
}

/* send report, start timer (MLDv2 only) */
static int mld_srst(struct mcast_parameters *p)
{
    struct mld_timer t = {
        0
    };
    struct pico_frame *copy_frame = NULL;
    struct pico_ipv6_link *link = NULL;

    mld_dbg("MLD: event = update group | action = send report, start timer (MLDv2 only)\n");

    link = pico_ipv6_link_get(&p->mcast_link.ip6);
    if (!link)
        return -1;

    if (link->mcast_compatibility != PICO_MLDV2) {
        mld_dbg("MLD: no MLDv2 compatible router on network\n");
        return -1;
    }

    if (pico_mld_generate_report(p) < 0)
        return -1;

    if (!p->f)
        return 0;

    copy_frame = pico_frame_copy(p->f);
    if (!copy_frame)
        return -1;

    if (pico_mld_send_report(p, copy_frame) < 0)
        return -1;

    t.type = MLD_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link.ip6;
    t.mcast_group = p->mcast_group.ip6;
    t.delay = (pico_rand() % (MLD_UNSOLICITED_REPORT_INTERVAL * 10000));
    t.f = p->f;
    t.mld_callback = pico_mld_report_expired;

    if (pico_mld_timer_start(&t) < 0)
        return -1;

    p->state = MLD_STATE_DELAYING_LISTENER;
    mld_dbg("MLD: new state = delaying member\n");
    return 0;
}
static int mld_discard(struct mcast_parameters *p)
{
    mld_dbg("MLD: ignore and mld_discard frame\n");
    /* the frame will be discared bij the ipv6 module!!! */
    IGNORE_PARAMETER(p);
    return 0;
}

/* finite state machine table */
static const mld_callback mld_state_diagram[3][6] =
{ /* event                    | Stop Listening | Start Listening | Update Group |Query reveive |Report receive |Timer expired */
/* none listener*/
    { mld_discard,    mld_srsfst,         mld_srsfst,  mld_discard,    mld_discard,    mld_discard},
/* idle listener */ { mld_stsdifs,    mld_mrsrrt,         mld_mrsrrt,  mld_rtimrtct,   mld_stcl,       mld_srsf },
/* delaying listener     */ { mld_rtimrtct,    mld_srst,           mld_srst,  mld_srsf,       mld_stsdifs,    mld_discard }
};

static int pico_mld_process_event(struct mcast_parameters *p)
{
    struct pico_tree_node *index = NULL;
    struct mcast_parameters *_p;
#ifdef DEBUG_MLD
    char ipv6[PICO_IPV6_STRING];
    pico_ipv6_to_string(ipv6, p->mcast_group.ip6.addr);
    mld_dbg("MLD: process event on group address %s\n", ipv6);
#endif
    if (p->event == MLD_EVENT_QUERY_RECV && p->general_query) { /* general query */
        pico_tree_foreach(index, &MLDParameters) {
            _p = index->keyValue;
            _p->max_resp_time = p->max_resp_time;
            _p->event = MLD_EVENT_QUERY_RECV;
#ifdef DEBUG_MLD
            mld_dbg("MLD: for each mcast_group = %s | state = %u\n", ipv6, _p->state);
#endif
            return mld_state_diagram[_p->state][_p->event](_p);
        }
    } else {
        mld_dbg("MLD: state = %u (0: non-listener - 1: delaying listener - 2: idle listener) event = %u\n", p->state, p->event);
        return mld_state_diagram[p->state][p->event](p);
    }

    return 0;
}
#else
uint16_t pico_mld_checksum(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return 0;
}
int pico_mld_process_in(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return -1;
}

int pico_mld_state_change(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group, uint8_t filter_mode, struct pico_tree *_MCASTFilter, uint8_t state)
{
    IGNORE_PARAMETER(mcast_link);
    IGNORE_PARAMETER(mcast_group);
    IGNORE_PARAMETER(filter_mode);
    IGNORE_PARAMETER(_MCASTFilter);
    IGNORE_PARAMETER(state);
    return -1;
}
#endif
