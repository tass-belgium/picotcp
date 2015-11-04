/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   RFC 1112, 2236, 3376, 3569, 3678, 4607

   Authors: Kristof Roelants (IGMPv3), Simon Maes, Brecht Van Cauwenberghe
 *********************************************************************/

#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_igmp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_frame.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "pico_socket.h"

#if defined(PICO_SUPPORT_IGMP) && defined(PICO_SUPPORT_MCAST) 

#define igmp_dbg(...) do {} while(0)
/* #define igmp_dbg dbg */

/* membership states */
#define IGMP_STATE_NON_MEMBER             (0x0)
#define IGMP_STATE_DELAYING_MEMBER        (0x1)
#define IGMP_STATE_IDLE_MEMBER            (0x2)

/* events */
#define IGMP_EVENT_DELETE_GROUP           (0x0)
#define IGMP_EVENT_CREATE_GROUP           (0x1)
#define IGMP_EVENT_UPDATE_GROUP           (0x2)
#define IGMP_EVENT_QUERY_RECV             (0x3)
#define IGMP_EVENT_REPORT_RECV            (0x4)
#define IGMP_EVENT_TIMER_EXPIRED          (0x5)

/* message types */
#define IGMP_TYPE_MEM_QUERY               (0x11)
#define IGMP_TYPE_MEM_REPORT_V1           (0x12)
#define IGMP_TYPE_MEM_REPORT_V2           (0x16)
#define IGMP_TYPE_LEAVE_GROUP             (0x17)
#define IGMP_TYPE_MEM_REPORT_V3           (0x22)

/* group record types */
#define IGMP_MODE_IS_INCLUDE              (1)
#define IGMP_MODE_IS_EXCLUDE              (2)
#define IGMP_CHANGE_TO_INCLUDE_MODE       (3)
#define IGMP_CHANGE_TO_EXCLUDE_MODE       (4)
#define IGMP_ALLOW_NEW_SOURCES            (5)
#define IGMP_BLOCK_OLD_SOURCES            (6)

/* host flag */
#define IGMP_HOST_LAST                    (0x1)
#define IGMP_HOST_NOT_LAST                (0x0)

/* list of timers, counters and their default values */
#define IGMP_ROBUSTNESS                   (2u)
#define IGMP_QUERY_INTERVAL               (125) /* secs */
#define IGMP_QUERY_RESPONSE_INTERVAL      (10u) /* secs */
#define IGMP_STARTUP_QUERY_INTERVAL       (IGMPV3_QUERY_INTERVAL / 4)
#define IGMP_STARTUP_QUERY_COUNT          (IGMPV3_ROBUSTNESS)
#define IGMP_LAST_MEMBER_QUERY_INTERVAL   (1) /* secs */
#define IGMP_LAST_MEMBER_QUERY_COUNT      (IGMPV3_ROBUSTNESS)
#define IGMP_UNSOLICITED_REPORT_INTERVAL  (1) /* secs */
#define IGMP_DEFAULT_MAX_RESPONSE_TIME    (100)

/* custom timers types */
#define IGMP_TIMER_GROUP_REPORT           (1)
#define IGMP_TIMER_V1_QUERIER             (2)
#define IGMP_TIMER_V2_QUERIER             (3)

/* IGMP groups */
#define IGMP_ALL_HOST_GROUP               long_be(0xE0000001) /* 224.0.0.1 */
#define IGMP_ALL_ROUTER_GROUP             long_be(0xE0000002) /* 224.0.0.2 */
#define IGMPV3_ALL_ROUTER_GROUP           long_be(0xE0000016) /* 224.0.0.22 */

/* misc */
#define IGMP_TIMER_STOPPED                (1)
#define IP_OPTION_ROUTER_ALERT_LEN        (4u)
#define IGMP_MAX_GROUPS                   (32) /* max 255 */

PACKED_STRUCT_DEF igmp_message {
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t crc;
    uint32_t mcast_group;
};

PACKED_STRUCT_DEF igmpv3_query {
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t crc;
    uint32_t mcast_group;
    uint8_t rsq;
    uint8_t qqic;
    uint16_t sources;
};

PACKED_STRUCT_DEF igmpv3_group_record {
    uint8_t type;
    uint8_t aux;
    uint16_t sources;
    uint32_t mcast_group;
};

PACKED_STRUCT_DEF igmpv3_report {
    uint8_t type;
    uint8_t res0;
    uint16_t crc;
    uint16_t res1;
    uint16_t groups;
};

struct igmp_parameters {
    uint8_t event;
    uint8_t state;
    uint8_t last_host;
    uint8_t filter_mode;
    uint8_t max_resp_time;
    struct pico_ip4 mcast_link;
    struct pico_ip4 mcast_group;
    struct pico_tree *MCASTFilter;
    struct pico_frame *f;
};

struct igmp_timer {
    uint8_t type;
    uint8_t stopped;
    pico_time start;
    pico_time delay;
    struct pico_ip4 mcast_link;
    struct pico_ip4 mcast_group;
    struct pico_frame *f;
    void (*callback)(struct igmp_timer *t);
};

/* queues */
static struct pico_queue igmp_in = {
    0
};
static struct pico_queue igmp_out = {
    0
};

/* finite state machine caller */
static int pico_igmp_process_event(struct igmp_parameters *p);

/* state callback prototype */
typedef int (*callback)(struct igmp_parameters *);

static inline int igmpt_type_compare(struct igmp_timer *a,  struct igmp_timer *b)
{
    if (a->type < b->type)
        return -1;

    if (a->type > b->type)
        return 1;

    return 0;
}


static inline int igmpt_group_compare(struct igmp_timer *a,  struct igmp_timer *b)
{
    return pico_ipv4_compare(&a->mcast_group, &b->mcast_group);
}

static inline int igmpt_link_compare(struct igmp_timer *a,  struct igmp_timer *b)
{
    return pico_ipv4_compare(&a->mcast_link, &b->mcast_link);
}

/* redblack trees */
static int igmp_timer_cmp(void *ka, void *kb)
{
    struct igmp_timer *a = ka, *b = kb;
    int cmp = igmpt_type_compare(a, b);
    if (cmp)
        return cmp;

    cmp = igmpt_group_compare(a, b);
    if (cmp)
        return cmp;

    return igmpt_link_compare(a, b);

}
PICO_TREE_DECLARE(IGMPTimers, igmp_timer_cmp);

static inline int igmpparm_group_compare(struct igmp_parameters *a,  struct igmp_parameters *b)
{
    return pico_ipv4_compare(&a->mcast_group, &b->mcast_group);
}

static inline int igmpparm_link_compare(struct igmp_parameters *a,  struct igmp_parameters *b)
{
    return pico_ipv4_compare(&a->mcast_link, &b->mcast_link);
}

static int igmp_parameters_cmp(void *ka, void *kb)
{
    struct igmp_parameters *a = ka, *b = kb;
    int cmp = igmpparm_group_compare(a, b);
    if (cmp)
        return cmp;

    return igmpparm_link_compare(a, b);
}
PICO_TREE_DECLARE(IGMPParameters, igmp_parameters_cmp);

static int igmp_sources_cmp(void *ka, void *kb)
{
    struct pico_ip4 *a = ka, *b = kb;
    return pico_ipv4_compare(a, b);
}
PICO_TREE_DECLARE(IGMPAllow, igmp_sources_cmp);
PICO_TREE_DECLARE(IGMPBlock, igmp_sources_cmp);

static struct igmp_parameters *pico_igmp_find_parameter(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group)
{
    struct igmp_parameters test = {
        0
    };
    if (!mcast_link || !mcast_group)
        return NULL;

    test.mcast_link.addr = mcast_link->addr;
    test.mcast_group.addr = mcast_group->addr;
    return pico_tree_findKey(&IGMPParameters, &test);
}

static int pico_igmp_delete_parameter(struct igmp_parameters *p)
{
    if (pico_tree_delete(&IGMPParameters, p))
        PICO_FREE(p);
    else
        return -1;

    return 0;
}

static void pico_igmp_timer_expired(pico_time now, void *arg)
{
    struct igmp_timer *t = NULL, *timer = NULL, test = {
        0
    };

    IGNORE_PARAMETER(now);
    t = (struct igmp_timer *)arg;
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    igmp_dbg("IGMP: timer expired for %08X link %08X type %u, delay %lu\n", t->mcast_group.addr, t->mcast_link.addr, t->type, t->delay);
    timer = pico_tree_findKey(&IGMPTimers, &test);
    if (!timer) {
        return;
    }

    if (timer->stopped == IGMP_TIMER_STOPPED) {
        pico_tree_delete(&IGMPTimers, timer);
        PICO_FREE(t);
        return;
    }

    if (timer->start + timer->delay < PICO_TIME_MS()) {
        pico_tree_delete(&IGMPTimers, timer);
        if (timer->callback)
            timer->callback(timer);

        PICO_FREE(timer);
    } else {
        igmp_dbg("IGMP: restart timer for %08X, delay %lu, new delay %lu\n", t->mcast_group.addr, t->delay,  (timer->start + timer->delay) - PICO_TIME_MS());
        pico_timer_add((timer->start + timer->delay) - PICO_TIME_MS(), &pico_igmp_timer_expired, timer);
    }

    return;
}

static int pico_igmp_timer_reset(struct igmp_timer *t)
{
    struct igmp_timer *timer = NULL, test = {
        0
    };

    igmp_dbg("IGMP: reset timer for %08X, delay %lu\n", t->mcast_group.addr, t->delay);
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&IGMPTimers, &test);
    if (!timer)
        return -1;

    *timer = *t;
    timer->start = PICO_TIME_MS();
    return 0;
}

static int pico_igmp_timer_start(struct igmp_timer *t)
{
    struct igmp_timer *timer = NULL, test = {
        0
    };

    igmp_dbg("IGMP: start timer for %08X link %08X type %u, delay %lu\n", t->mcast_group.addr, t->mcast_link.addr, t->type, t->delay);
    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&IGMPTimers, &test);
    if (timer)
        return pico_igmp_timer_reset(t);

    timer = PICO_ZALLOC(sizeof(struct igmp_timer));
    if (!timer) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    *timer = *t;
    timer->start = PICO_TIME_MS();

    pico_tree_insert(&IGMPTimers, timer);
    pico_timer_add(timer->delay, &pico_igmp_timer_expired, timer);
    return 0;
}

static int pico_igmp_timer_stop(struct igmp_timer *t)
{
    struct igmp_timer *timer = NULL, test = {
        0
    };

    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&IGMPTimers, &test);
    if (!timer)
        return -1;

    igmp_dbg("IGMP: stop timer for %08X, delay %lu\n", timer->mcast_group.addr, timer->delay);
    timer->stopped = IGMP_TIMER_STOPPED;
    return 0;
}

static int pico_igmp_timer_is_running(struct igmp_timer *t)
{
    struct igmp_timer *timer = NULL, test = {
        0
    };

    test.type = t->type;
    test.mcast_link = t->mcast_link;
    test.mcast_group = t->mcast_group;
    timer = pico_tree_findKey(&IGMPTimers, &test);
    if (timer)
        return 1;

    return 0;
}

static struct igmp_timer *pico_igmp_find_timer(uint8_t type, struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group)
{
    struct igmp_timer test = {
        0
    };

    test.type = type;
    test.mcast_link = *mcast_link;
    test.mcast_group = *mcast_group;
    return pico_tree_findKey(&IGMPTimers, &test);
}

static void pico_igmp_report_expired(struct igmp_timer *t)
{
    struct igmp_parameters *p = NULL;

    p = pico_igmp_find_parameter(&t->mcast_link, &t->mcast_group);
    if (!p)
        return;

    p->event = IGMP_EVENT_TIMER_EXPIRED;
    pico_igmp_process_event(p);
}

static void pico_igmp_v2querier_expired(struct igmp_timer *t)
{
    struct pico_ipv4_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;

    link = pico_ipv4_link_by_dev(t->f->dev);
    if (!link)
        return;

    /* When changing compatibility mode, cancel all pending response
     * and retransmission timers.
     */
    pico_tree_foreach_safe(index, &IGMPTimers, _tmp)
    {
        ((struct igmp_timer *)index->keyValue)->stopped = IGMP_TIMER_STOPPED;
        pico_tree_delete(&IGMPTimers, index->keyValue);
    }
    igmp_dbg("IGMP: switch to compatibility mode IGMPv3\n");
    link->mcast_compatibility = PICO_IGMPV3;
    return;
}

static int pico_igmp_is_checksum_valid(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = NULL;
    uint8_t ihl = 24, datalen = 0;

    hdr = (struct pico_ipv4_hdr *)f->net_hdr;
    ihl = (uint8_t)((hdr->vhl & 0x0F) * 4); /* IHL is in 32bit words */
    datalen = (uint8_t)(short_be(hdr->len) - ihl);

    if (short_be(pico_checksum(f->transport_hdr, datalen)) == 0)
        return 1;

    igmp_dbg("IGMP: invalid checksum\n");
    return 0;
}

/* RFC 3376 $7.1 */
static int pico_igmp_compatibility_mode(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = NULL;
    struct pico_ipv4_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct igmp_timer t = {
        0
    };
    uint8_t ihl = 24, datalen = 0;

    link = pico_ipv4_link_by_dev(f->dev);
    if (!link)
        return -1;

    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    ihl = (uint8_t)((hdr->vhl & 0x0F) * 4); /* IHL is in 32bit words */
    datalen = (uint8_t)(short_be(hdr->len) - ihl);
    igmp_dbg("IGMP: IHL = %u, LEN = %u, OCTETS = %u\n", ihl, short_be(hdr->len), datalen);

    if (datalen >= 12) {
        /* IGMPv3 query */
        t.type = IGMP_TIMER_V2_QUERIER;
        if (pico_igmp_timer_is_running(&t)) { /* IGMPv2 querier present timer still running */
            igmp_dbg("Timer is already running\n");
            return -1;
        } else {
            link->mcast_compatibility = PICO_IGMPV3;
            igmp_dbg("IGMP Compatibility: v3\n");
            return 0;
        }
    } else if (datalen == 8) {
        struct igmp_message *query = (struct igmp_message *)f->transport_hdr;
        if (query->max_resp_time != 0) {
            /* IGMPv2 query */
            /* When changing compatibility mode, cancel all pending response
             * and retransmission timers.
             */
            pico_tree_foreach_safe(index, &IGMPTimers, _tmp)
            {
                ((struct igmp_timer *)index->keyValue)->stopped = IGMP_TIMER_STOPPED;
                pico_tree_delete(&IGMPTimers, index->keyValue);
            }
            igmp_dbg("IGMP: switch to compatibility mode IGMPv2\n");
            link->mcast_compatibility = PICO_IGMPV2;
            t.type = IGMP_TIMER_V2_QUERIER;
            t.delay = ((IGMP_ROBUSTNESS * link->mcast_last_query_interval) + IGMP_QUERY_RESPONSE_INTERVAL) * 1000;
            t.f = f;
            t.callback = pico_igmp_v2querier_expired;
            /* only one of this type of timer may exist! */
            pico_igmp_timer_start(&t);
        } else {
            /* IGMPv1 query, not supported */
            return -1;
        }
    } else {
        /* invalid query, silently ignored */
        return -1;
    }

    return 0;
}

static struct igmp_parameters *pico_igmp_analyse_packet(struct pico_frame *f)
{
    struct igmp_message *message = NULL;
    struct igmp_parameters *p = NULL;
    struct pico_ipv4_link *link = NULL;
    struct pico_ip4 mcast_group = {
        0
    };

    link = pico_ipv4_link_by_dev(f->dev);
    if (!link)
        return NULL;

    /* IGMPv2 and IGMPv3 have a similar structure for the first 8 bytes */
    message = (struct igmp_message *)f->transport_hdr;
    mcast_group.addr = message->mcast_group;
    p = pico_igmp_find_parameter(&link->address, &mcast_group);
    if (!p && mcast_group.addr == 0) { /* general query */
        p = PICO_ZALLOC(sizeof(struct igmp_parameters));
        if (!p)
            return NULL;

        p->state = IGMP_STATE_NON_MEMBER;
        p->mcast_link.addr = link->address.addr;
        p->mcast_group.addr = mcast_group.addr;
        pico_tree_insert(&IGMPParameters, p);
    } else if (!p) {
        return NULL;
    }

    switch (message->type) {
    case IGMP_TYPE_MEM_QUERY:
        p->event = IGMP_EVENT_QUERY_RECV;
        break;
    case IGMP_TYPE_MEM_REPORT_V1:
        p->event = IGMP_EVENT_REPORT_RECV;
        break;
    case IGMP_TYPE_MEM_REPORT_V2:
        p->event = IGMP_EVENT_REPORT_RECV;
        break;
    case IGMP_TYPE_MEM_REPORT_V3:
        p->event = IGMP_EVENT_REPORT_RECV;
        break;
    default:
        return NULL;
    }
    p->max_resp_time = message->max_resp_time; /* if IGMPv3 report this will be 0 (res0 field) */
    p->f = f;

    return p;
}

static int pico_igmp_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    struct igmp_parameters *p = NULL;
    IGNORE_PARAMETER(self);

    if (!pico_igmp_is_checksum_valid(f))
        goto out;

    if (pico_igmp_compatibility_mode(f) < 0)
        goto out;

    p = pico_igmp_analyse_packet(f);
    if (!p)
        goto out;

    return pico_igmp_process_event(p);

out:
    pico_frame_discard(f);
    return 0;
}

static int pico_igmp_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    /* packets are directly transferred to the IP layer by calling pico_ipv4_frame_push */
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(f);
    return 0;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_igmp = {
    .name = "igmp",
    .proto_number = PICO_PROTO_IGMP,
    .layer = PICO_LAYER_TRANSPORT,
    .process_in = pico_igmp_process_in,
    .process_out = pico_igmp_process_out,
    .q_in = &igmp_in,
    .q_out = &igmp_out,
};

int pico_igmp_state_change(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t filter_mode, struct pico_tree *_MCASTFilter, uint8_t state)
{
    struct igmp_parameters *p = NULL;

    if (mcast_group->addr == IGMP_ALL_HOST_GROUP)
        return 0;

    p = pico_igmp_find_parameter(mcast_link, mcast_group);
    if (!p && state == PICO_IGMP_STATE_CREATE) {
        p = PICO_ZALLOC(sizeof(struct igmp_parameters));
        if (!p) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if (!mcast_link || !mcast_group) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        p->state = IGMP_STATE_NON_MEMBER;
        p->mcast_link = *mcast_link;
        p->mcast_group = *mcast_group;
        pico_tree_insert(&IGMPParameters, p);
    } else if (!p) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (state) {
    case PICO_IGMP_STATE_CREATE:
        p->event = IGMP_EVENT_CREATE_GROUP;
        break;

    case PICO_IGMP_STATE_UPDATE:
        p->event = IGMP_EVENT_UPDATE_GROUP;
        break;

    case PICO_IGMP_STATE_DELETE:
        p->event = IGMP_EVENT_DELETE_GROUP;
        break;

    default:
        return -1;
    }
    p->filter_mode = filter_mode;
    p->MCASTFilter = _MCASTFilter;

    return pico_igmp_process_event(p);
}

static int pico_igmp_send_report(struct igmp_parameters *p, struct pico_frame *f)
{
    struct pico_ip4 dst = {
        0
    };
    struct pico_ip4 mcast_group = {
        0
    };
    struct pico_ipv4_link *link = NULL;

    link = pico_ipv4_link_get(&p->mcast_link);
    if (!link)
        return -1;

    mcast_group.addr = p->mcast_group.addr;
    switch (link->mcast_compatibility) {
    case PICO_IGMPV2:
        if (p->event == IGMP_EVENT_DELETE_GROUP)
            dst.addr = IGMP_ALL_ROUTER_GROUP;
        else
            dst.addr = mcast_group.addr;

        break;

    case PICO_IGMPV3:
        dst.addr = IGMPV3_ALL_ROUTER_GROUP;
        break;

    default:
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;
    }

    igmp_dbg("IGMP: send membership report on group %08X to %08X\n", mcast_group.addr, dst.addr);
    pico_ipv4_frame_push(f, &dst, PICO_PROTO_IGMP);
    return 0;
}

static int8_t pico_igmp_generate_report(struct igmp_parameters *p)
{
    struct pico_ipv4_link *link = NULL;
    int i = 0;

    link = pico_ipv4_link_get(&p->mcast_link);
    if (!link) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (link->mcast_compatibility) {
    case PICO_IGMPV1:
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;

    case PICO_IGMPV2:
    {
        struct igmp_message *report = NULL;
        uint8_t report_type = IGMP_TYPE_MEM_REPORT_V2;
        if (p->event == IGMP_EVENT_DELETE_GROUP)
            report_type = IGMP_TYPE_LEAVE_GROUP;

        p->f = pico_proto_ipv4.alloc(&pico_proto_ipv4, IP_OPTION_ROUTER_ALERT_LEN + sizeof(struct igmp_message));
        p->f->net_len = (uint16_t)(p->f->net_len + IP_OPTION_ROUTER_ALERT_LEN);
        p->f->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
        p->f->transport_len = (uint16_t)(p->f->transport_len - IP_OPTION_ROUTER_ALERT_LEN);
        p->f->dev = pico_ipv4_link_find(&p->mcast_link);
        /* p->f->len is correctly set by alloc */

        report = (struct igmp_message *)p->f->transport_hdr;
        report->type = report_type;
        report->max_resp_time = IGMP_DEFAULT_MAX_RESPONSE_TIME;
        report->mcast_group = p->mcast_group.addr;

        report->crc = 0;
        report->crc = short_be(pico_checksum(report, sizeof(struct igmp_message)));
        break;
    }
    case PICO_IGMPV3:
    {
        struct igmpv3_report *report = NULL;
        struct igmpv3_group_record *record = NULL;
        struct pico_mcast_group *g = NULL, test = {
            0
        };
        struct pico_tree_node *index = NULL, *_tmp = NULL;
        struct pico_tree *IGMPFilter = NULL;
        struct pico_ip4 *source = NULL;
        uint8_t record_type = 0;
        uint8_t sources = 0;
        uint16_t len = 0;

        test.mcast_addr = p->mcast_group;
        g = pico_tree_findKey(link->MCASTGroups, &test);
        if (!g) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        if (p->event == IGMP_EVENT_DELETE_GROUP) { /* "non-existent" state of filter mode INCLUDE and empty source list */
            p->filter_mode = PICO_IP_MULTICAST_INCLUDE;
            p->MCASTFilter = NULL;
        }

        if (p->event == IGMP_EVENT_QUERY_RECV) {
            goto igmp3_report;
        }


        /* cleanup filters */
        pico_tree_foreach_safe(index, &IGMPAllow, _tmp)
        {
            pico_tree_delete(&IGMPAllow, index->keyValue);
        }
        pico_tree_foreach_safe(index, &IGMPBlock, _tmp)
        {
            pico_tree_delete(&IGMPBlock, index->keyValue);
        }

        switch (g->filter_mode) {

        case PICO_IP_MULTICAST_INCLUDE:
            switch (p->filter_mode) {
            case PICO_IP_MULTICAST_INCLUDE:
                if (p->event == IGMP_EVENT_DELETE_GROUP) { /* all ADD_SOURCE_MEMBERSHIP had an equivalent DROP_SOURCE_MEMBERSHIP */
                    /* TO_IN (B) */
                    record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
                    IGMPFilter = &IGMPAllow;
                    if (p->MCASTFilter) {
                        pico_tree_foreach(index, p->MCASTFilter) /* B */
                        {
                            pico_tree_insert(&IGMPAllow, index->keyValue);
                            sources++;
                        }
                    } /* else { IGMPAllow stays empty } */

                    break;
                }

                /* ALLOW (B-A) */
                /* if event is CREATE A will be empty, thus only ALLOW (B-A) has sense */
                if (p->event == IGMP_EVENT_CREATE_GROUP) /* first ADD_SOURCE_MEMBERSHIP */
                    record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
                else
                    record_type = IGMP_ALLOW_NEW_SOURCES;

                IGMPFilter = &IGMPAllow;
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    pico_tree_insert(&IGMPAllow, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, &g->MCASTSources) /* A */
                {
                    source = pico_tree_findKey(&IGMPAllow, index->keyValue);
                    if (source) {
                        pico_tree_delete(&IGMPAllow, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPAllow)) /* record type is ALLOW */
                    break;

                /* BLOCK (A-B) */
                record_type = IGMP_BLOCK_OLD_SOURCES;
                IGMPFilter = &IGMPBlock;
                pico_tree_foreach(index, &g->MCASTSources) /* A */
                {
                    pico_tree_insert(&IGMPBlock, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    source = pico_tree_findKey(&IGMPBlock, index->keyValue);
                    if (source) {
                        pico_tree_delete(&IGMPBlock, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPBlock)) /* record type is BLOCK */
                    break;

                /* ALLOW (B-A) and BLOCK (A-B) are empty: do not send report (RFC 3376 $5.1) */
                p->f = NULL;
                return 0;

            case PICO_IP_MULTICAST_EXCLUDE:
                /* TO_EX (B) */
                record_type = IGMP_CHANGE_TO_EXCLUDE_MODE;
                IGMPFilter = &IGMPBlock;
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    pico_tree_insert(&IGMPBlock, index->keyValue);
                    sources++;
                }
                break;

            default:
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            break;

        case PICO_IP_MULTICAST_EXCLUDE:
            switch (p->filter_mode) {
            case PICO_IP_MULTICAST_INCLUDE:
                /* TO_IN (B) */
                record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
                IGMPFilter = &IGMPAllow;
                if (p->MCASTFilter) {
                    pico_tree_foreach(index, p->MCASTFilter) /* B */
                    {
                        pico_tree_insert(&IGMPAllow, index->keyValue);
                        sources++;
                    }
                } /* else { IGMPAllow stays empty } */

                break;

            case PICO_IP_MULTICAST_EXCLUDE:
                /* BLOCK (B-A) */
                record_type = IGMP_BLOCK_OLD_SOURCES;
                IGMPFilter = &IGMPBlock;
                pico_tree_foreach(index, p->MCASTFilter)
                {
                    pico_tree_insert(&IGMPBlock, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, &g->MCASTSources) /* A */
                {
                    source = pico_tree_findKey(&IGMPBlock, index->keyValue); /* B */
                    if (source) {
                        pico_tree_delete(&IGMPBlock, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPBlock)) /* record type is BLOCK */
                    break;

                /* ALLOW (A-B) */
                record_type = IGMP_ALLOW_NEW_SOURCES;
                IGMPFilter = &IGMPAllow;
                pico_tree_foreach(index, &g->MCASTSources)
                {
                    pico_tree_insert(&IGMPAllow, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    source = pico_tree_findKey(&IGMPAllow, index->keyValue); /* A */
                    if (source) {
                        pico_tree_delete(&IGMPAllow, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPAllow)) /* record type is ALLOW */
                    break;

                /* BLOCK (B-A) and ALLOW (A-B) are empty: do not send report (RFC 3376 $5.1) */
                p->f = NULL;
                return 0;

            default:
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            break;

        default:
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

igmp3_report:
        len = (uint16_t)(sizeof(struct igmpv3_report) + sizeof(struct igmpv3_group_record) + (sources * sizeof(struct pico_ip4)));
        p->f = pico_proto_ipv4.alloc(&pico_proto_ipv4, (uint16_t)(IP_OPTION_ROUTER_ALERT_LEN + len));
        p->f->net_len = (uint16_t)(p->f->net_len + IP_OPTION_ROUTER_ALERT_LEN);
        p->f->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
        p->f->transport_len = (uint16_t)(p->f->transport_len - IP_OPTION_ROUTER_ALERT_LEN);
        p->f->dev = pico_ipv4_link_find(&p->mcast_link);
        /* p->f->len is correctly set by alloc */

        report = (struct igmpv3_report *)p->f->transport_hdr;
        report->type = IGMP_TYPE_MEM_REPORT_V3;
        report->res0 = 0;
        report->crc = 0;
        report->res1 = 0;
        report->groups = short_be(1);

        record = (struct igmpv3_group_record *)(((uint8_t *)report) + sizeof(struct igmpv3_report));
        record->type = record_type;
        record->aux = 0;
        record->sources = short_be(sources);
        record->mcast_group = p->mcast_group.addr;
        if (IGMPFilter && !pico_tree_empty(IGMPFilter)) {
            uint32_t *source_addr = (uint32_t *)((uint8_t *)record + sizeof(struct igmpv3_group_record));
            i = 0;
            pico_tree_foreach(index, IGMPFilter)
            {
                source_addr[i] = ((struct pico_ip4 *)index->keyValue)->addr;
                i++;
            }
        }

        report->crc = short_be(pico_checksum(report, len));
        break;
    }

    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    return 0;
}

/* stop timer, send leave if flag set */
static int stslifs(struct igmp_parameters *p)
{
    struct igmp_timer t = {
        0
    };

    igmp_dbg("IGMP: event = leave group | action = stop timer, send leave if flag set\n");

    t.type = IGMP_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    if (pico_igmp_timer_stop(&t) < 0)
        return -1;

    /* always send leave, even if not last host */
    if (pico_igmp_send_report(p, p->f) < 0)
        return -1;

    pico_igmp_delete_parameter(p);
    igmp_dbg("IGMP: new state = non-member\n");
    return 0;
}

/* send report, set flag, start timer */
static int srsfst(struct igmp_parameters *p)
{
    struct igmp_timer t = {
        0
    };
    struct pico_frame *copy_frame = NULL;

    igmp_dbg("IGMP: event = join group | action = send report, set flag, start timer\n");

    p->last_host = IGMP_HOST_LAST;

    if (pico_igmp_generate_report(p) < 0)
        return -1;

    if (!p->f)
        return 0;

    copy_frame = pico_frame_copy(p->f);
    if (!copy_frame) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    if (pico_igmp_send_report(p, copy_frame) < 0)
        return -1;

    t.type = IGMP_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    t.delay = (pico_rand() % (IGMP_UNSOLICITED_REPORT_INTERVAL * 10000));
    t.f = p->f;
    t.callback = pico_igmp_report_expired;
    pico_igmp_timer_start(&t);

    p->state = IGMP_STATE_DELAYING_MEMBER;
    igmp_dbg("IGMP: new state = delaying member\n");
    return 0;
}

/* merge report, send report, reset timer (IGMPv3 only) */
static int mrsrrt(struct igmp_parameters *p)
{
    struct igmp_timer *t = NULL;
    struct pico_frame *copy_frame = NULL;
    struct pico_ipv4_link *link = NULL;

    igmp_dbg("IGMP: event = update group | action = merge report, send report, reset timer (IGMPv3 only)\n");

    link = pico_ipv4_link_get(&p->mcast_link);
    if (!link)
        return -1;

    if (link->mcast_compatibility != PICO_IGMPV3) {
        igmp_dbg("IGMP: no IGMPv3 compatible router on network\n");
        return -1;
    }

    /* XXX: merge with pending report rfc 3376 $5.1 */

    copy_frame = pico_frame_copy(p->f);
    if (!copy_frame)
        return -1;

    if (pico_igmp_send_report(p, copy_frame) < 0)
        return -1;

    t = pico_igmp_find_timer(IGMP_TIMER_GROUP_REPORT, &p->mcast_link, &p->mcast_group);
    if (!t)
        return -1;

    t->delay = (pico_rand() % (IGMP_UNSOLICITED_REPORT_INTERVAL * 10000));
    pico_igmp_timer_reset(t);

    p->state = IGMP_STATE_DELAYING_MEMBER;
    igmp_dbg("IGMP: new state = delaying member\n");
    return 0;
}

/* send report, start timer (IGMPv3 only) */
static int srst(struct igmp_parameters *p)
{
    struct igmp_timer t = {
        0
    };
    struct pico_frame *copy_frame = NULL;
    struct pico_ipv4_link *link = NULL;

    igmp_dbg("IGMP: event = update group | action = send report, start timer (IGMPv3 only)\n");

    link = pico_ipv4_link_get(&p->mcast_link);
    if (!link)
        return -1;

    if (link->mcast_compatibility != PICO_IGMPV3) {
        igmp_dbg("IGMP: no IGMPv3 compatible router on network\n");
        return -1;
    }

    if (pico_igmp_generate_report(p) < 0)
        return -1;

    if (!p->f)
        return 0;

    copy_frame = pico_frame_copy(p->f);
    if (!copy_frame)
        return -1;

    if (pico_igmp_send_report(p, copy_frame) < 0)
        return -1;

    t.type = IGMP_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    t.delay = (pico_rand() % (IGMP_UNSOLICITED_REPORT_INTERVAL * 10000));
    t.f = p->f;
    t.callback = pico_igmp_report_expired;
    pico_igmp_timer_start(&t);

    p->state = IGMP_STATE_DELAYING_MEMBER;
    igmp_dbg("IGMP: new state = delaying member\n");
    return 0;
}

/* send leave if flag set */
static int slifs(struct igmp_parameters *p)
{
    igmp_dbg("IGMP: event = leave group | action = send leave if flag set\n");

    /* always send leave, even if not last host */
    if (pico_igmp_send_report(p, p->f) < 0)
        return -1;

    pico_igmp_delete_parameter(p);
    igmp_dbg("IGMP: new state = non-member\n");
    return 0;
}

/* start timer */
static int st(struct igmp_parameters *p)
{
    struct igmp_timer t = {
        0
    };

    igmp_dbg("IGMP: event = query received | action = start timer\n");

    if (pico_igmp_generate_report(p) < 0) {
        igmp_dbg("Failed to generate report\n");
        return -1;
    }

    if (!p->f) {
        igmp_dbg("No pending frame\n");
        return -1;
    }

    t.type = IGMP_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    t.delay = (pico_rand() % ((1u + p->max_resp_time) * 100u));
    t.f = p->f;
    t.callback = pico_igmp_report_expired;
    pico_igmp_timer_start(&t);

    p->state = IGMP_STATE_DELAYING_MEMBER;
    igmp_dbg("IGMP: new state = delaying member\n");
    return 0;
}

/* stop timer, clear flag */
static int stcl(struct igmp_parameters *p)
{
    struct igmp_timer t = {
        0
    };

    igmp_dbg("IGMP: event = report received | action = stop timer, clear flag\n");

    t.type = IGMP_TIMER_GROUP_REPORT;
    t.mcast_link = p->mcast_link;
    t.mcast_group = p->mcast_group;
    if (pico_igmp_timer_stop(&t) < 0)
        return -1;

    p->last_host = IGMP_HOST_NOT_LAST;
    p->state = IGMP_STATE_IDLE_MEMBER;
    igmp_dbg("IGMP: new state = idle member\n");
    return 0;
}

/* send report, set flag */
static int srsf(struct igmp_parameters *p)
{
    igmp_dbg("IGMP: event = timer expired | action = send report, set flag\n");

    if (pico_igmp_send_report(p, p->f) < 0)
        return -1;

    p->state = IGMP_STATE_IDLE_MEMBER;
    igmp_dbg("IGMP: new state = idle member\n");
    return 0;
}

/* reset timer if max response time < current timer */
static int rtimrtct(struct igmp_parameters *p)
{
    struct igmp_timer *t = NULL;
    uint32_t time_to_run = 0;

    igmp_dbg("IGMP: event = query received | action = reset timer if max response time < current timer\n");

    t = pico_igmp_find_timer(IGMP_TIMER_GROUP_REPORT, &p->mcast_link, &p->mcast_group);
    if (!t)
        return -1;

    time_to_run = (uint32_t)(t->start + t->delay - PICO_TIME_MS());
    if ((p->max_resp_time * 100u) < time_to_run) { /* max_resp_time in units of 1/10 seconds */
        t->delay = pico_rand() % ((1u + p->max_resp_time) * 100u);
        pico_igmp_timer_reset(t);
    }

    p->state = IGMP_STATE_DELAYING_MEMBER;
    igmp_dbg("IGMP: new state = delaying member\n");
    return 0;
}

static int discard(struct igmp_parameters *p)
{
    igmp_dbg("IGMP: ignore and discard frame\n");
    pico_frame_discard(p->f);
    return 0;
}

/* finite state machine table */
const callback host_membership_diagram_table[3][6] =
{ /* event                    |Delete Group  |Create Group |Update Group |Query Received  |Report Received  |Timer Expired */
/* state Non-Member      */
    { discard,       srsfst,       srsfst,       discard,         discard,          discard },
/* state Delaying Member */ { stslifs,       mrsrrt,       mrsrrt,       rtimrtct,        stcl,             srsf    },
/* state Idle Member     */ { slifs,         srst,         srst,         st,              discard,          discard }
};

static int pico_igmp_process_event(struct igmp_parameters *p)
{
    struct pico_tree_node *index = NULL;
    struct igmp_parameters *_p = NULL;

    igmp_dbg("IGMP: process event on group address %08X\n", p->mcast_group.addr);
    if (p->event == IGMP_EVENT_QUERY_RECV && p->mcast_group.addr == 0) { /* general query */
        pico_tree_foreach(index, &IGMPParameters) {
            _p = index->keyValue;
            _p->max_resp_time = p->max_resp_time;
            _p->event = IGMP_EVENT_QUERY_RECV;
            igmp_dbg("IGMP: for each mcast_group = %08X | state = %u\n", _p->mcast_group.addr, _p->state);
            host_membership_diagram_table[_p->state][_p->event](_p);
        }
    } else {
        igmp_dbg("IGMP: state = %u (0: non-member - 1: delaying member - 2: idle member)\n", p->state);
        host_membership_diagram_table[p->state][p->event](p);
    }

    return 0;
}

#else
static struct pico_queue igmp_in = {
    0
};
static struct pico_queue igmp_out = {
    0
};

static int pico_igmp_process_in(struct pico_protocol *self, struct pico_frame *f) {
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(f);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

static int pico_igmp_process_out(struct pico_protocol *self, struct pico_frame *f) {
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(f);
    return -1;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_igmp = {
    .name = "igmp",
    .proto_number = PICO_PROTO_IGMP,
    .layer = PICO_LAYER_TRANSPORT,
    .process_in = pico_igmp_process_in,
    .process_out = pico_igmp_process_out,
    .q_in = &igmp_in,
    .q_out = &igmp_out,
};

int pico_igmp_state_change(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t filter_mode, struct pico_tree *_MCASTFilter, uint8_t state) {
    IGNORE_PARAMETER(mcast_link);
    IGNORE_PARAMETER(mcast_group);
    IGNORE_PARAMETER(filter_mode);
    IGNORE_PARAMETER(_MCASTFilter);
    IGNORE_PARAMETER(state);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}
#endif
