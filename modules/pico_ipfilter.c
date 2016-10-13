/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Andrei Carp
         Simon  Maes
 *********************************************************************/

#include "pico_ipv4.h"
#include "pico_config.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_ipfilter.h"
#include "pico_tcp.h"
#include "pico_udp.h"

/**************** LOCAL MACROS ****************/
#define MAX_PRIORITY    (10)
#define MIN_PRIORITY    (-10)

#ifdef DEBUG_IPF
    #define ipf_dbg dbg
#else
    #define ipf_dbg(...) do {} while(0)
#endif

/**************** LOCAL DECLARATIONS ****************/
struct filter_node;


struct filter_node {
    struct pico_device *fdev;
    struct filter_node *next_filter;
    /* output address */
    uint32_t out_addr;
    uint32_t out_addr_netmask;
    /* input address */
    uint32_t in_addr;
    uint32_t in_addr_netmask;
    /* transport */
    uint16_t out_port;
    uint16_t in_port;
    /* filter details */
    uint8_t proto;
    int8_t priority;
    uint8_t tos;
    uint32_t filter_id;
    int (*function_ptr)(struct filter_node *filter, struct pico_frame *f);
};

static struct filter_node *filter_nodes_head = NULL;
static struct filter_node *filter_nodes_tail = NULL;

static inline int ipfilter_uint32_cmp(uint32_t a, uint32_t b)
{
    if (a < b)
        return -1;

    if (b < a)
        return 1;

    return 0;
}

static inline int ipfilter_uint16_cmp(uint16_t a, uint16_t b)
{
    if (a < b)
        return -1;

    if (b < a)
        return 1;

    return 0;
}

static inline int ipfilter_uint8_cmp(uint8_t a, uint8_t b)
{
    if (a < b)
        return -1;

    if (b < a)
        return 1;

    return 0;
}

static inline int ipfilter_ptr_cmp(void *a, void *b)
{
    if (a < b)
        return -1;

    if (b < a)
        return 1;

    return 0;
}

static inline int filter_compare_proto(struct filter_node *a, struct filter_node *b)
{
    return ipfilter_uint8_cmp(a->proto, b->proto);
}

static inline int filter_match_packet_dev(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp;
    /* 1. Compare devices */
    if (rule->fdev) {
        cmp = ipfilter_ptr_cmp(a->fdev, b->fdev);
        if (cmp)
            return cmp;
    }

    return 0;

}

static inline int filter_match_packet_proto(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp;
    /* 2. Compare protocol */
    if (rule->proto) {
        cmp = filter_compare_proto(a, b);
        if (cmp)
            return cmp;
    }

    return 0;

}
static inline int filter_match_packet_addr_in(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp;
    /* 3. Compare addresses order: in, out */
    if (rule->in_addr) {
        cmp = ipfilter_uint32_cmp(a->in_addr & rule->in_addr_netmask, b->in_addr & rule->in_addr_netmask);
        if (cmp)
            return cmp;
    }

    return 0;
}
static inline int filter_match_packet_addr_out(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp;
    if (rule->out_addr) {
        cmp = ipfilter_uint32_cmp(a->out_addr & rule->out_addr_netmask, b->out_addr & rule->out_addr_netmask);
        if (cmp) {
            return cmp;
        }
    }

    return 0;
}
static inline int filter_match_packet_port_in(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp;
    /* 4. Compare ports     order: in, out */
    if (rule->in_port) {
        cmp = ipfilter_uint16_cmp(a->in_port, b->in_port);
        if (cmp)
            return cmp;
    }

    return 0;
}
static inline int filter_match_packet_port_out(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp;
    if (rule->out_port) {
        cmp = ipfilter_uint16_cmp(a->out_port, b->out_port);
        if (cmp)
            return cmp;
    }

    return 0;
}

static inline int filter_match_packet_dev_and_proto(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp = filter_match_packet_dev(a, b, rule);
    if (cmp)
        return cmp;

    return filter_match_packet_proto(a, b, rule);
}

static inline int filter_match_packet_addr(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp = filter_match_packet_addr_in(a, b, rule);
    if (cmp)
        return cmp;

    return filter_match_packet_addr_out(a, b, rule);

}

static inline int filter_match_packet_port(struct filter_node *a, struct filter_node *b, struct filter_node *rule)
{
    int cmp = filter_match_packet_port_in(a, b, rule);
    if (cmp)
        return cmp;

    return filter_match_packet_port_out(a, b, rule);
}

static inline struct filter_node *filter_match_packet_find_rule(struct filter_node *a, struct filter_node *b)
{
    if (!a->filter_id)
        return b;

    return a;
}

static inline int filter_match_packet(struct filter_node *a, struct filter_node *b)
{
    struct filter_node *rule;
    int cmp = 0;
    rule = filter_match_packet_find_rule(a, b);

    cmp = filter_match_packet_dev_and_proto(a, b, rule);
    if (cmp)
        return cmp;

    cmp = filter_match_packet_addr(a, b, rule);
    if (cmp)
        return cmp;

    cmp = filter_match_packet_port(a, b, rule);
    if (cmp)
        return cmp;

    return 0;
}

/**************** FILTER CALLBACKS ****************/

static int fp_priority(struct filter_node *filter, struct pico_frame *f)
{
    /* TODO do priority-stuff */
    IGNORE_PARAMETER(filter);
    IGNORE_PARAMETER(f);
    return 0;
}

static int fp_reject(struct filter_node *filter, struct pico_frame *f)
{
/* TODO check first if sender is pico itself or not */
    IGNORE_PARAMETER(filter);
    ipf_dbg("ipfilter> reject\n");
    (void)pico_icmp4_packet_filtered(f);
    pico_frame_discard(f);
    return 1;
}

static int fp_drop(struct filter_node *filter, struct pico_frame *f)
{
    IGNORE_PARAMETER(filter);
    ipf_dbg("ipfilter> drop\n");
    pico_frame_discard(f);
    return 1;
}

static int fp_allow(struct filter_node *filter, struct pico_frame *f)
{
    IGNORE_PARAMETER(filter);
    IGNORE_PARAMETER(f);
    ipf_dbg("ipfilter> allow\n");
    return 0;
}

struct fp_function {
    int (*fn)(struct filter_node *filter, struct pico_frame *f);
};


static const struct fp_function fp_function[FILTER_COUNT] =
{
    {&fp_priority},
    {&fp_reject},
    {&fp_drop},
    {&fp_allow}
};

static int pico_ipv4_filter_add_validate(int8_t priority, enum filter_action action)
{
    if ( priority > MAX_PRIORITY || priority < MIN_PRIORITY) {
        return -1;
    }

    if (action >= FILTER_COUNT) {
        return -1;
    }

    return 0;
}

static inline struct filter_node * ipfilter_apply_filter(struct filter_node *pkt)
{
    struct filter_node *filter_frame = filter_nodes_head;
    while (filter_frame != NULL) {
        if(filter_match_packet(filter_frame, pkt) == 0){
            ipf_dbg("ipfilter> # ipfilter match\r\n");
            return filter_frame;
        }
        ipf_dbg("ipfilter> # next filter\r\n");
        filter_frame = filter_frame->next_filter;
    }
    return NULL;
}

/**************** FILTER API's ****************/
uint32_t pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto,
                              struct pico_ip4 *out_addr, struct pico_ip4 *out_addr_netmask,
                              struct pico_ip4 *in_addr, struct pico_ip4 *in_addr_netmask,
                              uint16_t out_port, uint16_t in_port, int8_t priority,
                              uint8_t tos, enum filter_action action)
{
    static uint32_t filter_id = 1u; /* 0 is a special value used for packets being processed */
    struct filter_node *new_filter;

    if (pico_ipv4_filter_add_validate(priority, action) < 0) {
        pico_err = PICO_ERR_EINVAL;
        return 0;
    }

    new_filter = PICO_ZALLOC(sizeof(struct filter_node));
    if (!new_filter) {
        pico_err = PICO_ERR_ENOMEM;
        return 0;
    }
    if (!filter_nodes_head){
        filter_nodes_head = filter_nodes_tail = new_filter;
    } else {
        filter_nodes_tail->next_filter = new_filter;
        filter_nodes_tail = new_filter;
    }
    new_filter->fdev = dev;
    new_filter->proto = proto;
    new_filter->out_addr = (!out_addr) ? (0U) : (out_addr->addr);
    new_filter->out_addr_netmask = (!out_addr_netmask) ? (0U) : (out_addr_netmask->addr);
    new_filter->in_addr = (!in_addr) ? (0U) : (in_addr->addr);
    new_filter->in_addr_netmask = (!in_addr_netmask) ? (0U) : (in_addr_netmask->addr);
    new_filter->out_port = out_port;
    new_filter->in_port = in_port;
    new_filter->priority = priority;
    new_filter->tos = tos;
    new_filter->filter_id = filter_id++;
    new_filter->function_ptr = fp_function[action].fn;

    return new_filter->filter_id;
}

int pico_ipv4_filter_del(uint32_t filter_id)
{
    struct filter_node **nodep = &filter_nodes_head;
    struct filter_node *node = filter_nodes_head;

    while (node) {
        if (node->filter_id == filter_id){
            *nodep = node->next_filter;
            pico_free(node);
            return 0;
        }
        nodep = &node->next_filter;
        node = node->next_filter;
    }
    return PICO_ERR_EINVAL;
}

int ipfilter(struct pico_frame *f)
{
    struct filter_node temp;
    struct filter_node *match;
    struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_trans *trans;
    struct pico_icmp4_hdr *icmp_hdr;

    memset(&temp, 0u, sizeof(struct filter_node));

    temp.fdev = f->dev;
    temp.out_addr = ipv4_hdr->dst.addr;
    temp.in_addr = ipv4_hdr->src.addr;
    if ((ipv4_hdr->proto == PICO_PROTO_TCP) || (ipv4_hdr->proto == PICO_PROTO_UDP)) {
        trans = (struct pico_trans *) f->transport_hdr;
        temp.out_port = short_be(trans->dport);
        temp.in_port = short_be(trans->sport);
    }
    else if(ipv4_hdr->proto == PICO_PROTO_ICMP4) {
        icmp_hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
        if(icmp_hdr->type == PICO_ICMP_UNREACH && icmp_hdr->code == PICO_ICMP_UNREACH_FILTER_PROHIB)
            return 0;
    }

    temp.proto = ipv4_hdr->proto;
    temp.priority = f->priority;
    temp.tos = ipv4_hdr->tos;

    match = ipfilter_apply_filter(&temp);
    if(match != NULL) {
        return match->function_ptr(match, f);
    }
    return 0;
}

