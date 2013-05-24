/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
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
#include "/home/kristof/documents/utilities/hexdump/hexdump.c"

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
#define IGMP_ROBUSTNESS                   (2)
#define IGMP_QUERY_INTERVAL               (125) /* secs */
#define IGMP_QUERY_RESPONSE_INTERVAL      (10) /* secs */
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
#define TIMER_NOT_ACTIVE                  (0)
#define IP_OPTION_ROUTER_ALERT_LEN        (4)
#define IGMP_MAX_GROUPS                   (32) /* max 255 */

struct __attribute__((packed)) igmp_message {
  uint8_t type;
  uint8_t max_resp_time;
  uint16_t crc;
  uint32_t mcast_group;
};

struct __attribute__((packed)) igmpv3_query {
  uint8_t type;
  uint8_t max_resp_time;
  uint16_t crc;
  uint32_t mcast_group;
  uint8_t rsq;
  uint8_t qqic;
  uint16_t sources;
  uint32_t source_addr[0];
};

struct __attribute__((packed)) igmpv3_group_record {
  uint8_t type;
  uint8_t aux;
  uint16_t sources;
  uint32_t mcast_group;
  uint32_t source_addr[0];
};

struct __attribute__((packed)) igmpv3_report {
  uint8_t type;
  uint8_t res0;
  uint16_t crc;
  uint16_t res1;
  uint16_t groups;
  struct igmpv3_group_record record[0];
};

struct igmp_parameters {
  uint8_t event;
  uint8_t state;
  uint8_t last_host;
  uint8_t filter_mode;
  uint8_t max_resp_time;
  uint8_t mcast_compatibility;
  uint16_t delay;
  unsigned long timer_start;
  struct pico_ip4 mcast_link;
  struct pico_ip4 mcast_group;
  struct pico_tree *MCASTFilter;
  struct pico_frame *f;
};

/* XXX: to be replaced */
struct timer_callback_info {
  unsigned long timer_start;
  struct pico_frame *f;
};

struct igmp_timer {
  uint8_t type;
  unsigned long start;
  unsigned long delay;
  struct pico_ip4 mcast_group;
  struct pico_frame *f;
  void (*callback)(struct igmp_timer *t);
};

static int igmp_timer_cmp(void *ka, void *kb)
{
  struct igmp_timer *a = ka, *b =kb;
  if (a->type < b->type)
    return -1;
  if (a->type > b->type)
    return 1;
  if (a->mcast_group.addr < b->mcast_group.addr)
    return -1;
  if (a->mcast_group.addr > b->mcast_group.addr)
    return 1;
  return 0;
}
PICO_TREE_DECLARE(IGMPTimers, igmp_timer_cmp);

static int igmp_parameters_cmp(void *ka, void *kb)
{
  struct igmp_parameters *a = ka, *b = kb;
  if (a->mcast_group.addr < b->mcast_group.addr)
    return -1;
  if (a->mcast_group.addr > b->mcast_group.addr)
    return 1;
  return 0;
}
PICO_TREE_DECLARE(IGMPParameters, igmp_parameters_cmp);

static int igmp_sources_cmp(void *ka, void *kb)
{
  struct pico_ip4 *a = ka, *b = kb;
  if (a->addr < b->addr)
    return -1;
  if (a->addr > b->addr)
    return 1;
  return 0;
}
PICO_TREE_DECLARE(IGMPAllow, igmp_sources_cmp);
PICO_TREE_DECLARE(IGMPBlock, igmp_sources_cmp);

static struct igmp_parameters *pico_igmp_find_parameters(struct pico_ip4 *mcast_group)
{
  struct igmp_parameters test = {0};
  test.mcast_group.addr = mcast_group->addr;
  return pico_tree_findKey(&IGMPParameters,&test);
}

static int pico_igmp_delete_parameters(struct igmp_parameters *info)
{
  if(!info){
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  else {
    if(pico_tree_delete(&IGMPParameters, info)) {
      pico_free(info);
    } else {
      pico_err = PICO_ERR_EEXIST;
      return -1; /* do not free, error on removing element from tree */
    }
  }
  return 0;
}

static int pico_igmp_process_event(struct igmp_parameters *params);
static void generate_event_timer_expired(long unsigned int empty, void *info);

#ifdef PICO_UNIT_TEST_IGMP
#define igmp_dbg dbg
static int pico_igmp_process_event(struct igmp_parameters *params);
static int pico_igmp_analyse_packet(struct pico_frame *f, struct igmp_parameters *params);
static int pico_igmp_process_in(struct pico_protocol *self, struct pico_frame *f);

int test_pico_igmp_process_in(struct pico_protocol *self, struct pico_frame *f){
  pico_igmp_process_in(self, f);
  return 0;
}
int test_pico_igmp_set_membershipState(struct pico_ip4 *mcast_group ,uint8_t state){
  struct igmp_parameters *info = pico_igmp_find_parameters(mcast_group);
  info->state = state;
  igmp_dbg("DEBUG_IGMP:STATE = %s\n", (info->state == 0 ? "Non-Member" : (info->state == 1 ? "Delaying MEMBER" : "Idle MEMBER"))); 
  return 0;
}
uint8_t test_pico_igmp_get_membershipState(struct pico_ip4 *mcast_group){
  struct igmp_parameters *info = pico_igmp_find_parameters(mcast_group);
  igmp_dbg("DEBUG_IGMP:STATE = %s\n", (info->state == 0 ? "Non-Member" : (info->state == 1 ? "Delaying Member" : "Idle Member"))); 
  return info->state;
}
int test_pico_igmp_process_event(struct igmp_parameters *params) {
   pico_igmp_process_event(params);
   return 0;
}

int test_pico_igmp_analyse_packet(struct pico_frame *f, struct igmp_parameters *params){
  pico_igmp_analyse_packet(f, params);
  return 0;
}
#else
//#define igmp_dbg(...) do{}while(0)
#define igmp_dbg dbg
#endif

/* queues */
static struct pico_queue igmp_in = {};
static struct pico_queue igmp_out = {};

static int pico_igmp_analyse_packet(struct pico_frame *f, struct igmp_parameters *params)
{
  /* IGMPv2 and IGMPv3 have a similar structure for the first 8 bytes */ 
  struct igmp_message *message = (struct igmp_message *)f->transport_hdr;
  switch (message->type) {
    case IGMP_TYPE_MEM_QUERY:
       params->event = IGMP_EVENT_QUERY_RECV;
       break;
    case IGMP_TYPE_MEM_REPORT_V1:
       params->event = IGMP_EVENT_REPORT_RECV;
       break;
    case IGMP_TYPE_MEM_REPORT_V2:
       params->event = IGMP_EVENT_REPORT_RECV;
       break;
    case IGMP_TYPE_MEM_REPORT_V3:
       params->event = IGMP_EVENT_REPORT_RECV;
       break;
    default:
       pico_frame_discard(f);
       pico_err = PICO_ERR_EINVAL;
       return -1;
  }
  params->mcast_group.addr = message->mcast_group;
  params->max_resp_time = message->max_resp_time; /* if IGMPv3 this will be 0 */
  params->f = f;

  return 0;
}

/* XXX: to be replaced */
static int pico_igmp_checksum(struct igmp_parameters *params)
{
  struct igmp_message *igmp_hdr = (struct igmp_message *) params->f->transport_hdr;
  if (!igmp_hdr) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  igmp_hdr->crc = 0;
  igmp_hdr->crc = short_be(pico_checksum(igmp_hdr, sizeof(struct igmp_message)));
  return 0;
}

static void igmp_timer_expired(unsigned long now, void *arg)
{
  struct igmp_timer *t = NULL, *timer = NULL, test = {0};

  t = (struct igmp_timer *)arg;
  test.type = t->type;
  test.mcast_group = t->mcast_group;
  timer = pico_tree_findKey(&IGMPTimers, &test);
  if (!timer) { /* timer has been stopped */
    pico_free(t);
    return;
  }
  
  if (timer->start + timer->delay < PICO_TIME_MS()) {
    pico_tree_delete(&IGMPTimers, timer);
    if (timer->callback)
      timer->callback(timer);
    pico_free(timer);
  } else {
    pico_timer_add((timer->start + timer->delay) - PICO_TIME_MS(), &igmp_timer_expired, timer);
  }
  return;
}

static int igmp_timer_reset(struct igmp_timer *t)
{
  struct igmp_timer *timer = NULL, test = {0};

  test.type = t->type;
  test.mcast_group = t->mcast_group;
  timer = pico_tree_findKey(&IGMPTimers, &test);
  if (!timer)
    return -1;

  *timer = *t;
  timer->start = PICO_TIME_MS();
  return 0;
}

static int igmp_timer_start(struct igmp_timer *t)
{
  struct igmp_timer *timer = NULL, test = {0};

  test.type = t->type;
  test.mcast_group = t->mcast_group;
  timer = pico_tree_findKey(&IGMPTimers, &test);
  if (timer)
    return igmp_timer_reset(t);

  timer = pico_zalloc(sizeof(struct igmp_timer));
  if (!timer) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  *timer = *t;
  timer->start = PICO_TIME_MS();

  pico_tree_insert(&IGMPTimers, timer);
  pico_timer_add(timer->delay, &igmp_timer_expired, timer);
  return 0;
}

static int igmp_timer_stop(struct igmp_timer *t)
{
  struct igmp_timer *timer = NULL, test = {0};

  test.type = t->type;
  test.mcast_group = t->mcast_group;
  timer = pico_tree_findKey(&IGMPTimers, &test);
  if (!timer)
    return 0;

  /* if timer expires and the timer is not found in IGMPTimers, 
   * he has been stopped and frees the allocated timer memory.
   */
  pico_tree_delete(&IGMPTimers, timer);
  return 0;
}

static int igmp_timer_is_running(struct igmp_timer *t)
{
  struct igmp_timer *timer = NULL, test = {0};

  test.type = t->type;
  test.mcast_group = t->mcast_group;
  timer = pico_tree_findKey(&IGMPTimers, &test);
  if (timer)
    return 1;
  return 0;
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
    pico_tree_delete(&IGMPTimers, index->keyValue);
  }
  link->mcast_compatibility = PICO_IGMPV3;
  return;
}

/* RFC 3376 $7.1 */
static int pico_igmp_compatibility_mode(struct pico_frame *f)
{
  struct pico_ipv4_hdr *hdr = NULL;
  struct pico_ipv4_link *link = NULL;
  struct igmp_timer t = {0};
  uint8_t ihl = 24, datalen = 0;

  link = pico_ipv4_link_by_dev(f->dev);
  if (!link)
    return -1;

  hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  ihl = (hdr->vhl & 0x0F) * 4; /* IHL is in 32bit words */
  datalen = short_be(hdr->len) - ihl;
  printf(">>>>>>>>>>>>>>>>> IHL = %u, LEN = %u, LEN - IHL = %u\n", ihl, short_be(hdr->len), datalen);
  if (datalen > 12) {
    /* IGMPv3 query */
    t.type = IGMP_TIMER_V2_QUERIER;
    if (igmp_timer_is_running(&t)) { /* IGMPv2 querier present timer still running */
      pico_frame_discard(f);
      return -1;
    } else {
      link->mcast_compatibility = PICO_IGMPV3;
      return 0;
    }
  } else if (datalen == 8) {
    struct igmp_message *query = (struct igmp_message *)f->transport_hdr;
    if (query->max_resp_time != 0) {
      /* IGMPv2 query */
      link->mcast_compatibility = PICO_IGMPV2;
      t.type = IGMP_TIMER_V2_QUERIER;
      t.delay = ((IGMP_ROBUSTNESS * link->mcast_last_query_interval) + IGMP_QUERY_RESPONSE_INTERVAL) * 1000;
      t.f = f;
      t.callback = pico_igmp_v2querier_expired;
      igmp_timer_start(&t);
    } else {
      /* IGMPv1 query, not supported */
      pico_frame_discard(f);
      return -1;
    }
  } else {
    /* invalid query, silently ignored */
    pico_frame_discard(f);
    return -1;
  }
  return 0;
}

static int pico_igmp_is_checksum_valid(struct pico_frame *f)
{
  struct pico_ipv4_hdr *hdr = NULL;
  uint8_t ihl = 24, datalen = 0;

  hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  ihl = (hdr->vhl & 0x0F) * 4; /* IHL is in 32bit words */
  datalen = short_be(hdr->len) - ihl;

  if (short_be(pico_checksum(f->transport_hdr, datalen)) == 0)
    return 1;
  return 0;
}

static int pico_igmp_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct igmp_parameters params;
 
  if (!pico_igmp_is_checksum_valid(f)) {
    igmp_dbg("IGMP: invalid checksum\n");
    pico_frame_discard(f);
    return 0;
  }
    
  if (pico_igmp_compatibility_mode(f) < 0)
    return 0;

  if (pico_igmp_analyse_packet(f, &params) < 0)
    return 0;

  return pico_igmp_process_event(&params);
}

static int pico_igmp_process_out(struct pico_protocol *self, struct pico_frame *f) {
  /* packets are directly transferred to the IP layer by calling pico_ipv4_frame_push */
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

int pico_igmp_state_change(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t filter_mode, struct pico_tree *MCASTFilter, uint8_t state) 
{
  struct igmp_parameters *rbtparams = NULL, params = {0};
  
  if (mcast_group->addr == IGMP_ALL_HOST_GROUP)
    return 0;

  switch (state) {
    case PICO_IGMP_STATE_CREATE:
      params.event = IGMP_EVENT_CREATE_GROUP;
      break;

    case PICO_IGMP_STATE_UPDATE:
      params.event = IGMP_EVENT_UPDATE_GROUP;
      break;
    
    case PICO_IGMP_STATE_DELETE:
      params.event = IGMP_EVENT_DELETE_GROUP;
      break;

    default:
      return -1;
  }

  params.mcast_compatibility = PICO_IGMPV3; /* default RFC 3376 $7.2.1 */
  params.mcast_group = *mcast_group;
  params.mcast_link = *mcast_link;
  params.filter_mode = filter_mode;
  params.MCASTFilter = MCASTFilter;

  rbtparams = pico_igmp_find_parameters(mcast_group);
  if (rbtparams) {
    rbtparams->event = params.event;
    rbtparams->mcast_link = params.mcast_link;
    rbtparams->filter_mode = params.filter_mode;
    rbtparams->MCASTFilter = params.MCASTFilter;
  }

  return pico_igmp_process_event(&params);
}

/* XXX: to be replaced */
static int start_timer(struct igmp_parameters *params,const uint16_t delay)
{
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));
  struct timer_callback_info *timer_info= pico_zalloc(sizeof(struct timer_callback_info));

  timer_info->timer_start = PICO_TIME_MS();
  timer_info->f = params->f;
  info->delay = delay;
  info->timer_start = timer_info->timer_start;
  pico_timer_add(delay, &generate_event_timer_expired, timer_info);
  return 0;
}

/* XXX: to be replaced */
static int stop_timer(struct pico_ip4 *mcast_group)
{
  struct igmp_parameters *info = pico_igmp_find_parameters(mcast_group);
  if (!info)
    return -1;
  info->timer_start = TIMER_NOT_ACTIVE;
  return 0;
}

/* XXX: to be replaced */
static int reset_timer(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  uint16_t delay = pico_rand() % (params->max_resp_time*100); 

  ret |= stop_timer(&(params->mcast_group));
  ret |= start_timer(params, delay);
  return ret;
}

static int send_membership_report(struct igmp_parameters *params, struct pico_frame *f)
{
  struct pico_ip4 dst = {0};
  struct pico_ip4 mcast_group = {0};

  mcast_group.addr = params->mcast_group.addr;
  switch (params->mcast_compatibility) {
    case PICO_IGMPV2:
    {
      if (params->event == IGMP_EVENT_DELETE_GROUP)
        dst.addr = IGMP_ALL_ROUTER_GROUP;
      else
        dst.addr = mcast_group.addr;
      break;
    }

    case PICO_IGMPV3:
      dst.addr = IGMPV3_ALL_ROUTER_GROUP;
      break;

    default:
      pico_err = PICO_ERR_EPROTONOSUPPORT;
      return -1;
  }

  igmp_dbg("IGMP: send membership report on group %08X to %08X\n", mcast_group.addr, dst.addr);
  pico_ipv4_frame_push(f, &dst, PICO_PROTO_IGMP);
  stop_timer(&mcast_group);
  return 0;
}

static int generate_igmp_report(struct igmp_parameters *params)
{
  struct pico_ipv4_link *link = NULL;
  int i = 0;

  link = pico_ipv4_link_get(&params->mcast_link);
  if (!link) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  params->mcast_compatibility = link->mcast_compatibility;

  switch (params->mcast_compatibility) {
    case PICO_IGMPV1:
      pico_err = PICO_ERR_EPROTONOSUPPORT;
      return -1;
      
    case PICO_IGMPV2:
    {
      struct igmp_message *report = NULL;
      uint8_t report_type = IGMP_TYPE_MEM_REPORT_V2;
      if (params->event == IGMP_EVENT_DELETE_GROUP)
        report_type = IGMP_TYPE_LEAVE_GROUP;

      params->f = pico_proto_ipv4.alloc(&pico_proto_ipv4, IP_OPTION_ROUTER_ALERT_LEN + sizeof(struct igmp_message));
      params->f->net_len += IP_OPTION_ROUTER_ALERT_LEN;
      params->f->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
      params->f->transport_len -= IP_OPTION_ROUTER_ALERT_LEN;
      params->f->dev = pico_ipv4_link_find(&params->mcast_link);
      /* params->f->len is correctly set by alloc */

      report = (struct igmp_message *)params->f->transport_hdr;
      report->type = report_type;
      report->max_resp_time = IGMP_DEFAULT_MAX_RESPONSE_TIME;
      report->mcast_group = params->mcast_group.addr;

      pico_igmp_checksum(params);
      break;
    }
    case PICO_IGMPV3:
    {
      struct igmpv3_report *report = NULL;
      struct igmpv3_group_record *record = NULL;
      struct pico_mcast_group *g = NULL, test = {0};
      struct pico_tree_node *index = NULL, *_tmp = NULL;
      struct pico_tree *IGMPFilter = NULL;
      struct pico_ip4 *source = NULL;
      uint8_t record_type = 0;
      uint8_t sources = 0;
      int len = 0;

      test.mcast_addr = params->mcast_group;
      g = pico_tree_findKey(link->MCASTGroups, &test);
      if (!g) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
      }

      if (params->event == IGMP_EVENT_DELETE_GROUP) { /* "non-existent" state of filter mode INCLUDE and empty source list */
        params->filter_mode = PICO_IP_MULTICAST_INCLUDE;
        params->MCASTFilter = NULL;
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
          switch (params->filter_mode) {
            case PICO_IP_MULTICAST_INCLUDE:
              if (params->event == IGMP_EVENT_DELETE_GROUP) { /* all ADD_SOURCE_MEMBERSHIP had an equivalent DROP_SOURCE_MEMBERSHIP */
                /* TO_IN (B) */
                record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
                IGMPFilter = &IGMPAllow;
                if (params->MCASTFilter) {
                  pico_tree_foreach(index, params->MCASTFilter) /* B */
                  {
                    pico_tree_insert(&IGMPAllow, index->keyValue);
                    sources++;
                  }
                } /* else { IGMPAllow stays empty } */
                break;
              }

              /* ALLOW (B-A) */
              /* if event is CREATE A will be empty, thus only ALLOW (B-A) has sense */
              if (params->event == IGMP_EVENT_CREATE_GROUP) /* first ADD_SOURCE_MEMBERSHIP */
                record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
              else
                record_type = IGMP_ALLOW_NEW_SOURCES;
              IGMPFilter = &IGMPAllow;
              pico_tree_foreach(index, params->MCASTFilter) /* B */
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
              pico_tree_foreach(index, params->MCASTFilter) /* B */
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
              params->f = NULL;
              return 0;

            case PICO_IP_MULTICAST_EXCLUDE:
              /* TO_EX (B) */
              record_type = IGMP_CHANGE_TO_EXCLUDE_MODE;
              IGMPFilter = &IGMPBlock;
              pico_tree_foreach(index, params->MCASTFilter) /* B */
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
          switch (params->filter_mode) {
            case PICO_IP_MULTICAST_INCLUDE:
              /* TO_IN (B) */
              record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
              IGMPFilter = &IGMPAllow;
              if (params->MCASTFilter) {
                pico_tree_foreach(index, params->MCASTFilter) /* B */
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
              pico_tree_foreach(index, params->MCASTFilter)
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
              pico_tree_foreach(index, params->MCASTFilter) /* B */
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
              params->f = NULL;
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

      len = sizeof(struct igmpv3_report) + sizeof(struct igmpv3_group_record) + (sources * sizeof(struct pico_ip4));
      params->f = pico_proto_ipv4.alloc(&pico_proto_ipv4, IP_OPTION_ROUTER_ALERT_LEN + len);
      params->f->net_len += IP_OPTION_ROUTER_ALERT_LEN;
      params->f->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
      params->f->transport_len -= IP_OPTION_ROUTER_ALERT_LEN;
      params->f->dev = pico_ipv4_link_find(&params->mcast_link);
      /* params->f->len is correctly set by alloc */

      report = (struct igmpv3_report *)params->f->transport_hdr;
      report->type = IGMP_TYPE_MEM_REPORT_V3;
      report->res0 = 0;
      report->crc = 0;
      report->res1 = 0;
      report->groups = short_be(1);

      record = &report->record[0];
      record->type = record_type;
      record->aux = 0;
      record->sources = short_be(sources);
      record->mcast_group = params->mcast_group.addr;
      if (!pico_tree_empty(IGMPFilter)) {
        i = 0;
        pico_tree_foreach(index, IGMPFilter)
        {
          record->source_addr[i] = ((struct pico_ip4 *)index->keyValue)->addr;
          i++;
        }
      }
      report->crc = short_be(pico_checksum(report, len));

      hexdump("IGMPv3 report", report, len);
      break;
    }

    default:
      pico_err = PICO_ERR_EINVAL;
      return -1;
  }
  return 0;
}

/* XXX TO BE DELETED */
static int create_igmp_frame(struct igmp_parameters *params, struct pico_frame **f, struct pico_ip4 src, struct pico_ip4 *mcast_group, uint8_t type)
{
  uint8_t ret = 0;
  struct igmp_message *igmp_hdr = NULL;

  *f = pico_proto_ipv4.alloc(&pico_proto_ipv4, IP_OPTION_ROUTER_ALERT_LEN + sizeof(struct igmp_message));
  (*f)->net_len += IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->transport_len -= IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->len += IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->dev = pico_ipv4_link_find(&src);

  igmp_hdr = (struct igmp_message *) (*f)->transport_hdr;
  igmp_hdr->type = type;
  igmp_hdr->max_resp_time = IGMP_DEFAULT_MAX_RESPONSE_TIME;
  igmp_hdr->mcast_group = mcast_group->addr;

  ret |= pico_igmp_checksum(params);
  return ret;
}

static void generate_event_timer_expired(long unsigned int empty, void *data)
{
  struct timer_callback_info *info = (struct timer_callback_info *) data;
  struct igmp_parameters params = {0};
  struct pico_frame* f = (struct pico_frame*)info->f;
  struct igmp_message *igmp_hdr = (struct igmp_message *) f->transport_hdr;

  params.event = IGMP_EVENT_TIMER_EXPIRED;
  params.mcast_group.addr = igmp_hdr->mcast_group;
  params.timer_start = info->timer_start;
  params.f = info->f;

  pico_igmp_process_event(&params);
  pico_free(info);  
}

/* state callback prototypes */
typedef int (*callback)(struct igmp_parameters *);

/* stop timer, send leave if flag set */
static int stslifs(struct igmp_parameters *params)
{
  struct igmp_parameters *rbtparams = NULL;

  igmp_dbg("IGMP: event = leave group | action = stop timer, send leave if flag set\n");

  rbtparams = pico_igmp_find_parameters(&(params->mcast_group));
  if (!rbtparams)
    return -1;

  if (stop_timer(&(rbtparams->mcast_group)) < 0)
    return -1;

  /* always send leave, even if not last host */
  if (generate_igmp_report(rbtparams) < 0)
    return -1;
  if (!rbtparams->f)
    return 0;
  if (send_membership_report(rbtparams, rbtparams->f) < 0)
    return -1;

  /* delete from tree */
  pico_igmp_delete_parameters(rbtparams);
  igmp_dbg("IGMP: new state = non-member\n");
  return 0;
}

/* send report, set flag, start timer */
static int srsfst(struct igmp_parameters *params)
{
  struct igmp_parameters *rbtparams = NULL;
  struct pico_frame *copy_frame = NULL;

  igmp_dbg("IGMP: event = join group | action = send report, set flag, start timer\n");

  rbtparams = pico_zalloc(sizeof(struct igmp_parameters));
  if (!rbtparams) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  memcpy(rbtparams, params, sizeof(struct igmp_parameters));
  rbtparams->state = IGMP_STATE_NON_MEMBER;
  rbtparams->last_host = IGMP_HOST_LAST;
  rbtparams->timer_start = TIMER_NOT_ACTIVE;
  pico_tree_insert(&IGMPParameters, rbtparams);

  if (generate_igmp_report(rbtparams) < 0)
    return -1;
  if (!rbtparams->f)
    return 0;
  copy_frame = pico_frame_copy(rbtparams->f);
  if (!copy_frame) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  if (send_membership_report(rbtparams, copy_frame) < 0)
    return -1;

  rbtparams->delay = (pico_rand() % (IGMP_UNSOLICITED_REPORT_INTERVAL * 10000)); 
  if (start_timer(rbtparams, rbtparams->delay) < 0) /* XXX: change to one parameter? */
    return -1;
  rbtparams->state = IGMP_STATE_DELAYING_MEMBER;
  igmp_dbg("IGMP: new state = delaying member\n");
  return 0;
}

/* merge report, send report, reset timer (IGMPv3 only) */
static int mrsrrt(struct igmp_parameters *params)
{
  struct igmp_parameters *rbtparams = NULL;
  struct pico_frame *copy_frame = NULL;

  igmp_dbg("IGMP: event = update group | action = merge report, send report, reset timer (IGMPv3 only)\n");

  rbtparams = pico_igmp_find_parameters(&(params->mcast_group));
  if (!rbtparams)
    return -1;

  if (rbtparams->mcast_compatibility != PICO_IGMPV3) {
    igmp_dbg("IGMP: no IGMPv3 compatible router on network\n");
    pico_err = PICO_ERR_ENOPROTOOPT;
    return -1;
  }

  /* XXX: merge with pending report rfc 3376 p20 */

  if (generate_igmp_report(rbtparams) < 0)
    return -1;
  if (!rbtparams->f)
    return 0;
  copy_frame = pico_frame_copy(rbtparams->f);
  if (!copy_frame) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  if (send_membership_report(rbtparams, copy_frame) < 0)
    return -1;

  /* XXX: reset timer */

  rbtparams->state = IGMP_STATE_DELAYING_MEMBER;
  igmp_dbg("IGMP: new state = delaying member\n");
  return 0;
}

/* send report, start timer (IGMPv3 only) */
static int srst(struct igmp_parameters *params)
{
  struct igmp_parameters *rbtparams = NULL;
  struct pico_frame *copy_frame = NULL;

  igmp_dbg("IGMP: event = update group | action = send report, start timer (IGMPv3 only)\n");

  rbtparams = pico_igmp_find_parameters(&(params->mcast_group));
  if (!rbtparams)
    return -1;

  if (rbtparams->mcast_compatibility != PICO_IGMPV3) {
    igmp_dbg("IGMP: no IGMPv3 compatible router on network\n");
    pico_err = PICO_ERR_ENOPROTOOPT;
    return -1;
  }

  if (generate_igmp_report(rbtparams) < 0)
    return -1;
  if (!rbtparams->f)
    return 0;
  copy_frame = pico_frame_copy(rbtparams->f);
  if (!copy_frame) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  if (send_membership_report(rbtparams, copy_frame) < 0)
    return -1;

  /* XXX: start timer */

  rbtparams->state = IGMP_STATE_DELAYING_MEMBER;
  igmp_dbg("IGMP: new state = delaying member\n");
  return 0;
}

/* send leave if flag set */
static int slifs(struct igmp_parameters *params)
{
  struct igmp_parameters *rbtparams = NULL;

  igmp_dbg("IGMP: event = leave group | action = send leave if flag set\n");

  rbtparams = pico_igmp_find_parameters(&(params->mcast_group));
  if (!rbtparams)
    return -1;

  /* always send leave, even if not last host */
  if (generate_igmp_report(rbtparams) < 0)
    return -1;
  if (!rbtparams->f)
    return 0;
  if (send_membership_report(rbtparams, rbtparams->f) < 0)
    return -1;

  /* delete from tree */
  pico_igmp_delete_parameters(rbtparams);
  igmp_dbg("IGMP: new state = non-member\n");
  return 0;
}

/* start timer */
static int st(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));

  igmp_dbg("IGMP: event = query received | action = start timer\n");

  ret |= create_igmp_frame(params, &(params->f), info->mcast_link, &(params->mcast_group), IGMP_TYPE_MEM_REPORT_V2);
  info->delay = (pico_rand() % (params->max_resp_time*100)); 
  ret |= start_timer(params, info->delay);

  if (0 == ret) {
    info->state = IGMP_STATE_DELAYING_MEMBER;
    igmp_dbg("IGMP: new state = delaying member\n");
    return 0;
  } else {
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

/* stop timer, clear flag */
static int stcl(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));

  igmp_dbg("IGMP: event = report received | action = stop timer, clear flag\n");

  ret |= stop_timer(&(params->mcast_group));
  info->last_host = IGMP_HOST_NOT_LAST;

  if (0 == ret) {
    info->state = IGMP_STATE_IDLE_MEMBER;
    igmp_dbg("IGMP: new state = idle member\n");
    return 0;
  } else {
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

/* send report, set flag */
static int srsf(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));

  igmp_dbg("IGMP: event = timer expired | action = send report, set flag\n");

  /* start time of parameter == start time of expired timer? */
  if (info->timer_start == params->timer_start) {
    ret |= send_membership_report(params, params->f);
  } else {
    pico_frame_discard(params->f);
  }

  if (0 == ret) {
    info->state = IGMP_STATE_IDLE_MEMBER;
    igmp_dbg("IGMP: new state = idle member\n"); 
    return 0;
  } else {
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

/* reset timer if max response time < current timer */
static int rtimrtct(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));
  unsigned long current_time_left = ((unsigned long)info->delay - (PICO_TIME_MS() - (unsigned long)info->timer_start));

  igmp_dbg("IGMP: event = query received | action = reset timer if max response time < current timer\n");

  if (((unsigned long)(params->max_resp_time * 100)) < current_time_left) {
    ret |= create_igmp_frame(params, &(params->f), params->mcast_link, &(params->mcast_group), IGMP_TYPE_MEM_REPORT_V2);
    ret |= reset_timer(params);
  }

  if (0 == ret) {
    info->state = IGMP_STATE_DELAYING_MEMBER;
    igmp_dbg("IGMP: new state = delaying member\n"); 
    return 0;
  } else {
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

static int discard(struct igmp_parameters *params){
  igmp_dbg("IGMP: ignore and discard frame\n");
  pico_frame_discard(params->f);
  return 0;
}

static int err_non(struct igmp_parameters *params){
  igmp_dbg("IGMP ERROR: state = non-member, event = %u\n", params->event);
  pico_err = PICO_ERR_ENOENT;
  return -1;
}

/* finite state machine table */
const callback host_membership_diagram_table[3][6] =
{ /* event                    |Delete Group  |Create Group |Update Group |Query Received  |Report Received  |Timer Expired */
/* state Non-Member      */ { err_non,       srsfst,       srsfst,       discard,         err_non,          discard },
/* state Delaying Member */ { stslifs,       mrsrrt,       mrsrrt,       rtimrtct,        stcl,             srsf    },
/* state Idle Member     */ { slifs,         srst,         srst,         st,              discard,          discard }
};

static int pico_igmp_process_event(struct igmp_parameters *params)
{
  struct pico_tree_node *index;
  uint8_t ret = 0;
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));

  igmp_dbg("IGMP: process event on group address %08X\n", params->mcast_group.addr);
  if (NULL == info) {
    if (params->event == IGMP_EVENT_QUERY_RECV) { /* general query (mcast_group field is zero) */
      pico_tree_foreach(index,&IGMPParameters) {
        info = index->keyValue;
        params->mcast_link.addr = info->mcast_link.addr;
        params->mcast_group.addr = info->mcast_group.addr;
        igmp_dbg("IGMP: for each mcast_group = %08X | state = %u\n", params->mcast_group.addr, info->state);
        ret |= host_membership_diagram_table[info->state][params->event](params);
      }
    } else { /* first time this group enters the state diagram */
      igmp_dbg("IGMP: state = Non-Member\n");
      ret |= host_membership_diagram_table[IGMP_STATE_NON_MEMBER][params->event](params);
    }
  } else {
    igmp_dbg("IGMP: state = %u (0: non-member - 1: delaying member - 2: idle member)\n", info->state); 
    ret |= host_membership_diagram_table[info->state][params->event](params);
  }

  if( 0 == ret) {
    return 0;
  } else {
    igmp_dbg("IGMP ERROR: pico_igmp_process_event failed!\n");
    return -1;
  }
}

