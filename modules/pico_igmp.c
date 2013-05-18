/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

RFC 1112, 2236, 3376, 3678, 4607

Authors: Simon Maes, Brecht Van Cauwenberghe, Kristof Roelants
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

/* membership states */
#define IGMP_STATE_NON_MEMBER            (0x0)
#define IGMP_STATE_DELAYING_MEMBER       (0x1)
#define IGMP_STATE_IDLE_MEMBER           (0x2)

/* events */ 
#define IGMP_EVENT_DELETE_GROUP          (0x0)
#define IGMP_EVENT_UPDATE_GROUP          (0x1)
#define IGMP_EVENT_QUERY_RECV            (0x2)
#define IGMP_EVENT_REPORT_RECV           (0x3)
#define IGMP_EVENT_TIMER_EXPIRED         (0x4)

/* message types */
#define IGMP_TYPE_MEM_QUERY              (0x11)
#define IGMP_TYPE_MEM_REPORT_V1          (0x12)
#define IGMP_TYPE_MEM_REPORT_V2          (0x16)
#define IGMP_TYPE_LEAVE_GROUP            (0x17)
#define IGMP_TYPE_MEM_REPORT_V3          (0x22)

/* group record types */
#define IGMP_MODE_IS_INCLUDE             (1)
#define IGMP_MODE_IS_EXCLUDE             (2)
#define IGMP_CHANGE_TO_INCLUDE_MODE      (3)
#define IGMP_CHANGE_TO_EXCLUDE_MODE      (4)
#define IGMP_ALLOW_NEW_SOURCES           (5)
#define IGMP_BLOCK_OLD_SOURCES           (6)

/* host flag */
#define IGMP_HOST_LAST                   (0x1)
#define IGMP_HOST_NOT_LAST               (0x0)

/* misc */
#define TIMER_NOT_ACTIVE                 (0)
#define IP_OPTION_ROUTER_ALERT_LEN       (4)
#define IGMP_DEFAULT_MAX_RESPONSE_TIME   (100)
#define IGMP_UNSOLICITED_REPORT_INTERVAL (100)
#define IGMP_ALL_HOST_GROUP              long_be(0xE0000001) /* 224.0.0.1 */
#define IGMP_ALL_ROUTER_GROUP            long_be(0xE0000002) /* 224.0.0.2 */
#define IGMPV3_ALL_ROUTER_GROUP          long_be(0xE0000016) /* 224.0.0.22 */

struct __attribute__((packed)) igmpv2_message {
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
  uint16_t delay;
  unsigned long timer_start;
  struct pico_ip4 mcast_link;
  struct pico_ip4 mcast_group;
  struct pico_tree *MCASTFilter;
  struct pico_frame *f;
};

struct timer_callback_info {
  unsigned long timer_start;
  struct pico_frame *f;
};

static int parameters_cmp(void *ka,void *kb)
{
	struct igmp_parameters *a = ka, *b = kb;
  if (a->mcast_group.addr < b->mcast_group.addr)
    return -1;
  if (a->mcast_group.addr > b->mcast_group.addr)
    return 1;
  return 0;
}
PICO_TREE_DECLARE(IGMPParameters, parameters_cmp);

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
  struct igmpv2_message *hdr = (struct igmpv2_message *) f->transport_hdr;
  switch (hdr->type) {
    case IGMP_TYPE_MEM_QUERY:
       params->event = IGMP_EVENT_QUERY_RECV;
       break;
    case IGMP_TYPE_MEM_REPORT_V1:
       params->event = IGMP_EVENT_REPORT_RECV;
       break;
    case IGMP_TYPE_MEM_REPORT_V2:
       params->event = IGMP_EVENT_REPORT_RECV;
       break;
    default:
       pico_frame_discard(f);
       pico_err = PICO_ERR_EINVAL;
       return -1;
  }
  params->mcast_group.addr = hdr->mcast_group;
  params->max_resp_time = hdr->max_resp_time;
  params->f = f;
  return 0;
}

static int check_igmp_checksum(struct pico_frame *f)
{
  struct igmpv2_message *igmp_hdr = (struct igmpv2_message *) f->transport_hdr;
  uint16_t header_checksum;

  if (!igmp_hdr) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  header_checksum = igmp_hdr->crc;
  igmp_hdr->crc=0;

  if (header_checksum == short_be(pico_checksum(igmp_hdr, sizeof(struct igmpv2_message)))) {
    igmp_hdr->crc = header_checksum;
    return 0;
  } else {
    igmp_hdr->crc = header_checksum;
    pico_err = PICO_ERR_EFAULT;
    return -1;
  }
}

static int pico_igmp_checksum(struct pico_frame *f)
{
  struct igmpv2_message *igmp_hdr = (struct igmpv2_message *) f->transport_hdr;
  if (!igmp_hdr) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  igmp_hdr->crc = 0;
  igmp_hdr->crc = short_be(pico_checksum(igmp_hdr, sizeof(struct igmpv2_message)));
  return 0;
}

static int pico_igmp_process_in(struct pico_protocol *self, struct pico_frame *f)
{
  struct igmp_parameters params;
 
  if (check_igmp_checksum(f) == 0) {
    if (!pico_igmp_analyse_packet(f, &params)) {
      pico_igmp_process_event(&params);
    }
  } else {
    igmp_dbg("IGMP: failure on checksum\n");
    pico_frame_discard(f);
  }
  return 0;
}

static int pico_igmp_process_out(struct pico_protocol *self, struct pico_frame *f) {
  // not supported.
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
  struct igmp_parameters params = {0};
  
  if (mcast_group->addr == IGMP_ALL_HOST_GROUP)
    return 0;

  switch (state) {
    case PICO_IGMP_STATE_CREATE:
      /* fall through */

    case PICO_IGMP_STATE_UPDATE:
      params.event = IGMP_EVENT_UPDATE_GROUP;
      break;
    
    case PICO_IGMP_STATE_DELETE:
      params.event = IGMP_EVENT_DELETE_GROUP;
      break;

    default:
      return -1;
  }

  params.mcast_link = *mcast_link;
  params.mcast_group = *mcast_group;
  params.filter_mode = filter_mode;
  params.MCASTFilter = MCASTFilter;

  return pico_igmp_process_event(&params);
}

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

static int stop_timer(struct pico_ip4 *mcast_group)
{
  struct igmp_parameters *info = pico_igmp_find_parameters(mcast_group);
  info->timer_start = TIMER_NOT_ACTIVE;
  return 0;
}

static int reset_timer(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  uint16_t delay = pico_rand() % (params->max_resp_time*100); 

  ret |= stop_timer(&(params->mcast_group));
  ret |= start_timer(params, delay);
  return ret;
}

static int send_membership_report(struct pico_frame *f)
{
  uint8_t ret = 0;
  struct igmpv2_message *igmp_hdr = (struct igmpv2_message *) f->transport_hdr;
  struct pico_ip4 dst = {0};
  struct pico_ip4 mcast_group = {0};

  mcast_group.addr = igmp_hdr->mcast_group;
  dst.addr = igmp_hdr->mcast_group;

  igmp_dbg("IGMP: send membership report on group %08X\n", mcast_group.addr);
  pico_ipv4_frame_push(f, &dst, PICO_PROTO_IGMP);
  ret |= stop_timer(&mcast_group);
  return ret;
}

static int send_leave(struct pico_frame *f)
{
  uint8_t ret = 0;
  struct igmpv2_message *igmp_hdr = (struct igmpv2_message *) f->transport_hdr;
  struct pico_ip4 mcast_group = {0};
  struct pico_ip4 dst = {0};

  mcast_group.addr = igmp_hdr->mcast_group;
  dst.addr = IGMP_ALL_ROUTER_GROUP;

  igmp_dbg("IGMP: send leave group on group %08X\n", mcast_group.addr);
  pico_ipv4_frame_push(f,&dst,PICO_PROTO_IGMP);
  ret |= stop_timer(&mcast_group);
  return ret;
}

static int generate_igmp_report(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  struct pico_ipv4_link *link = NULL;

  link = pico_ipv4_link_get(&params->mcast_link);
  if (!link) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  switch (link->mcast_router_version) {
    case PICO_IGMPV1:
      pico_err = PICO_ERR_EPROTONOSUPPORT;
      return -1;
      
    case PICO_IGMPV2:
    {
      struct igmpv2_message *report = NULL;
      params->f = pico_proto_ipv4.alloc(&pico_proto_ipv4, IP_OPTION_ROUTER_ALERT_LEN + sizeof(struct igmpv2_message));
      params->f->net_len += IP_OPTION_ROUTER_ALERT_LEN;
      params->f->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
      params->f->transport_len -= IP_OPTION_ROUTER_ALERT_LEN;
      params->f->len += IP_OPTION_ROUTER_ALERT_LEN;
      params->f->dev = pico_ipv4_link_find(&params->mcast_link);

      report = (struct igmpv2_message *)params->f->transport_hdr;
      report->type = IGMP_TYPE_MEM_REPORT_V2;
      report->max_resp_time = IGMP_DEFAULT_MAX_RESPONSE_TIME;
      report->mcast_group = params->mcast_group.addr;

      ret |= pico_igmp_checksum(params->f);
      break;
    }
    case PICO_IGMPV3:
      pico_err = PICO_ERR_EPROTONOSUPPORT;
      break;

    default:
      pico_err = PICO_ERR_EINVAL;
      return -1;
  }
  return ret;
}

static int create_igmp_frame(struct pico_frame **f, struct pico_ip4 src, struct pico_ip4 *mcast_group, uint8_t type)
{
  uint8_t ret = 0;
  struct igmpv2_message *igmp_hdr = NULL;

  *f = pico_proto_ipv4.alloc(&pico_proto_ipv4, IP_OPTION_ROUTER_ALERT_LEN + sizeof(struct igmpv2_message));
  (*f)->net_len += IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->transport_len -= IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->len += IP_OPTION_ROUTER_ALERT_LEN;
  (*f)->dev = pico_ipv4_link_find(&src);

  igmp_hdr = (struct igmpv2_message *) (*f)->transport_hdr;
  igmp_hdr->type = type;
  igmp_hdr->max_resp_time = IGMP_DEFAULT_MAX_RESPONSE_TIME;
  igmp_hdr->mcast_group = mcast_group->addr;

  ret |= pico_igmp_checksum(*f);
  return ret;
}

static void generate_event_timer_expired(long unsigned int empty, void *data)
{
  struct timer_callback_info *info = (struct timer_callback_info *) data;
  struct igmp_parameters params = {0};
  struct pico_frame* f = (struct pico_frame*)info->f;
  struct igmpv2_message *igmp_hdr = (struct igmpv2_message *) f->transport_hdr;

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
  uint8_t ret = 0;
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));
  struct pico_frame *f = NULL;

  igmp_dbg("IGMP: event = leave group | action = stop timer, send leave if flag set\n");

  ret |= stop_timer(&(params->mcast_group));
  if (IGMP_HOST_LAST == info->last_host) {
    ret |= create_igmp_frame(&f, params->mcast_link, &(params->mcast_group), IGMP_TYPE_LEAVE_GROUP);
    ret |= send_leave(f);
  }

  if ( 0 == ret) {
    /* delete from tree */
    pico_igmp_delete_parameters(info);
    igmp_dbg("IGMP: new state = non-member\n");
    return 0;
  } else {
    pico_err =  PICO_ERR_EFAULT;
    return -1;
  }
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
  copy_frame = pico_frame_copy(rbtparams->f);
  if (!copy_frame) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  if (send_membership_report(copy_frame) < 0)
    return -1;

  rbtparams->delay = (pico_rand() % (IGMP_UNSOLICITED_REPORT_INTERVAL * 100)); 
  if (start_timer(rbtparams, rbtparams->delay) < 0) /* XXX: change to one parameter? */
    return -1;
  rbtparams->state = IGMP_STATE_DELAYING_MEMBER;
  igmp_dbg("IGMP: new state = delaying member\n");
  return 0;
}

/* send leave if flag set */
static int slifs(struct igmp_parameters *params)
{
  struct pico_frame *f = NULL;
  struct igmp_parameters *info;
  uint8_t ret = 0;

  igmp_dbg("IGMP: event = leave group | action = send leave if flag set\n");

  info = pico_igmp_find_parameters(&(params->mcast_group));
  if (IGMP_HOST_LAST == info->last_host) {
    ret |= create_igmp_frame(&f, params->mcast_link, &(params->mcast_group), IGMP_TYPE_LEAVE_GROUP);
    send_leave(f);
  }

  if (0 == ret) {
    /* delete from tree */
    pico_igmp_delete_parameters(info);
    igmp_dbg("IGMP: new state = non-member\n");
    return 0;
  } else {
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

/* start timer */
static int st(struct igmp_parameters *params)
{
  uint8_t ret = 0;
  struct igmp_parameters *info = pico_igmp_find_parameters(&(params->mcast_group));

  igmp_dbg("IGMP: event = query received | action = start timer\n");

  ret |= create_igmp_frame(&(params->f), info->mcast_link, &(params->mcast_group), IGMP_TYPE_MEM_REPORT_V2);
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
    ret |= send_membership_report(params->f);
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
    ret |= create_igmp_frame(&(params->f), params->mcast_link, &(params->mcast_group), IGMP_TYPE_MEM_REPORT_V2);
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

static int err_delaying(struct igmp_parameters *params){
  igmp_dbg("IGMP ERROR: state = delaying member, event = %u\n", params->event);
  pico_err = PICO_ERR_EEXIST;
  return -1;
}

static int err_idle(struct igmp_parameters *params){
  igmp_dbg("IGMP ERROR: state = idle member, event = %u\n", params->event);
  pico_err = PICO_ERR_EEXIST;
  return -1;
}

/* finite state machine table */
const callback host_membership_diagram_table[3][5] =
{ /* event                    |Delete Group  |Update Group |Query Received  |Report Received  |Timer Expired */
/* state Non-Member      */ { err_non,       srsfst,       discard,         err_non,          discard },
/* state Delaying Member */ { stslifs,       err_delaying, rtimrtct,        stcl,             srsf    },
/* state Idle Member     */ { slifs,         err_idle,     st,              discard,          discard }
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

