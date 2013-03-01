/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

Authors: Simon Maes, Brecht Van Cauwenberghe
*********************************************************************/

#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_igmp2.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_frame.h"
#include "pico_tree.h"

#define NO_ACTIVE_TIMER (0)


/*================= RB_TREE FUNCTIONALITY ================*/

struct mgroup_info {
  struct pico_ip4 mgroup_addr;
  struct pico_ip4 src_interface;
  unsigned long active_timer_starttime;
  /* Connector for trees */
  uint16_t delay;
  uint8_t membership_state;
  uint8_t Last_Host_flag;
};

struct timer_callback_info {
  unsigned long timer_starttime;
  struct pico_frame *f;
};

static int mgroup_cmp(void *ka,void *kb)
{
	struct mgroup_info *a=ka, *b=kb;
  if (a->mgroup_addr.addr < b->mgroup_addr.addr) {
    return -1;
  }
  else if (a->mgroup_addr.addr > b->mgroup_addr.addr) {
    return 1;
  }
  else {
     /* a and b are identical */
    return 0;
  }
}

PICO_TREE_DECLARE(KEYTable,mgroup_cmp);

static struct mgroup_info *pico_igmp2_find_mgroup(struct pico_ip4 *mgroup_addr)
{
  struct mgroup_info test = {{0}};
  test.mgroup_addr.addr = mgroup_addr->addr;
  /* returns NULL if test can not be found */
  return pico_tree_findKey(&KEYTable,&test);
}

static int pico_igmp2_del_mgroup(struct mgroup_info *info)
{
  if(!info){
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  else {
    // RB_REMOVE returns pointer to removed element, NULL to indicate error·
    if(pico_tree_delete(&KEYTable,info))
      pico_free(info);
    else {
      pico_err = PICO_ERR_EEXIST;
      return -1;// Do not free, error on removing element from tree
    }
  }
  return 0;
}

/*========================================================*/

struct igmp2_packet_params {
  struct pico_ip4 group_address;
  struct pico_ip4 src_interface;
  struct pico_frame *f;
  uint8_t event;
  uint8_t max_resp_time;
  unsigned long timer_starttime;
};

static int pico_igmp2_process_event(struct igmp2_packet_params *params);
static void generate_event_timer_expired(long unsigned int empty, void *info);

#ifdef PICO_UNIT_TEST_IGMP2
#define igmp2_dbg dbg
static int pico_igmp2_process_event(struct igmp2_packet_params *params);
static int pico_igmp2_analyse_packet(struct pico_frame *f, struct igmp2_packet_params *params);
static int pico_igmp2_process_in(struct pico_protocol *self, struct pico_frame *f);


int test_pico_igmp2_process_in(struct pico_protocol *self, struct pico_frame *f){
  pico_igmp2_process_in(self, f);
  return 0;
}
int test_pico_igmp2_set_membershipState(struct pico_ip4 *mgroup_addr ,uint8_t state){
  struct mgroup_info *info = pico_igmp2_find_mgroup(mgroup_addr);
  info->membership_state = state;
  igmp2_dbg("DEBUG_IGMP2:STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delaying MEMBER" : "Idle MEMBER"))); 
  return 0;
}
uint8_t test_pico_igmp2_get_membershipState(struct pico_ip4 *mgroup_addr){
  struct mgroup_info *info = pico_igmp2_find_mgroup(mgroup_addr);
  igmp2_dbg("DEBUG_IGMP2:STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delaying Member" : "Idle Member"))); 
  return info->membership_state;
}
int test_pico_igmp2_process_event(struct igmp2_packet_params *params) {
   pico_igmp2_process_event(params);
   return 0;
}

int test_pico_igmp2_analyse_packet(struct pico_frame *f, struct igmp2_packet_params *params){
  pico_igmp2_analyse_packet(f, params);
  return 0;
}
#else
#define igmp2_dbg(...) do{}while(0)
#endif


/* Queues */
static struct pico_queue igmp_in = {};
static struct pico_queue igmp_out = {};

static int pico_igmp2_analyse_packet(struct pico_frame *f, struct igmp2_packet_params *params){
  struct pico_igmp2_hdr *hdr = (struct pico_igmp2_hdr *) f->transport_hdr;
  switch (hdr->type){
    case PICO_IGMP2_TYPE_MEM_QUERY:
       params->event = PICO_IGMP2_EVENT_QUERY_RECV;
       break;
    case PICO_IGMP2_TYPE_V1_MEM_REPORT:
       params->event = PICO_IGMP2_EVENT_REPORT_RECV;
       break;
    case PICO_IGMP2_TYPE_V2_MEM_REPORT:
       params->event = PICO_IGMP2_EVENT_REPORT_RECV;
       break;
    default:
       pico_frame_discard(f);
       pico_err = PICO_ERR_EINVAL;
       return -1;
  }
  params->group_address.addr = hdr->group_address;
  params->max_resp_time = hdr->max_resp_time;
  params->f = f;
  return 0;
}

static int check_igmp2_checksum(struct pico_frame *f){
  struct pico_igmp2_hdr *igmp2_hdr = (struct pico_igmp2_hdr *) f->transport_hdr;
  uint16_t header_checksum = igmp2_hdr->crc;

  if (!igmp2_hdr) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  igmp2_hdr->crc=0;

  if(header_checksum == short_be(pico_checksum(igmp2_hdr, sizeof(struct pico_igmp2_hdr)))){
    igmp2_hdr->crc = header_checksum;
    return 0;
  }else{
    igmp2_hdr->crc = header_checksum;
    pico_err = PICO_ERR_EFAULT;
    return -1;
  }
}

static int pico_igmp2_checksum(struct pico_frame *f)
{
  struct pico_igmp2_hdr *igmp2_hdr = (struct pico_igmp2_hdr *) f->transport_hdr;
  if (!igmp2_hdr) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  igmp2_hdr->crc = 0;
  igmp2_hdr->crc = short_be(pico_checksum(igmp2_hdr, sizeof(struct pico_igmp2_hdr)));
  //igmp2_dbg("CHECKSUM = %04X\n",igmp2_hdr->crc);
  return 0;
}


static int pico_igmp2_process_in(struct pico_protocol *self, struct pico_frame *f) {
  igmp2_dbg("pico_igmp2_process_in\n");
  struct igmp2_packet_params params;
 
  if (check_igmp2_checksum(f) == 0) {
    if (!pico_igmp2_analyse_packet(f,&params)) {
      pico_igmp2_process_event(&params);
    }
  }else{
    igmp2_dbg("failed for igmp2 checksum\n");
    pico_frame_discard(f);
  }
  return 0;
}

static int pico_igmp2_process_out(struct pico_protocol *self, struct pico_frame *f) {
  // TODO impmement this function
  return 0;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_igmp2 = {
  .name = "igmp2",
  .proto_number = PICO_PROTO_IGMP2,
  .layer = PICO_LAYER_TRANSPORT,
  .process_in = pico_igmp2_process_in,
  .process_out = pico_igmp2_process_out,
  .q_in = &igmp_in,
  .q_out = &igmp_out,
};


/*====================== API CALLS ======================*/

int pico_igmp2_join_group(struct pico_ip4 *group_address, struct pico_ipv4_link *link) {
  struct igmp2_packet_params params = {{0}};

  params.event = PICO_IGMP2_EVENT_JOIN_GROUP ;
  params.group_address.addr = group_address->addr;
  params.src_interface.addr = link->address.addr;

  return pico_igmp2_process_event(&params);
}

int pico_igmp2_leave_group(struct pico_ip4 *group_address, struct pico_ipv4_link *link) {
  struct igmp2_packet_params params = {{0}};

  params.event = PICO_IGMP2_EVENT_LEAVE_GROUP ;
  params.group_address.addr = group_address->addr;
  params.src_interface.addr = link->address.addr;

  return pico_igmp2_process_event(&params);
}

/*================== GENERAL FUNCTIONS ==================*/

static int start_timer(struct igmp2_packet_params *params,const uint16_t delay){

  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));
  struct timer_callback_info *timer_info= pico_zalloc(sizeof(struct timer_callback_info));
  timer_info->timer_starttime = PICO_TIME_MS();
  info->delay = delay;
  timer_info->f = params->f;

  info->active_timer_starttime = timer_info->timer_starttime;

  pico_timer_add(delay, &generate_event_timer_expired, timer_info);
  return 0;
}

static int stop_timer(struct pico_ip4 *group_address){

  struct mgroup_info *info = pico_igmp2_find_mgroup(group_address);
  info->active_timer_starttime = NO_ACTIVE_TIMER;
  return 0;
}


static int reset_timer(struct igmp2_packet_params *params){

  uint8_t ret = 0;
  ret |= stop_timer(&(params->group_address));
  uint16_t delay = pico_rand() % (params->max_resp_time*100); 

  ret |= start_timer(params, delay);
  return ret;
}

static int send_membership_report(struct pico_frame *f){
  uint8_t ret = 0;
  struct pico_igmp2_hdr *igmp2_hdr = (struct pico_igmp2_hdr *) f->transport_hdr;

  struct pico_ip4 dst = {0};
  struct pico_ip4 group_address = {0};
  group_address.addr = igmp2_hdr->group_address;
  dst.addr = igmp2_hdr->group_address;

  igmp2_dbg("send_membership_report on group %x\n",group_address.addr);
  pico_ipv4_frame_push(f,&dst,PICO_PROTO_IGMP2);
  ret |= stop_timer(&group_address);
  return ret;
}

static int send_leave(struct pico_frame *f) {
  igmp2_dbg("send leave\n");
  uint8_t ret = 0;
  struct pico_igmp2_hdr *igmp2_hdr = (struct pico_igmp2_hdr *) f->transport_hdr;

  struct pico_ip4 group_address = {0};
  group_address.addr = igmp2_hdr->group_address;
  struct pico_ip4 dst = {0};
  dst.addr = PICO_IGMP2_ALL_ROUTER_GROUP;

  pico_ipv4_frame_push(f,&dst,PICO_PROTO_IGMP2);
  ret |= stop_timer(&group_address);
  return ret;
}

static int create_igmp2_frame(struct pico_frame **f, struct pico_ip4 src, struct pico_ip4 *mcast_addr, uint8_t type){
  uint8_t ret = 0;
  struct pico_igmp2_hdr *igmp2_hdr = NULL;
  *f = pico_proto_ipv4.alloc(&pico_proto_ipv4, sizeof(struct pico_igmp2_hdr));

  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *) (*f)->net_hdr;

  // Fill IPV4 header
  ipv4_hdr->src.addr = src.addr;
  ipv4_hdr->ttl = 1;

  // Fill The IGMP2_HDR
  igmp2_hdr = (struct pico_igmp2_hdr *) (*f)->transport_hdr;

  igmp2_hdr->type = type;
  igmp2_hdr->max_resp_time = PICO_IGMP2_DEFAULT_MAX_RESPONSE_TIME;
  igmp2_hdr->group_address = mcast_addr->addr;

  ret |= pico_igmp2_checksum(*f);
  return ret;
}

/*================== TIMER CALLBACKS ====================*/

static void generate_event_timer_expired(long unsigned int empty, void *data) {
  struct timer_callback_info *info = (struct timer_callback_info *) data;
  struct igmp2_packet_params params = {{0}};
  struct pico_frame* f = (struct pico_frame*)info->f;
  struct pico_igmp2_hdr *igmp2_hdr = (struct pico_igmp2_hdr *) f->transport_hdr;

  params.event = PICO_IGMP2_EVENT_TIMER_EXPIRED;
  params.group_address.addr = igmp2_hdr->group_address;
  params.timer_starttime = info->timer_starttime;
  params.f = info->f;

  pico_igmp2_process_event(&params);
  pico_free(info);  
}

/* ------------------ */
/* HOST STATE MACHINE */
/* ------------------ */

/* state callbacks prototype */
typedef int (*callback)(struct igmp2_packet_params *);


/*------------ ACTIONS ------------*/
/*
#ACTION1 STSLIFS:  stop timer, send leave if flag set
#ACTION2 SRSFST:   send report, set flag, start timer
#ACTION3 SLIFS:    send leave if flag set
#ACTION4 ST:       start timer
#ACTION5 STCL:     stop timer, clear flag
#ACTION6 SRSF:     send report, set flag
#ACTION7 RTIMRTCT: reset timer if Max resp time < current time
*/

static int action1(struct igmp2_packet_params *params){

  uint8_t ret = 0;
  igmp2_dbg("DEBUG_IGMP2:EVENT = Leave Group\n");
  igmp2_dbg("DEBUG_IGMP2:ACTION = STSLIFS\n");
  ret |= stop_timer(&(params->group_address));

  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));
  if (PICO_IGMP2_HOST_LAST == info->Last_Host_flag) {
    struct pico_frame *f = NULL;
    ret |= create_igmp2_frame(&f, params->src_interface, &(params->group_address), PICO_IGMP2_TYPE_LEAVE_GROUP);
    ret |= send_leave(f);
  }

  /*Check if action is completed successfully, if so then adjust Membership State*/
  if( 0 == ret) {
    igmp2_dbg("DEBUG_IGMP2:NEW STATE = Non-Member\n");
    /*del element from tree*/
    pico_igmp2_del_mgroup(info);
    return 0;
  }else{
    pico_err =  PICO_ERR_EFAULT;
    return -1;
  }
}

static int action2(struct igmp2_packet_params *params){

  uint8_t ret = 0;
  struct pico_frame *f = NULL;

  igmp2_dbg("DEBUG_IGMP2:EVENT = Join Group\n");
  igmp2_dbg("DEBUG_IGMP2:ACTION = SRSFST\n");

  /*insert in tree*/
  struct mgroup_info *info = pico_zalloc(sizeof(struct mgroup_info));
  info->mgroup_addr.addr = params->group_address.addr;
  info->src_interface.addr = params->src_interface.addr;
  info->membership_state = PICO_IGMP2_STATES_NON_MEMBER;
  info->Last_Host_flag = PICO_IGMP2_HOST_LAST;
  info->active_timer_starttime = NO_ACTIVE_TIMER;

  pico_tree_insert(&KEYTable,info);
  /*---------------*/

  ret |= create_igmp2_frame(&f, params->src_interface, &(params->group_address), PICO_IGMP2_TYPE_V2_MEM_REPORT);

  struct pico_frame *copy_frame = pico_frame_copy(f);
  if (copy_frame == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  ret |= send_membership_report(copy_frame);
  info->delay = (pico_rand() %( PICO_IGMP2_UNSOLICITED_REPORT_INTERVAL*100)); 
  params->f = f;
  ret |= start_timer(params, info->delay);
  /*Check if action is completed successfully, if so then adjust Membership State*/
  if( 0 == ret) {
    struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));
    info->membership_state = PICO_IGMP2_STATES_DELAYING_MEMBER;
    igmp2_dbg("DEBUG_IGMP2:NEW STATE = Delaying Member\n");
    return 0;
  }else{
    pico_err = PICO_ERR_EFAULT;
    return -1;
  }
}

static int action3(struct igmp2_packet_params *params){

  uint8_t ret = 0;

  igmp2_dbg("DEBUG_IGMP2:EVENT = Leave Group\n");
  igmp2_dbg("DEBUG_IGMP2:ACTION = SLIFS\n");

  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));
  if (PICO_IGMP2_HOST_LAST == info->Last_Host_flag) {
    struct pico_frame *f = NULL;
    ret |= create_igmp2_frame(&f, params->src_interface, &(params->group_address), PICO_IGMP2_TYPE_LEAVE_GROUP);
    send_leave(f);
  }

  /*Check if action is completed successfully, if so then adjust Membership State*/
  if( 0 == ret) {
    igmp2_dbg("DEBUG_IGMP2:NEW STATE = Non-Member\n");
    /*del element from tree*/
    pico_igmp2_del_mgroup(info);
    return 0;
  }else{
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

static int action4(struct igmp2_packet_params *params){

  uint8_t ret = 0;

  igmp2_dbg("DEBUG_IGMP2:EVENT = Query Received\n");
  igmp2_dbg("DEBUG_IGMP2:ACTION = ST\n");

  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));

  ret |= create_igmp2_frame(&(params->f), info->src_interface, &(params->group_address), PICO_IGMP2_TYPE_V2_MEM_REPORT);

  info->delay = (pico_rand() % (params->max_resp_time*100) ); 
  ret |= start_timer(params, info->delay);

  /*Check if action is completed successfully, if so then adjust Membership State*/
  if( 0 == ret) {
    info->membership_state = PICO_IGMP2_STATES_DELAYING_MEMBER;
    igmp2_dbg("DEBUG_IGMP2:NEW STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delaying Member" : "Idle Member"))); 
    return 0;
  }else{
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

static int action5(struct igmp2_packet_params *params){

  uint8_t ret = 0;

  igmp2_dbg("DEBUG_IGMP2:EVENT = Report Received\n");
  igmp2_dbg("DEBUG_IGMP2:ACTION = STCL\n");

  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));
  ret |= stop_timer(&(params->group_address));
  info->Last_Host_flag = PICO_IGMP2_HOST_LAST;

  /*Check if action is completed successfully, if so then adjust Membership State*/
  if( 0 == ret) {
    info->membership_state = PICO_IGMP2_STATES_IDLE_MEMBER;
    igmp2_dbg("DEBUG_IGMP2:NEW STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delayed Member" : "Idle Member"))); 
    return 0;
  }else{
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

static int action6(struct igmp2_packet_params *params){

  uint8_t ret = 0;

  igmp2_dbg("DEBUG_IGMP2:EVENT = Timer Expired\n");
  igmp2_dbg("DEBUG_IGMP2:ACTION = SRSF\n");

  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));
  if ( info->active_timer_starttime == params->timer_starttime) {
    ret |= send_membership_report(params->f);
  }
  else {
    pico_frame_discard(params->f);
  }

  //Check if action is completed successfully, if so then adjust Membership State
  if( 0 == ret) {
    info->membership_state = PICO_IGMP2_STATES_IDLE_MEMBER;
    igmp2_dbg("DEBUG_IGMP2:NEW STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delaying Member" : "Idle Member"))); 
    return 0;
  }else{
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

static int action7(struct igmp2_packet_params *params){

  uint8_t ret = 0;
  igmp2_dbg("DEBUG_IGMP2:EVENT = Query Received\n");
  igmp2_dbg("DEBUG_IGMP2:ACTION = RTIMRTCT\n");
  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));

  unsigned long current_time_left = ((unsigned long)info->delay - (PICO_TIME_MS()-(unsigned long)info->active_timer_starttime));

  if ( ((unsigned long) (params->max_resp_time*100)) < current_time_left) {
    ret |= create_igmp2_frame(&(params->f), params->src_interface, &(params->group_address), PICO_IGMP2_TYPE_V2_MEM_REPORT);
    ret |= reset_timer(params);
  }
  /*Check if action is completed successfully, if so then adjust Membership State*/
  if( 0 == ret) {
    info->membership_state = PICO_IGMP2_STATES_DELAYING_MEMBER;
    igmp2_dbg("DEBUG_IGMP2:NEW STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delaying Member" : "Idle Member"))); 
    return 0;
  }else{
    pico_err = PICO_ERR_ENOENT;
    return -1;
  }
}

static int ignore_and_discardframe(struct igmp2_packet_params *params){
  igmp2_dbg("ignore and discard frame igmp2\n");
  pico_frame_discard(params->f);
  return 0;
}

static int generate_err1(struct igmp2_packet_params *params){
  igmp2_dbg("ERROR: STATE = Non-Member, EVENT = Leave Group");
  pico_err = PICO_ERR_ENOENT;
  return -1;
}

static int generate_err2(struct igmp2_packet_params *params){
  igmp2_dbg("ERROR: STATE = Delaying Member, EVENT = Join Group");
  pico_err = PICO_ERR_EEXIST;
  return -1;
}

static int generate_err3(struct igmp2_packet_params *params){
  igmp2_dbg("ERROR: STATE = Idle Member, EVENT = Join Group");
  pico_err = PICO_ERR_EEXIST;
  return -1;
}

static int generate_err4(struct igmp2_packet_params *params){
  igmp2_dbg("ERROR: STATE = Non-Member, EVENT = Report Received");
  pico_err = PICO_ERR_ENOENT;
  return -1;
}

/* finite state machine table */
const callback host_membership_diagram_table[3][5] =
{ /*     event               |Leave Group       |Join Group       |Query Received              |Report Received            |Timer Expired */
/* state Non-Member      */ { generate_err1,     action2,          ignore_and_discardframe,     generate_err4,              ignore_and_discardframe   },
/* state Delaying Member */ { action1,           generate_err2,    action7,                     action5,                    action6                   },
/* state Idle Member     */ { action3,           generate_err3,    action4,                     ignore_and_discardframe,    ignore_and_discardframe   }
};

static int pico_igmp2_process_event(struct igmp2_packet_params *params) {
	struct pico_tree_node * index;
  igmp2_dbg("pico_igmp2_process_event , params->group_address = %x\n",params->group_address.addr);
  uint8_t ret = 0;
  struct mgroup_info *info = pico_igmp2_find_mgroup(&(params->group_address));
  if (NULL == info) {
    if(params->event == PICO_IGMP2_EVENT_QUERY_RECV){
      pico_tree_foreach(index,&KEYTable){
    		info = index->keyValue;
        params->src_interface.addr = info->src_interface.addr;
        params->group_address.addr = info->mgroup_addr.addr;
        igmp2_dbg("FOR EACH params->group_address = %x\n",params->group_address.addr);

        igmp2_dbg("DEBUG_IGMP2:STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delaying Member" : "Idle Member"))); 
        ret |= host_membership_diagram_table[info->membership_state][params->event](params);
      }
    }
    else{//first time this group enters the state diagram
      igmp2_dbg("DEBUG_IGMP2:STATE = Non-Member\n");
      ret |= host_membership_diagram_table[PICO_IGMP2_STATES_NON_MEMBER][params->event](params);
    }
  }else {
    igmp2_dbg("DEBUG_IGMP2:STATE = %s\n", (info->membership_state == 0 ? "Non-Member" : (info->membership_state == 1 ? "Delaying Member" : "Idle Member"))); 
    ret |= host_membership_diagram_table[info->membership_state][params->event](params);
  }

  if( 0 == ret) {
    return 0;
  }else{
    igmp2_dbg("ERROR: pico_igmp2_process_event FAILED!\n");
    return -1;
  }
}
