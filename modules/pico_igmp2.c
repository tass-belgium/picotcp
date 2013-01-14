/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Simon Maes, Brecht Van Cauwenberghe
*********************************************************************/

#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_igmp2.h"
#include "pico_config.h"
#include "pico_eth.h"

static uint8_t membership_state = PICO_STATES_NON_MEMBER;

//initially always last
static uint8_t Last_Host_flag = PICO_IGMP_HOST_LAST;

struct igmp2_packet_params {
  uint8_t event;
  struct igmp2_action_data *data_pointer ;
};

struct igmp2_action_data {
  uint8_t max_resp_time;
  uint32_t Group_address;
  struct pico_frame *f;
};


#ifdef PICO_UNIT_TEST_IGMP2
#define igmp2_dbg dbg

static int pico_igmp2_process_event(struct igmp2_packet_params *params);
static int pico_igmp2_analyse_packet(struct pico_frame *f, struct igmp2_packet_params *params);


int test_pico_igmp2_set_membershipState(uint8_t state ){
  membership_state = state;
  igmp2_dbg("STATE: %d\n",membership_state);
  return 0;
}
uint8_t test_pico_igmp2_get_membershipState(void){
  igmp2_dbg("STATE: %d\n",membership_state);
  return membership_state;
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
static struct pico_queue in = {};
static struct pico_queue out = {};

static int pico_igmp2_analyse_packet(struct pico_frame *f, struct igmp2_packet_params *params){

  struct pico_igmp2_hdr *hdr = (struct pico_igmp2_hdr *) f->transport_hdr;
  struct igmp2_action_data *data = params->data_pointer;

  switch (hdr->type){
    //TODO: Test functionality
    case PICO_IGMP_TYPE_MEM_QUERY:
       igmp2_dbg("QUERY REQUEST\n");
       params->event = PICO_EVENT_QUERY_RECV;
       break;
    case PICO_IGMP_TYPE_V1_MEM_REPORT:
       igmp2_dbg("REPORT = VERSION 1\n");
       params->event = PICO_EVENT_REPORT_RECV;
       break;
    case PICO_IGMP_TYPE_V2_MEM_REPORT:
       igmp2_dbg("REPORT = VERSION 2\n");
       params->event = PICO_EVENT_REPORT_RECV;
       break;
    default:
       igmp2_dbg("Error unkown TYPE %d\n",hdr->type);
       pico_frame_discard(f);
       return 1;
       break;
  }
  data->Group_address = hdr->Group_address;
  data->max_resp_time = hdr->max_resp_time;
  data->f = f;
  return 0;
}

static int pico_igmp2_process_event(struct igmp2_packet_params *params) {
  //TODO implement this function
  // params = pointer to parameter struct
  // membership_state = current membership state
  // params->event = current event
  // tablet_state_table[membership_state][params->event](params);
  return 0;
}

static int check_igmp2_checksum(struct pico_frame *f){
  //TODO implement this function;
  igmp2_dbg("ERROR CRC IS NOT CHECKED YET! \n");
  return 0;
}

static int pico_igmp2_process_in(struct pico_protocol *self, struct pico_frame *f) {

  // TODO check if this abstraction data pointer is really usefull
  struct igmp2_packet_params params;
  struct igmp2_action_data data;
  params.data_pointer=&data;
 
  if (check_igmp2_checksum(f) == 0) {
    if (pico_igmp2_analyse_packet(f,&params)) {
      pico_igmp2_process_event(&params);
    }
  }else{
    // TODO send error message for failed checksum
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
  .q_in = &in,
  .q_out = &out,
};
