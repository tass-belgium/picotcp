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

//#define igmp2_dbg(...) do{}while(0)
#define igmp2_dbg dbg

struct igmp2_packet_params {
  uint8_t event;
  struct igmp2_action_data *data_pointer ;
};

struct igmp2_action_data {
  uint8_t max_resp_time;
  uint32_t Group_address;
  struct pico_frame *f;
};

static uint8_t membership_state = PICO_STATES_NON_MEMBER;

//initially always last
static uint8_t Last_Host_flag = PICO_IGMP_HOST_LAST;

/* Queues */
static struct pico_queue in = {};
static struct pico_queue out = {};


static int print_membership_state(void){
  igmp2_dbg("STATE = %d\n", membership_state);
  return 0;
}

int pico_igmp2_set_membershipState(uint8_t state){
  membership_state = state;
  print_membership_state();
  return 0;
}

uint8_t pico_igmp2_get_membershipState(void){
  print_membership_state();
  return membership_state ;
}


static uint8_t pico_igmp2_analyse_packet(struct pico_frame *f){
  uint8_t event = 0;

  struct pico_igmp2_hdr *hdr = (struct pico_igmp2_hdr *) f->transport_hdr;

  switch (hdr->type){
    case PICO_IGMP_TYPE_MEM_QUERY:
       //TODO: implement this funcionality
       break;
    case PICO_IGMP_TYPE_V1_MEM_REPORT:
       //TODO: implement this funcionality
       break;
    case PICO_IGMP_TYPE_V2_MEM_REPORT:
       //TODO: implement this funcionality
       break;
    case PICO_IGMP_TYPE_LEAVE_GROUP:
       //TODO: implement this funcionality
       break;
    default:
       igmp2_dbg("Error unkown TYPE %d\n",hdr->type);
       break;
  }
  return event;
}



int pico_igmp2_process_event(uint8_t event){
  //TODO implement this function

  return 0;

}

static int pico_igmp2_process_in(struct pico_protocol *self, struct pico_frame *f) {

  uint8_t event=0;

  event = pico_igmp2_analyse_packet(f); //implementation not done yet
  membership_state = pico_igmp2_process_event(event);

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

