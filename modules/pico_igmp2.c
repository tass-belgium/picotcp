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


//#define igmp2_dbg(...) do{}while(0)
#define igmp2_dbg dbg

static uint8_t membership_state = PICO_STATES_NON_MEMBER;


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


int pico_igmp2_process_event(uint8_t event){
  //TODO implement this function

  return 0;
}
