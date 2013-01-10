/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Kristof Roelants, Brecht Van Cauwenberghe,
         Simon Maes, Philippe Mariman
*********************************************************************/


#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_igmp2.h"


int main(int argc, char **argv)
{
  pico_stack_init();

  pico_stack_tick(); // do this to enable rand generation


  int TestNumber = atoi(argv[1]);

  uint8_t state = 0;
  uint8_t event = 0;

  switch (TestNumber) {
    case 1: state = PICO_STATES_DELAYING_MEMBER;
            event = PICO_EVENT_LEAVE_GROUP; 
            pico_igmp2_set_membershipState(state);
            pico_igmp2_process_event(event); 
            break;
    case 2: state = PICO_STATES_NON_MEMBER;
            event = PICO_EVENT_JOIN_GROUP;
            pico_igmp2_set_membershipState(state);
            pico_igmp2_process_event(event);            
            break;
    case 3: state = PICO_STATES_IDLE_MEMBER;
            event = PICO_EVENT_QUERY_RECV;
            pico_igmp2_set_membershipState(state);
            pico_igmp2_process_event(event);
            break;
    case 4: state = PICO_STATES_DELAYING_MEMBER;
            event = PICO_EVENT_REPORT_RECV;
            pico_igmp2_set_membershipState(state);
            pico_igmp2_process_event(event);
            break;
    case 5: //Timer Case;
            break;
    case 6: state = PICO_STATES_IDLE_MEMBER;
            event = PICO_EVENT_LEAVE_GROUP;
            pico_igmp2_set_membershipState(state);
            pico_igmp2_process_event(event);
            break;
    case 7: state = PICO_STATES_DELAYING_MEMBER;
            event = PICO_EVENT_QUERY_RECV;
            pico_igmp2_set_membershipState(state);
            pico_igmp2_process_event(event);
            break;

    default: printf("ERROR: incorrect Testnumber!");
             break;
     } 





  return 0;

}


