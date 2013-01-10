/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.
  
Authors: Kristof Roelants, Simon Maes, Brecht Van Cauwenberghe
*********************************************************************/

#ifndef _INCLUDE_PICO_IGMP2
#define _INCLUDE_PICO_IGMP2


// EVENT DEFINITIONS
#define PICO_EVENT_JOIN_GROUP       (0x1)
#define PICO_EVENT_LEAVE_GROUP      (0x2)
#define PICO_EVENT_QUERY_RECV       (0x3)
#define PICO_EVENT_REPORT_RECV      (0x4)

// MEMBERSHIP DEFINITIONS
#define PICO_STATES_NON_MEMBER      (0x1)
#define PICO_STATES_DELAYING_MEMBER (0x2)
#define PICO_STATES_IDLE_MEMBER     (0x3)


int pico_igmp2_set_membershipState(uint8_t state);
uint8_t pico_igmp2_get_membershipState(void);

int pico_igmp2_process_event(uint8_t event);



#endif /* _INCLUDE_PICO_IGMP2 */
