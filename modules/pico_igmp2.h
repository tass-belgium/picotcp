/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.
  
Authors: Kristof Roelants, Simon Maes, Brecht Van Cauwenberghe
*********************************************************************/

#ifndef _INCLUDE_PICO_IGMP2
#define _INCLUDE_PICO_IGMP2

extern struct pico_protocol pico_proto_igmp2;

struct __attribute__((packed)) pico_igmp2_hdr {
  uint8_t type;
  uint8_t max_resp_time;
  uint16_t crc;
  uint32_t Group_address;
};


// HOST FLAG DEFS
#define PICO_IGMP_HOST_LAST         (0x1)
#define PICO_IGMP_HOST_NOT_LAST     (0x0)

// EVENT DEFS
#define PICO_EVENT_JOIN_GROUP       (0x1)
#define PICO_EVENT_LEAVE_GROUP      (0x2)
#define PICO_EVENT_QUERY_RECV       (0x3)
#define PICO_EVENT_REPORT_RECV      (0x4)

// MEMBERSHIP DEFS
#define PICO_STATES_NON_MEMBER      (0x1)
#define PICO_STATES_DELAYING_MEMBER (0x2)
#define PICO_STATES_IDLE_MEMBER     (0x3)

// 
#define PICO_IGMP_TYPE_MEM_QUERY      (0x11)
#define PICO_IGMP_TYPE_V1_MEM_REPORT  (0x12)
#define PICO_IGMP_TYPE_V2_MEM_REPORT  (0x16)
#define PICO_IGMP_TYPE_LEAVE_GROUP    (0x17)


//TODO define ALL_ROUTER_GROUP 224.0.0.2



int pico_igmp2_set_membershipState(uint8_t state);
uint8_t pico_igmp2_get_membershipState(void);

int pico_igmp2_process_event(uint8_t event);



#endif /* _INCLUDE_PICO_IGMP2 */
