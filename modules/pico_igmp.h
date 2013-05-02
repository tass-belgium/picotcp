/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

Authors: Kristof Roelants, Simon Maes, Brecht Van Cauwenberghe
*********************************************************************/

#ifndef _INCLUDE_PICO_IGMP
#define _INCLUDE_PICO_IGMP

extern struct pico_protocol pico_proto_igmp;

struct __attribute__((packed)) pico_igmp_hdr {
  uint8_t type;
  uint8_t max_resp_time;
  uint16_t crc;
  uint32_t group_address;
};


// HOST FLAG DEFS
#define PICO_IGMP_HOST_LAST         (0x1)
#define PICO_IGMP_HOST_NOT_LAST     (0x0)

// EVENT DEFS
#define PICO_IGMP_EVENT_LEAVE_GROUP      (0x0)
#define PICO_IGMP_EVENT_JOIN_GROUP       (0x1)
#define PICO_IGMP_EVENT_QUERY_RECV       (0x2)
#define PICO_IGMP_EVENT_REPORT_RECV      (0x3)
#define PICO_IGMP_EVENT_TIMER_EXPIRED    (0x4)

// MEMBERSHIP DEFS
#define PICO_IGMP_STATES_NON_MEMBER      (0x0)
#define PICO_IGMP_STATES_DELAYING_MEMBER (0x1)
#define PICO_IGMP_STATES_IDLE_MEMBER     (0x2)

// 
#define PICO_IGMP_TYPE_MEM_QUERY      (0x11)
#define PICO_IGMP_TYPE_V1_MEM_REPORT  (0x12)
#define PICO_IGMP_TYPE_V2_MEM_REPORT  (0x16)
#define PICO_IGMP_TYPE_LEAVE_GROUP    (0x17)


//ALL_ROUTER_GROUP 224.0.0.2
#define PICO_IGMP_ALL_ROUTER_GROUP              (0x020000E0)

//ALL_HOST_GROUP 224.0.0.1
#define PICO_IGMP_ALL_HOST_GROUP                (0x010000E0)

#define PICO_IGMP_DEFAULT_MAX_RESPONSE_TIME   (100)
#define PICO_IGMP_UNSOLICITED_REPORT_INTERVAL (100)

int pico_igmp_join_group(struct pico_ip4 *group_address, struct pico_ipv4_link *link);
int pico_igmp_leave_group(struct pico_ip4 *group_address, struct pico_ipv4_link *link);

#endif /* _INCLUDE_PICO_IGMP */
