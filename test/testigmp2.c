/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Brecht Van Cauwenberghe, Simon Maes
*********************************************************************/


#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv4.h"
#include "pico_igmp2.h"
#include "test_pico_igmp2.h"
#include "pico_dev_vde.h"

int main(int argc, char **argv)
{
  int TestNumber = atoi(argv[1]);

  unsigned char macaddr_host[6] = {0x0e, 0, 0, 0xa, 0xb, 0xc};
  struct pico_ip4 address_host, netmask_host, netmask_linux, network_linux, gateway_linux;
  struct pico_device *vde_igmpv2host = NULL;
  struct pico_ipv4_link *link_host;

  pico_stack_init();

  address_host.addr = 0x0300320a;
  netmask_host.addr = 0x00FFFFFF;
  netmask_linux.addr = 0x00FFFFFF;
  network_linux.addr = 0x0000280A & netmask_linux.addr;
  gateway_linux.addr = 0xFE00320A;

  vde_igmpv2host = pico_vde_create("/tmp/pic0.ctl", "vde3", macaddr_host);

  if (vde_igmpv2host)
  {
    printf("Somethingerfzefzefze\n");
  }

  pico_ipv4_link_add(vde_igmpv2host, address_host, netmask_host);

  link_host = pico_ipv4_link_get(&address_host);

  printf("before if");
  if (link_host) {
    printf("befor route add\n");
    pico_ipv4_route_add(network_linux, netmask_linux, gateway_linux, 1, link_host);
  }
/*
  struct pico_frame *f = NULL;
  f = pico_proto_ipv4.alloc(&pico_proto_ipv4, sizeof(struct pico_igmp2_hdr));
  struct pico_igmp2_hdr *igmp2_hdr = (struct pico_igmp2_hdr *) f->transport_hdr;
  uint8_t state = PICO_IGMP2_STATES_DELAYING_MEMBER; 
  // Igmp parameter declaration
  struct igmp2_packet_params params;
  // -> Max response time 
  params.max_resp_time = 200;
  // -> Groupaddress 
  struct pico_ip4 address0;
//  address0.addr = 0x0101010e; //  224.1.1.1
//  address0.addr = 0xeffffffa; //  239.255.255.250
  address0.addr = 0x0a0a0aef; //  239.10.10.10

  params.group_address.addr = address0.addr;
*/
  struct pico_ip4 group_address;
  group_address.addr = 0x0a0a0aef; //  239.10.10.10
  switch (TestNumber) {
    case 0: pico_igmp2_join_group(&group_address, link_host);
            break;
    /*case 1: state = PICO_IGMP2_STATES_DELAYING_MEMBER;
            params.event = PICO_IGMP2_EVENT_LEAVE_GROUP; 
            test_pico_igmp2_set_membershipState(&address0, state);
            test_pico_igmp2_process_event(&params);
            break;
    case 2: state = PICO_IGMP2_STATES_NON_MEMBER;
            params.event = PICO_IGMP2_EVENT_JOIN_GROUP;
            test_pico_igmp2_set_membershipState(&address0, state);
            test_pico_igmp2_process_event(&params);
            break;
    case 3: state = PICO_IGMP2_STATES_IDLE_MEMBER;
            params.event = PICO_IGMP2_EVENT_QUERY_RECV;
            test_pico_igmp2_set_membershipState(&address0, state);
            test_pico_igmp2_process_event(&params);
            break;
    case 4: state = PICO_IGMP2_STATES_DELAYING_MEMBER;
            params.event = PICO_IGMP2_EVENT_REPORT_RECV;
            test_pico_igmp2_set_membershipState(&address0, state);
            test_pico_igmp2_process_event(&params);
            break;
    case 5: //Timer Case;
            break;
    case 6: state = PICO_IGMP2_STATES_IDLE_MEMBER;
            params.event = PICO_IGMP2_EVENT_LEAVE_GROUP;
            test_pico_igmp2_set_membershipState(&address0, state);
            test_pico_igmp2_process_event(&params);
            break;
    case 7: state = PICO_IGMP2_STATES_DELAYING_MEMBER;
            params.event = PICO_IGMP2_EVENT_QUERY_RECV;
            test_pico_igmp2_set_membershipState(&address0, state);
            test_pico_igmp2_process_event(&params);
            break;

    case 10:
            igmp2_hdr->type = PICO_IGMP2_TYPE_MEM_QUERY;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);
            break;
    case 11:
            igmp2_hdr->type = PICO_IGMP2_TYPE_V1_MEM_REPORT;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);
            break;
    case 12:
            igmp2_hdr->type = PICO_IGMP2_TYPE_V2_MEM_REPORT;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);            
            break;
    case 13:
            igmp2_hdr->type = PICO_IGMP2_TYPE_LEAVE_GROUP;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);
            break;
    case 14:
            igmp2_hdr->type = PICO_IGMP2_TYPE_V2_MEM_REPORT;
            igmp2_hdr->max_resp_time = 0;
            igmp2_hdr->crc = 0xfa04; //Test value; 
            //test_pico_igmp2_analyse_packet(f, &params);
            igmp2_hdr->group_address = 0xfaffffef; //  239.255.255.250
            pico_igmp2_checksum(f);
            igmp2_hdr->group_address = 0x0a0a0aef; //  239.10.10.10
            pico_igmp2_checksum(f);
            break;
*/
    default: printf("ERROR: incorrect Testnumber!");
             break;
     } 
  while(1){
    pico_stack_tick();
    usleep(2000);
  }

  return 0;
}

