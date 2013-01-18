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
#include "test_pico_igmp2.h"

int main(int argc, char **argv)
{
//  pico_stack_init();

//  pico_stack_tick(); // do this to enable rand generation

  int TestNumber = atoi(argv[1]);

  // Generate Test Frame
  struct pico_frame *f = pico_proto_ipv4.alloc(&pico_proto_ipv4, sizeof(struct pico_ipv4_hdr) + sizeof(struct pico_igmp2_hdr));
  
  // Create access to igmp2 header
  struct pico_igmp2_hdr *igmp2_hdr = (struct pico_igmp2_hdr *) f->transport_hdr; 

  // Create access to ipv4 header
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr*)(f->net_hdr);

   
  
  // Declaration of state
  uint8_t state = 0;

  // Igmp parameter declaration
  struct igmp2_packet_params params;
  struct igmp2_action_data data;
  params.data_pointer=&data;
  
  // -> Max response time 
  data.max_resp_time = 200;
  // -> Groupaddress 
  struct pico_ip4 address0;
//  address0.addr = 0x0101010e; //  224.1.1.1
//  address0.addr = 0xeffffffa; //  239.255.255.250
  address0.addr = 0x0a0a0aef; //  239.10.10.10

  data.Group_address = address0.addr;
/*
  switch (TestNumber) {
    case 1: state = PICO_STATES_DELAYING_MEMBER;
            params.event = PICO_EVENT_LEAVE_GROUP; 
            test_pico_igmp2_set_membershipState(state);
            test_pico_igmp2_process_event(&params);
            break;
    case 2: state = PICO_STATES_NON_MEMBER;
            params.event = PICO_EVENT_JOIN_GROUP;
            test_pico_igmp2_set_membershipState(state);
            test_pico_igmp2_process_event(&params);
            break;
    case 3: state = PICO_STATES_IDLE_MEMBER;
            params.event = PICO_EVENT_QUERY_RECV;
            test_pico_igmp2_set_membershipState(state);
            test_pico_igmp2_process_event(&params);
            break;
    case 4: state = PICO_STATES_DELAYING_MEMBER;
            params.event = PICO_EVENT_REPORT_RECV;
            test_pico_igmp2_set_membershipState(state);
            test_pico_igmp2_process_event(&params);
            break;
    case 5: //Timer Case;
            break;
    case 6: state = PICO_STATES_IDLE_MEMBER;
            params.event = PICO_EVENT_LEAVE_GROUP;
            test_pico_igmp2_set_membershipState(state);
            test_pico_igmp2_process_event(&params);
            break;
    case 7: state = PICO_STATES_DELAYING_MEMBER;
            params.event = PICO_EVENT_QUERY_RECV;
            test_pico_igmp2_set_membershipState(state);
            test_pico_igmp2_process_event(&params);
            break;

    case 10:
            igmp2_hdr->type = PICO_IGMP_TYPE_MEM_QUERY;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->Group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);
            break;
    case 11:
            igmp2_hdr->type = PICO_IGMP_TYPE_V1_MEM_REPORT;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->Group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);
            break;
    case 12:
            igmp2_hdr->type = PICO_IGMP_TYPE_V2_MEM_REPORT;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->Group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);            
            break;
    case 13:
            igmp2_hdr->type = PICO_IGMP_TYPE_LEAVE_GROUP;
            igmp2_hdr->max_resp_time = 200;
            igmp2_hdr->crc = 0;//TODO get crc; 
            igmp2_hdr->Group_address=address0.addr;
            test_pico_igmp2_analyse_packet(f, &params);
            break;
    case 14:
            igmp2_hdr->type = PICO_IGMP_TYPE_V2_MEM_REPORT;
            igmp2_hdr->max_resp_time = 0;
            igmp2_hdr->crc = 0xfa04; //Test value; 
            //test_pico_igmp2_analyse_packet(f, &params);
            igmp2_hdr->Group_address = 0xfaffffef; //  239.255.255.250
            pico_igmp2_checksum(f);
            igmp2_hdr->Group_address = 0x0a0a0aef; //  239.10.10.10
            pico_igmp2_checksum(f);
            break;

    default: printf("ERROR: incorrect Testnumber!");
             break;
     } 
*/
  return 0;
}

