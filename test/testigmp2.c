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

  pico_ipv4_link_add(vde_igmpv2host, address_host, netmask_host);

  link_host = pico_ipv4_link_get(&address_host);

  if (link_host) {
    pico_ipv4_route_add(network_linux, netmask_linux, gateway_linux, 1, link_host);
  }

/*START packet generation*/

  /*PACKET1: General Query--------------------------------*/
  /*Max Response Time is here 10sec!*/
  struct pico_frame *f1;
  struct pico_igmp2_hdr *igmp2_hdr1 = NULL;
  f1 = pico_proto_ipv4.alloc(&pico_proto_ipv4, sizeof(struct pico_igmp2_hdr));

  struct pico_ipv4_hdr *ipv4_hdr1 = (struct pico_ipv4_hdr *) (f1)->net_hdr;

  // Fill IPV4 header
  ipv4_hdr1->src.addr = 0x0a280001;
  ipv4_hdr1->ttl = 1;

  // Fill The IGMP2_HDR
  igmp2_hdr1 = (struct pico_igmp2_hdr *) (f1)->transport_hdr;

  igmp2_hdr1->type = 0x11;
  igmp2_hdr1->max_resp_time = 0x64;//=100
  igmp2_hdr1->group_address = 0x00000000;

  pico_igmp2_checksum(f1);

  printf("Packet generated!\n");
  /*----------------------------------------*/

  /*PACKET2: General Query--------------------------------*/
  /*Max Response Time is here 1sec!*/
  struct pico_frame *f2;
  struct pico_igmp2_hdr *igmp2_hdr2 = NULL;
  f2 = pico_proto_ipv4.alloc(&pico_proto_ipv4, sizeof(struct pico_igmp2_hdr));

  struct pico_ipv4_hdr *ipv4_hdr2 = (struct pico_ipv4_hdr *) (f2)->net_hdr;

  // Fill IPV4 header
  ipv4_hdr2->src.addr = 0x0a280001;
  ipv4_hdr2->ttl = 1;

  // Fill The IGMP2_HDR
  igmp2_hdr2 = (struct pico_igmp2_hdr *) (f2)->transport_hdr;

  igmp2_hdr2->type = 0x11;
  igmp2_hdr2->max_resp_time = 0x0a;//=10
  igmp2_hdr2->group_address = 0x00000000;

  pico_igmp2_checksum(f2);

  printf("Packet generated!\n");

  /*PACKET3: Membership Report--------------------------------*/
  /*Max Response Time is here 1sec!*/
  struct pico_frame *f3;
  struct pico_igmp2_hdr *igmp2_hdr3 = NULL;
  f3 = pico_proto_ipv4.alloc(&pico_proto_ipv4, sizeof(struct pico_igmp2_hdr));

  struct pico_ipv4_hdr *ipv4_hdr3 = (struct pico_ipv4_hdr *) (f3)->net_hdr;

  // Fill IPV4 header
  ipv4_hdr3->src.addr = 0x0a280001;
  ipv4_hdr3->ttl = 1;

  // Fill The IGMP2_HDR
  igmp2_hdr3 = (struct pico_igmp2_hdr *) (f3)->transport_hdr;

  igmp2_hdr3->type = 0x16;
  igmp2_hdr3->max_resp_time = 0x00;
  igmp2_hdr3->group_address = 0x0a0a0aef;

  pico_igmp2_checksum(f3);

  printf("Packet generated!\n");

/*END packet generation*/




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
  int i = 0;
  switch (TestNumber) {
    case 1: pico_igmp2_join_group(&group_address, link_host);
            while(i<10000)
            {
              pico_stack_tick();
              usleep(1000);
              i++;
            }
            pico_igmp2_leave_group(&group_address, link_host);
            break;

    case 2: pico_igmp2_join_group(&group_address, link_host);
            while(i<10)
            {
              pico_stack_tick();
              usleep(10);
              i++;
            }
            pico_igmp2_leave_group(&group_address, link_host);
            break;

    case 3: /*ACTION2*/
            pico_igmp2_join_group(&group_address, link_host);
            /*Delayed Member*/
            while(i<10000)
            {
              /*Necessary to process send packet*/
              pico_stack_tick();
              /*ACTION6*/
              usleep(1000);
              i++;
            }
            /*Idle Member*/
            /*ACTION4: Fake Query Received*/
            // Fake Query Received: MRT=10sec
            test_pico_igmp2_process_in(&pico_proto_igmp2,f1);
            /*Delaying Member*/
            /*ACTION5: Fake Query Received*/
            // Fake Report Received
            test_pico_igmp2_process_in(&pico_proto_igmp2,f3);
            /*Idle Member*/
            break;

    case 4: /*ACTION2*/
            pico_igmp2_join_group(&group_address, link_host);
            while(i<10)
            {
              pico_stack_tick();
              usleep(1);
              i++;
            }
            /*Delayed Member*/
            // Fake Query Received: MRT=1sec
            test_pico_igmp2_process_in(&pico_proto_igmp2,f2);
            /*Delaying Member*/
            while(i<10000)
            {
              /*Necessary to process send packet*/
              pico_stack_tick();
              /*ACTION6*/
              usleep(1000);
              i++;
            }
            /*Idle Member*/
            break;

    default: printf("ERROR: incorrect Testnumber!");
             break;
  }

  return 0;
}

