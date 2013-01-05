#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
#include "pico_frame.h" // include the pico_frame struct
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_tcp.h"
#include "pico_udp.h"
#include "pico_nat.h" 
#include "pico_addressing.h" 


#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

static int nat_print_frame_content(struct pico_frame* f){
  struct pico_ipv4_hdr* ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;

  if (ipv4_hdr->proto == PICO_PROTO_TCP) {
    struct pico_tcp_hdr *tcp_hdr = NULL;  
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    printf("frame:\t daddr %08X | dport %u | proto %u\n\t saddr %08X | sport %u\n",ipv4_hdr->dst.addr,tcp_hdr->trans.dport,ipv4_hdr->proto,ipv4_hdr->src.addr,tcp_hdr->trans.sport);
  } else if (ipv4_hdr->proto == PICO_PROTO_UDP) {
    struct pico_udp_hdr *udp_hdr = NULL;  
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    printf("frame:\t daddr %08X | dport %u | proto %u\n\t saddr %08X | sport %u\n",ipv4_hdr->dst.addr,udp_hdr->trans.dport,ipv4_hdr->proto,ipv4_hdr->src.addr,udp_hdr->trans.sport);
  }
  return 0;
}

static int change_src_dst(struct pico_frame* f){
  struct pico_ipv4_hdr* ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  struct pico_ip4 temp;
  uint16_t temp_port = 0; 
  //switch addr
  temp.addr = ipv4_hdr->src.addr;
  ipv4_hdr->src.addr = ipv4_hdr->dst.addr;
  ipv4_hdr->dst.addr = temp.addr;

  //switch ports
  if (ipv4_hdr->proto == PICO_PROTO_TCP) {
    struct pico_tcp_hdr *tcp_hdr = NULL;  
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    temp_port=tcp_hdr->trans.sport;
    tcp_hdr->trans.sport=tcp_hdr->trans.dport;
    tcp_hdr->trans.dport=temp_port;
  } else if (ipv4_hdr->proto == PICO_PROTO_UDP) {
    struct pico_udp_hdr *udp_hdr = NULL;  
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    temp_port=udp_hdr->trans.sport;
    udp_hdr->trans.sport=udp_hdr->trans.dport;
    udp_hdr->trans.dport=temp_port;
  }
  return 0;
}


int main(void)
{
  pico_stack_init();
	
  pico_stack_tick(); // do this to enable rand generation
  
  printf("started nat Test --------------------\n");
  uint8_t buffer[200]= {0};
  struct pico_frame *f= (struct pico_frame *) buffer;
  struct pico_ip4 nat_addr;
  nat_addr.addr = 0xFF00280a; //  10.40.0.256 Public Address
  
  uint8_t ipv4_buf[]= {0x45, 0x00, 0x00, 0x4a, 0x91, 0xc3, 0x40, 0x00, 0x3f, 0x06, 0x95, 0x8c, 0x0a, 0x32, 0x00, 0x03, 0x0a, 0x28, 0x00, 0x02};
  uint8_t tcp_buf[]= { 0x15, 0xb3, 0x15, 0xb3, 0xd5, 0x75, 0x77, 0xee, 0x00, 0x00, 0x00, 0x00, 0x90, 0x08, 0xf5, 0x3c, 0x55, 0x1f, 0x00, 0x00, 0x03, 0x03,  0x00, 0x08, 0x0a, 0xb7, 0xeb, 0xce, 0xc1, 0xb7, 0xeb, 0xce, 0xb5, 0x01, 0x01, 0x00}; 
 
  // connect the buffer to the f->net_hdr pointer 
  f->net_hdr= ipv4_buf;
  if (!f->net_hdr){
    printf("FAILED!");
    exit(0);
  }else{
    printf("net hdr is pointer to a buffer\n");
  }

  // connect the buffer to the f->transport_hdr pointer 
  f->transport_hdr= tcp_buf;
  if (!f->transport_hdr){
    printf("FAILED!");
    exit(0);
  }else{
    printf("transport hdr is pointer to a buffer\n");
  }
  
  printf("----------BEFORE NAT::\n");
  nat_print_frame_content(f);
  
  pico_ipv4_nat(f, nat_addr);
  printf("----------AFTER NAT::\n");
  nat_print_frame_content(f);

  printf("----------CHANGE SRC <-> DEST::\n");
  change_src_dst(f);
  nat_print_frame_content(f);



  printf("----------SECOND NAT::\n");
  pico_ipv4_nat(f, nat_addr);
  nat_print_frame_content(f);
   

  printf("----------CHANGE SRC <-> DEST::\n");
  change_src_dst(f);
  nat_print_frame_content(f);



  printf("----------THIRD NAT::\n");
  pico_ipv4_nat(f, nat_addr);
  nat_print_frame_content(f);





 return 0;
}
