
/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Frederik Van Slycken
*********************************************************************/

#include "pico_dhcp_server.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_socket.h"




#if 0
static int dhcp_finished = 0;
void callback(void* cli, int code){
	if(code == PICO_DHCP_SUCCESS)
		dhcp_finished = 1;
	printf("callback happened with code %d!\n", code);
}

void ping_callback(struct pico_icmp4_stats *s)
{
  char host[30];
  pico_ipv4_to_string(host, s->dst.addr);
  if (s->err == 0) {
    dbg("%lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
    if (s->seq >= 3) {
      dbg("DHCP CLIENT TEST: SUCCESS!\n\n\n");
      exit(0);
    }
  } else {
    dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
    dbg("DHCP CLIENT TEST: FAILED!\n");
    exit(1);
  }
}
#endif


int main(void)
{

  unsigned char macaddr0[6] = {0,0,0x0,0xa,0x0,0x0};
  struct pico_device *vde0;
	//void* cookie;
	struct pico_ip4 address0, netmask0;

  pico_stack_init();
	pico_stack_tick(); //to get random numbers working

	macaddr0[4] = pico_rand() & 0xFF;
	macaddr0[5] = pico_rand() & 0xFF;

	//setting up the connection
	vde0 = pico_vde_create("/tmp/pic0.ctl", "vde0", macaddr0);
  if (!vde0){
		printf("vde_create failed\n");
    return 1;
	}


  address0.addr = long_be(0x0a280001); //  10.40.0.1
  netmask0.addr = long_be(0xFFFFFF00);

  pico_ipv4_link_add(vde0, address0, netmask0);

	//cookie = pico_dhcp_initiate_negotiation(vde0, &callback);
	pico_dhcp_server_loop(vde0);

	printf("going into pico loop!\n");
	while(1) {
    //char gw_txt_addr[30];
		pico_stack_tick();
		usleep(2000);
#if 0
		if(dhcp_finished==1){
			//we should have an IP by now...
			gateway = pico_dhcp_get_gateway(cookie);
      pico_ipv4_to_string(gw_txt_addr, gateway.addr);
      pico_icmp4_ping(gw_txt_addr, 3, 1000, 5000, 32, ping_callback);
      //pico_icmp4_ping(gw_txt_addr, 1, 1000, 5000, 32,NULL); // use this line to run longer tests, when you don't want to quit after you've gotten your IP
      dhcp_finished++;
		}
#endif
	}
}

