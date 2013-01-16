
/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Frederik Van Slycken
*********************************************************************/

#include "pico_dhcp_client.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_socket.h"




static int dhcp_finished = 0;
void callback(void* cli, int code){
	dhcp_finished = 1;
	printf("callback happened!\n");
}


void ping_callback(struct pico_icmp4_stats *s)
{
  char host[30];
  int time_sec = 0;
  int time_msec = 0;
  pico_ipv4_to_string(host, s->dst.addr);
  time_sec = s->time / 1000;
  time_msec = s->time % 1000;
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


int main(void)
{

  unsigned char macaddr0[6] = {0,0,0x0,0xa,0x0,0x0};
  struct pico_device *vde0;
	void* cookie;
	struct pico_ip4  gateway;

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

	cookie = pico_dhcp_initiate_negotiation(vde0, &callback);

	while(1) {
    char gw_txt_addr[30];
		pico_stack_tick();
		usleep(2000);

		if(dhcp_finished==1){
			//we should have an IP by now...
			gateway = pico_dhcp_get_gateway(cookie);
      pico_ipv4_to_string(gw_txt_addr, gateway.addr);
      pico_icmp4_ping(gw_txt_addr, 3, 1000, 5000, 32, ping_callback);
      dhcp_finished++;
		}
	}
}

