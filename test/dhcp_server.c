
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


	struct pico_dhcpd_settings s = {0};

	s.dev = vde0;
	s.my_ip.addr = address0.addr;
	s.netmask.addr = netmask0.addr;
	s.pool_start = long_be(0x0a28000a);
	s.pool_end = long_be(0x0a2800ff);


	pico_dhcp_server_initiate(&s);

	printf("going into pico loop!\n");
	while(1) {
		pico_stack_tick();
		usleep(2000);
	}
}

