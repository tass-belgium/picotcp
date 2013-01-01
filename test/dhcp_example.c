
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
#include "pico_socket.h"




static int dhcp_finished = 0;
void callback(void* cli, int code){
	dhcp_finished = 1;
	printf("callback happened!\n");
}


int main(void)
{

  unsigned char macaddr0[6] = {0,0,0x0,0xa,0x0,0x0};
  struct pico_device *vde0;
	void* cookie;

  struct pico_socket *sk_udp;
  uint16_t port = short_be(6666);
	struct pico_ip4 address, gateway;

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
		pico_stack_tick();
		usleep(2000);

		if(dhcp_finished==1){
			//we should have an IP by now...

			sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
			if (!sk_udp){
				printf("failed to open socket\n");
				return 2;
			}

			address = pico_dhcp_get_address(cookie);
			gateway = pico_dhcp_get_gateway(cookie);
			if (pico_socket_bind(sk_udp, &address, &port)!= 0){
				printf("failed to bind socket\n");
				return 1;
			}

			if (pico_socket_connect(sk_udp, &gateway, port)!=0)
				return 3;

			pico_socket_sendto(sk_udp, "dhcp must've worked!", 20, &gateway, port);
			dhcp_finished = 2;
		}
	}
}

