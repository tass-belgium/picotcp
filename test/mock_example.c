#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_mock.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"

//This file will be removed in the future, once the mock device is advanced enough to be used in the unit tests.

void wakeup(uint16_t ev, struct pico_socket *s)
{
  char buf[30];
  int r=0;
  uint32_t peer;
  uint16_t port;

  printf("Called wakeup\n");
  if (ev == PICO_SOCK_EV_RD) { 
    do {
      r = pico_socket_recvfrom(s, buf, 30, &peer, &port);
      printf("------------------------------------- Receive: %d\n", r);
      if (r > 0) {
        printf("msg = %s\n",buf);
      }
    } while(r>0);
  }
  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(0);
  }
  if (ev == PICO_SOCK_EV_CLOSE) {
    printf("Socket received close\n");
  }
  if (ev == PICO_SOCK_EV_FIN) {
    printf("Socket is going to be closed!\n");
  } 
}



int main(void)
{

  unsigned char mac[6] = {0,0,0,0xa,0xb,0xd};

	struct mock_device* mock;
	struct pico_ip4 address = {.addr=long_be(0x0a280004)};
	struct pico_ip4 netmask = {.addr=long_be(0xffffff00)};
	struct pico_ip4 target = {.addr=long_be(0x0a280005)};
  struct pico_socket *sk_udp;
  uint16_t port = short_be(5555);
  uint16_t remote_port = short_be(5555);

	pico_stack_init();

	mock = pico_mock_create(NULL);
	if(!mock)
		return 1;

	pico_ipv4_link_add(mock->dev, address, netmask);

  sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
  if (!sk_udp)
    return 2;

  if (pico_socket_bind(sk_udp, &address, &port)!= 0)
    return 1;

	uint8_t buffer[4] = {0x01, 0x02, 0x03, 0x04};
	uint8_t buffer2[80] = {0x00};
	pico_socket_sendto(sk_udp, buffer, 4, &target, remote_port);

	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	int len = pico_mock_network_read(mock, buffer2, 80);
	printf("length : %d\n",len);

	//TODO : check some of these fields automatically...
	if(mock_get_sender_ip4(mock, buffer2, len) == address.addr){
		printf("great!\n");
	}else{
		printf("not so great!\n");
	}
	int cntr = 0;
	while(cntr < 80){
		printf("0x%02x ",buffer2[cntr]);
		cntr++;
		if(cntr %4 == 0)
			printf(" ");
		if(cntr %8 == 0)
			printf("\n");
	}


	uint8_t buffer3[32] = {0x45, 0x00, 0x00, 0x20,  0x91, 0xc0, 0x40, 0x00,  
												 0x40, 0x11, 0x94, 0xb4,  0x0a, 0x28, 0x00, 0x05,  
												 0x0a, 0x28, 0x00, 0x04,  0x15, 0xb3, 0x15, 0xb3,  
												 0x00, 0x0c, 0x00, 0x00,  'e', 'l', 'l', 'o'};

	pico_mock_network_write(mock,buffer3, 32);
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	return 0;
}
