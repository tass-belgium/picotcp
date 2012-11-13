#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

static int connected = 0;

void wakeup(uint16_t ev, struct pico_socket *s)
{
  char buf[30];
  int r;
  uint32_t peer;
  uint16_t port;

  printf("Called wakeup\n");
  if (ev == PICO_SOCK_EV_RD) { 
    do {
      r = pico_socket_recvfrom(s, buf, 30, &peer, &port);
      printf("------------------------------------- Receive: %d\n", r);
      if (r > 0) {
        pico_socket_write(s, buf, r);
      }
    } while(r>0);
  }
  if (ev == PICO_SOCK_EV_CONN) { 
    if (connected) {
      printf("Error: already connected.\n");
    } else {
      printf("Connection established.\n");
      connected = 1;
    }
  }
}

int main(void)
{
  unsigned char macaddr0[6] = {0,0,0,0xa,0xb,0xc};
  struct pico_device *vde0;
  struct pico_ip4 address0, netmask0, address1;

  struct pico_socket *sk_udp, *sk_tcp;
  uint16_t port = short_be(5555);

  pico_stack_init();

  address0.addr = 0x0300280a; //  10.40.0.3
  netmask0.addr = 0x00FFFFFF;

  address1.addr = 0x0100200a; //  10.40.0.1

  vde0 = pico_tun_create("tup0");
  if (!vde0)
    return 1;

  pico_ipv4_link_add(vde0, address0, netmask0);

  sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
  if (!sk_udp)
    return 2;

  if (pico_socket_bind(sk_udp, &address0, &port)!= 0)
    return 1;

  sk_tcp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &wakeup);
  if (!sk_tcp)
    return 2;

  if (pico_socket_bind(sk_tcp, &address0, &port)!= 0)
    return 1;

  sleep(10);

  if (pico_socket_connect(sk_tcp, &address1, port)!=0)
    return 3;

  while(1) {
    pico_stack_tick();
    usleep(2000);
  }

  return 0;

}


