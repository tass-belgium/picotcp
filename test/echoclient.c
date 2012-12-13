#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"

static int connected = 0;

void wakeup(uint16_t ev, struct pico_socket *s)
{
  char buf[30];
  int r=0, ret=0;
  uint32_t peer;
  uint16_t port;

  printf("Called wakeup\n");
  if (ev == PICO_SOCK_EV_RD) { 
    do {
      r = pico_socket_recvfrom(s, buf, 30, &peer, &port);
      printf("------------------------------------- Receive: %d\n", r);
      if (r > 0) {
        //printf("msg = %s\n",buf);
        ret = pico_socket_write(s, buf, r);
        if (ret < 0)
          printf("pico_err - socket_write : %d\n",pico_err);
      } 
      /*else {
        sprintf(buf,"TEST CALLBACK");
        ret = pico_socket_write(s, buf, sizeof("TEST CALLBACK"));
        if (ret < 0)
          printf("pico_err - socket_write : %d\n",pico_err); 
      }*/
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
  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(0);
  }
}

int main(void)
{
  //unsigned char macaddr0[6] = {0,0,0,0xa,0xb,0xc};
  struct pico_device *vde0;
  struct pico_ip4 address0, netmask0, address1;

  struct pico_socket *sk_udp, *sk_tcp;
  uint16_t port = short_be(5555);

  pico_stack_init();

  address0.addr = long_be(0x0a280003); //  10.40.0.3
  netmask0.addr = long_be(0xFFFFFF00);

  address1.addr = long_be(0x0a280001); //  10.40.0.1

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
  
  printf("sleep 10\n");
  sleep(10);
  printf("end sleep\n");

  if (pico_socket_connect(sk_tcp, &address1, port)!=0)
    return 3;

  while(1) {
    pico_stack_tick();
    usleep(2000);
  }

  return 0;

}


