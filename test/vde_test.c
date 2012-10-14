#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

void wakeup(struct pico_socket *s)
{
  char buf[30];
  int r;
  printf("Called wakeup\n");
  r = pico_socket_read(s, buf, 30);
  printf("Receive: %d\n", r);
  if (r > 0) {
    buf[r] = 0;
    printf("%s\n", buf);
  }
  
}


int main(void)
{
  unsigned char macaddr0[6] = {0,0,0,0xa,0xb,0xc};
  unsigned char macaddr1[6] = {0,0,0,0xa,0xb,0xd};
  struct pico_device *vde0, *vde1;
  struct pico_ip4 address0, netmask0, address1, netmask1;

  struct pico_socket *sk;
  uint16_t port = short_be(5555);

  pico_stack_init();

  address0.addr = 0x0300280a; //  10.40.0.3
  netmask0.addr = 0x00FFFFFF;

  address1.addr = 0x0300290a; //  10.41.0.3
  netmask1.addr = 0x00FFFFFF;

  vde0 = pico_vde_create("/tmp/pic0.ctl", "vde0", macaddr0);
  if (!vde0)
    return 1;

  vde1 = pico_vde_create("/tmp/pic1.ctl", "vde1", macaddr1);
  if (!vde1)
    return 1;

  pico_ipv4_link_add(vde0, address0, netmask0);
  pico_ipv4_link_add(vde1, address1, netmask1);

  sk = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
  if (!sk)
    return 2;

  if (pico_socket_bind(sk, &address0, &port)!= 0)
    return 1;

  

  while(1) {
    pico_stack_tick();
    usleep(1000);
  }

  return 0;

}


