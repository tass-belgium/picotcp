#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"


int main(void)
{
  unsigned char macaddr0[6] = {0,0,0,0xa,0xb,0xc};
  unsigned char macaddr1[6] = {0,0,0,0xa,0xb,0xd};
  struct pico_device *vde0, *vde1;
  struct pico_ip4 address0, netmask0, address1, netmask1;

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

  while(1) {
    pico_stack_tick();
    usleep(1000);
  }

  return 0;

}


