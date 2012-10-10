#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"


int main(void)
{
  unsigned char macaddr[6] = {0,0,0,0xa,0xb,0xc};
  struct pico_device *vde;
  struct pico_ip4 address, netmask;

  pico_stack_init();

  address.addr = 0x0300280a; //  10.40.0.3
  netmask.addr = 0x00FFFFFF;


  vde = pico_vde_create("/tmp/pico.ctl", "vde0", macaddr);
  if (!vde)
    return 1;

  pico_ipv4_link_add(vde, address, netmask);

  pico_stack_loop();

  return 0;

}


