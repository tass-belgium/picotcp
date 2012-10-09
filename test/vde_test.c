#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"


int main(void)
{
  unsigned char macaddr[6] = {0,0,0,0xa,0xb,0xc};
  struct pico_device *vde;

  vde = pico_vde_create("/tmp/vde0.ctl", "vde0", macaddr);
  if (!vde)
    return 1;

  pico_stack_loop();

  return 0;

}


