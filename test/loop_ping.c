#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_loop.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

int main(void)
{
  struct pico_device *loop;
  struct pico_ip4 loaddr, netmask;
  pico_stack_init();

  loaddr.addr   = 0x0100007F; //  10.40.0.3
  netmask.addr = 0x000000FF;

  loop = pico_loop_create();
  if (!loop)
    return 1;

  pico_ipv4_link_add(loop, loaddr, netmask);

  while(1) {
    pico_stack_tick();
//    usleep(2000);
  }

  return 0;

}


