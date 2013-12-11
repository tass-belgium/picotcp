
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
#include "pico_simple_http.h"

int main(void)
{
    unsigned char macaddr0[6] = {
        0, 0, 0, 0xa, 0xb, 0xc
    };
    struct pico_device *vde0;
    struct pico_ip4 address0, netmask0;

    pico_stack_init();
    printf("Started application....\n");
    pico_string_to_ipv4("192.168.24.4", &address0.addr);
    pico_string_to_ipv4("255.255.255.0", &netmask0.addr);

    /* vde0 = pico_tun_create("tup1"); */
    vde0 = pico_vde_create("/tmp/switch", "vde0", macaddr0);
    if (!vde0)
    {
        printf("Failed to create tun !\n");
        return 1;
    }

    pico_ipv4_link_add(vde0, address0, netmask0);

    if(pico_startHttpServer(&address0))
    {
        printf("Failed to create http server !\n");
        return 1;
    }

    printf("The stack is ticking....\n");
    printf("You can open http://192.168.24.4 now\n");
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
    return 0;

}
