#include "pico_defines.h"
#include "pico_stack.h"
#include "pico_jobs.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dev_tap.h"



int main(void)
{
    long long interval = 0;
    char ipaddr[]="192.168.2.150";
    struct pico_ip4 my_eth_addr, netmask;
    struct pico_device *tap;

    uint8_t mac[6] = {0x00,0x00,0x00,0x12,0x34,0x56};
    struct pico_ip6 my_addr6, netmask6;

    pico_stack_init();

    tap = (struct pico_device *) pico_tap_create("tap0");
    if (!tap)
        while (1);

    pico_string_to_ipv4(ipaddr, &my_eth_addr.addr);
    pico_string_to_ipv4("255.255.255.0", &netmask.addr);
    pico_string_to_ipv6("3ffe:501:ffff:100:260:37ff:fe12:3456", my_addr6.addr);
    pico_string_to_ipv6("ffff:ffff:ffff:ffff::0", netmask6.addr);
    pico_ipv4_link_add(tap, my_eth_addr, netmask);
    pico_ipv6_link_add(tap, my_addr6, netmask6);

    while(1) {
        interval = pico_stack_go();
        if (interval > 0) {
            pico_tap_WFI(tap, interval);
        }
    }

}
