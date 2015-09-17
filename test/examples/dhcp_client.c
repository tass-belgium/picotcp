#include "utils.h"
#include <pico_ipv4.h>
#include <pico_dhcp_client.h>
#include <pico_socket.h>
#include <pico_icmp4.h>
#include <pico_device.h>
/*** START DHCP Client ***/
#ifdef PICO_SUPPORT_DHCPC
    
/* This must stay global, its lifetime is the same as the dhcp negotiation */
uint32_t dhcpclient_xid;


static uint8_t dhcpclient_devices = 0;

void ping_callback_dhcpclient(struct pico_icmp4_stats *s)
{
    char host[30] = { };

    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("DHCP client: %lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n",
            s->size, host, s->seq, (long unsigned int)s->time);
        if (s->seq >= 3) {
            dbg("DHCP client: TEST SUCCESS!\n");
            if (--dhcpclient_devices <= 0)
                exit(0);
        }
    } else {
        dbg("DHCP client: ping %lu to %s error %d\n", s->seq, host, s->err);
        dbg("DHCP client: TEST FAILED!\n");
        exit(1);
    }
}

void callback_dhcpclient(void *arg, int code)
{
    struct pico_ip4 address = ZERO_IP4, gateway = ZERO_IP4;
    char s_address[16] = { }, s_gateway[16] = { };

    printf("DHCP client: callback happened with code %d!\n", code);
    if (code == PICO_DHCP_SUCCESS) {
        address = pico_dhcp_get_address(arg);
        gateway = pico_dhcp_get_gateway(arg);
        pico_ipv4_to_string(s_address, address.addr);
        pico_ipv4_to_string(s_gateway, gateway.addr);
        printf("DHCP client: got IP %s assigned with cli %p\n", s_address, arg);
#ifdef PICO_SUPPORT_PING
        pico_icmp4_ping(s_gateway, 3, 1000, 5000, 32, ping_callback_dhcpclient);
        /* optional test to check routing when links get added and deleted */
        /* do {
           char *new_arg = NULL, *p = NULL;
           new_arg = calloc(1, strlen(s_address) + strlen(":224.7.7.7:6667:6667") + 1);
           p = strcat(new_arg, s_address);
           p = strcat(p + strlen(s_address), ":224.7.7.7:6667:6667");
           app_mcastsend(new_arg);
           } while (0);
         */
#endif
    }
}

void app_dhcp_client(char *arg)
{
    char *sdev = NULL;
    char *nxt = arg;
    struct pico_device *dev = NULL;

    if (!nxt)
        goto out;

    while (nxt) {
        if (nxt) {
            nxt = cpy_arg(&sdev, nxt);
            if(!sdev) {
                goto out;
            }
        }

        dev = pico_get_device(sdev);
        if(dev == NULL) {
            printf("%s: error getting device %s: %s\n", __FUNCTION__, dev->name, strerror(pico_err));
            exit(255);
        }

        printf("Starting negotiation\n");

        if (pico_dhcp_initiate_negotiation(dev, &callback_dhcpclient, &dhcpclient_xid) < 0) {
            printf("%s: error initiating negotiation: %s\n", __FUNCTION__, strerror(pico_err));
            exit(255);
        }

        dhcpclient_devices++;
    }
    return;

out:
    fprintf(stderr, "dhcpclient expects the following format: dhcpclient:dev_name:[dev_name]\n");
    exit(255);
}
#endif
/*** END DHCP Client ***/
