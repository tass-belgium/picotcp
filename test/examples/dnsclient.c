#include <stdint.h>
#include <pico_stack.h>
#include <pico_dns_client.h>
#include "utils.h"
extern int IPV6_MODE;

/*** START UDP DNS CLIENT ***/
/*
   ./test/vde_sock_start.sh
   echo 1 > /proc/sys/net/ipv4/ip_forward
   iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
   iptables -A FORWARD -i pic0 -o wlan0 -j ACCEPT
   iptables -A FORWARD -i wlan0 -o pic0 -j ACCEPT
   ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0:10.40.0.1: -a udpdnsclient:www.google.be:173.194.67.94
 */
void cb_udpdnsclient_getaddr(char *ip, void *arg)
{
    uint8_t *id = (uint8_t *) arg;

    if (!ip) {
        picoapp_dbg("%s: ERROR occured! (id: %u)\n", __FUNCTION__, *id);
        return;
    }

    picoapp_dbg("%s: ip %s (id: %u)\n", __FUNCTION__, ip, *id);
    if (arg)
        PICO_FREE(arg);
}

void cb_udpdnsclient_getname(char *name, void *arg)
{
    uint8_t *id = (uint8_t *) arg;

    if (!name) {
        picoapp_dbg("%s: ERROR occured! (id: %u)\n", __FUNCTION__, *id);
        return;
    }

    picoapp_dbg("%s: name %s (id: %u)\n", __FUNCTION__, name, *id);
    if (arg)
        PICO_FREE(arg);
}

void app_udpdnsclient(char *arg)
{
    struct pico_ip4 nameserver;
    char *dname, *daddr;
    char *nxt;
    char *ipver;
    int v = 4;
    uint8_t *getaddr_id, *getname_id, *getaddr6_id, *getname6_id;

    nxt = cpy_arg(&dname, arg);
    if (!dname || !nxt) {
        picoapp_dbg(" udpdnsclient expects the following format: udpdnsclient:dest_name:dest_ip:[ipv6]\n");
        exit(255);
    }

    nxt = cpy_arg(&daddr, nxt);
    if (!daddr || !nxt) {
        picoapp_dbg(" udpdnsclient expects the following format: udpdnsclient:dest_name:dest_ip:[ipv6]\n");
        exit(255);
    }

    nxt = cpy_arg(&ipver, nxt);
    if (!ipver || strcmp("ipv6", ipver) != 0)
        v = 4;
    else
        v = 6;

    picoapp_dbg("UDP DNS client started.\n");

    picoapp_dbg("----- Deleting non existant nameserver -----\n");
    pico_string_to_ipv4("127.0.0.1", &nameserver.addr);
    pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_DEL);
    picoapp_dbg("----- Adding 8.8.8.8 nameserver -----\n");
    pico_string_to_ipv4("8.8.8.8", &nameserver.addr);
    pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_ADD);
    picoapp_dbg("----- Deleting 8.8.8.8 nameserver -----\n");
    pico_string_to_ipv4("8.8.8.8", &nameserver.addr);
    pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_DEL);
    picoapp_dbg("----- Adding 8.8.8.8 nameserver -----\n");
    pico_string_to_ipv4("8.8.8.8", &nameserver.addr);
    pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_ADD);
    picoapp_dbg("----- Adding 8.8.4.4 nameserver -----\n");
    pico_string_to_ipv4("8.8.4.4", &nameserver.addr);
    pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_ADD);
    if (!IPV6_MODE) {
        if (v == 4) {
            picoapp_dbg("Mode: IPv4\n");
            getaddr_id = calloc(1, sizeof(uint8_t));
            *getaddr_id = 1;
            picoapp_dbg(">>>>> DNS GET ADDR OF %s\n", dname);
            pico_dns_client_getaddr(dname, &cb_udpdnsclient_getaddr, getaddr_id);

            getname_id = calloc(1, sizeof(uint8_t));
            *getname_id = 2;
            picoapp_dbg(">>>>> DNS GET NAME OF %s\n", daddr);
            pico_dns_client_getname(daddr, &cb_udpdnsclient_getname, getname_id);
            return;
        }

        picoapp_dbg("Mode: IPv6\n");

#ifdef PICO_SUPPORT_IPV6
        getaddr6_id = calloc(1, sizeof(uint8_t));
        *getaddr6_id = 3;
        picoapp_dbg(">>>>> DNS GET ADDR6 OF %s\n", dname);
        pico_dns_client_getaddr6(dname, &cb_udpdnsclient_getaddr, getaddr6_id);
        getname6_id = calloc(1, sizeof(uint8_t));
        *getname6_id = 4;
        picoapp_dbg(">>>>> DNS GET NAME OF ipv6 addr 2a00:1450:400c:c06::64\n");
        pico_dns_client_getname6("2a00:1450:400c:c06::64", &cb_udpdnsclient_getname, getname6_id);
#endif
    }

    return;
}
/*** END UDP DNS CLIENT ***/
