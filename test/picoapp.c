/* PicoTCP Test application */
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
#include "pico_dev_tap.h"
#include "pico_nat.h"
#include "pico_icmp4.h"
#include "pico_icmp6.h"
#include "pico_dns_client.h"
#include "pico_dev_loop.h"
#include "pico_dhcp_client.h"
#include "pico_dhcp_server.h"
#include "pico_ipfilter.h"
#include "pico_olsr.h"
#include "pico_sntp_client.h"
#include "pico_mdns.h"
#include "pico_tftp.h"

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#ifdef FAULTY
#include "pico_faulty.h"
#endif

void app_udpecho(char *args);
void app_tcpecho(char *args);
void app_udpclient(char *args);
void app_tcpclient(char *args);
void app_tcpbench(char *args);
void app_natbox(char *args);
void app_udpdnsclient(char *args);
void app_udpnatclient(char *args);
void app_mcastsend(char *args);
void app_mcastreceive_ipv6(char *args);
void app_mcastsend_ipv6(char *args);
void app_mcastreceive(char *args);
void app_ping(char *args);
void app_dhcp_server(char *args);
void app_dhcp_client(char *args);
void app_dns_sd(char *arg, struct pico_ip4 addr);
void app_mdns(char *arg, struct pico_ip4 addr);
void app_sntp(char *args);
void app_tftp(char *args);
void app_slaacv4(char *args);
void app_udpecho(char *args);
void app_sendto_test(char *args);
void app_noop(void);

struct pico_ip4 ZERO_IP4 = {
    0
};
struct pico_ip_mreq ZERO_MREQ = {
    .mcast_group_addr = {0}, .mcast_link_addr = {0}
};
struct pico_ip_mreq_source ZERO_MREQ_SRC = { {0}, {0}, {0} };
struct pico_ip6 ZERO_IP6 = {
 { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }   
};
struct pico_ip_mreq ZERO_MREQ_IP6 = {
    .mcast_group_addr.ip6 =  {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }} ,
    .mcast_link_addr.ip6 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }} 
};
struct pico_ip_mreq_source ZERO_MREQ_SRC_IP6 = {  
    .mcast_group_addr.ip6 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }} ,
    .mcast_link_addr.ip6 =  {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }} ,
    .mcast_source_addr.ip6 ={{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }} };

/* #define INFINITE_TCPTEST */
#define picoapp_dbg(...) do {} while(0)
/* #define picoapp_dbg printf */

/* #define PICOAPP_IPFILTER 1 */

int IPV6_MODE;


struct pico_ip4 inaddr_any = {
    0
};
struct pico_ip6 inaddr6_any = {{0}};

char *cpy_arg(char **dst, char *str);

void deferred_exit(pico_time __attribute__((unused)) now, void *arg)
{
    if (arg) {
        free(arg);
        arg = NULL;
    }

    printf("%s: quitting\n", __FUNCTION__);
    exit(0);
}



/** From now on, parsing the command line **/
#define NXT_MAC(x) ++ x[5]

/* Copy a string until the separator,
   terminate it and return the next index,
   or NULL if it encounters a EOS */
char *cpy_arg(char **dst, char *str)
{
    char *p, *nxt = NULL;
    char *start = str;
    char *end = start + strlen(start);
    char sep = ':';

    if (IPV6_MODE)
        sep = ',';

    p = str;
    while (p) {
        if ((*p == sep) || (*p == '\0')) {
            *p = (char)0;
            nxt = p + 1;
            if ((*nxt == 0) || (nxt >= end))
                nxt = 0;

            printf("dup'ing %s\n", start);
            *dst = strdup(start);
            break;
        }

        p++;
    }
    return nxt;
}

static void __wakeup(uint16_t __attribute__((unused)) ev, struct pico_socket __attribute__((unused)) *s)
{

}


static void usage(char *arg0)
{
    printf("Usage: %s [--vde name:sock:address:netmask[:gateway]] [--vde ...] [--tun name:address:netmask[:gateway]] [--tun ...] [--app name[:args]]\n\n\n", arg0);
    printf("\tall arguments can be repeated, e.g. to run on multiple links or applications\n");
    printf("\t* --app arguments must be at the end  *\n");
    exit(255);
}

#define IF_APPNAME(x) if(strcmp(x, name) == 0)

int main(int argc, char **argv)
{
    unsigned char macaddr[6] = {
        0, 0, 0, 0xa, 0xb, 0x0
    };
    uint16_t *macaddr_low = (uint16_t *) (macaddr + 2);
    struct pico_device *dev = NULL;
    struct pico_ip4 addr4 = {
        0
    };
    struct pico_ip4 bcastAddr = ZERO_IP4;

    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"vde", 1, 0, 'v'},
        {"barevde", 1, 0, 'b'},
        {"tun", 1, 0, 't'},
        {"tap", 1, 0, 'T'},
        {"route", 1, 0, 'r'},
        {"app", 1, 0, 'a'},
        {"dns", 1, 0, 'd'},
        {"loop", 0, 0, 'l'},
        {0, 0, 0, 0}
    };
    int option_idx = 0;
    int c;
    char *app = NULL, *p = argv[0];
    /* parse till we find the name of the executable */
    while (p) {
        if (*p == '/')
            app = p + 1;
        else if (*p == '\0')
            break;
        else
        {} /* do nothing */

        p++;
    }
    if (strcmp(app, "picoapp6.elf") == 0)
        IPV6_MODE = 1;

    *macaddr_low = (uint16_t)(*macaddr_low ^ (uint16_t)((uint16_t)getpid() & (uint16_t)0xFFFFU));
    printf("My macaddr base is: %02x %02x\n", macaddr[2], macaddr[3]);
    printf("My macaddr is: %02x %02x %02x %02x %02x %02x\n", macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

#ifdef PICO_SUPPORT_MM
    pico_mem_init(128 * 1024);
#endif
    pico_stack_init();
    /* Parse args */
    while(1) {
        c = getopt_long(argc, argv, "v:b:t:T:a:r:hl", long_options, &option_idx);
        if (c < 0)
            break;

        switch(c) {
        case 'h':
            usage(argv[0]);
            break;
        case 'T':
        {
            char *nxt, *name = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
            struct pico_ip4 ipaddr, netmask, gateway, zero = ZERO_IP4;
            do {
                nxt = cpy_arg(&name, optarg);
                if (!nxt) break;

                nxt = cpy_arg(&addr, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&nm, nxt);
                if (!nxt) break;

                cpy_arg(&gw, nxt);
            } while(0);
            if (!nm) {
                fprintf(stderr, "Tun: bad configuration...\n");
                exit(1);
            }

            dev = pico_tap_create(name);
            if (!dev) {
                perror("Creating tap");
                exit(1);
            }

            pico_string_to_ipv4(addr, &ipaddr.addr);
            pico_string_to_ipv4(nm, &netmask.addr);
            pico_ipv4_link_add(dev, ipaddr, netmask);
            bcastAddr.addr = (ipaddr.addr) | (~netmask.addr);
            if (gw && *gw) {
                pico_string_to_ipv4(gw, &gateway.addr);
                printf("Adding default route via %08x\n", gateway.addr);
                pico_ipv4_route_add(zero, zero, gateway, 1, NULL);
            }

#ifdef PICO_SUPPORT_IPV6
            if (IPV6_MODE) {
                struct pico_ip6 ipaddr6 = {{0}}, netmask6 = {{0}}, gateway6 = {{0}}, zero6 = {{0}};
                pico_string_to_ipv6(addr, ipaddr6.addr);
                pico_string_to_ipv6(nm, netmask6.addr);
                pico_ipv6_link_add(dev, ipaddr6, netmask6);
                if (gw && *gw) {
                    pico_string_to_ipv6(gw, gateway6.addr);
                    pico_ipv6_route_add(zero6, zero6, gateway6, 1, NULL);
                }

                pico_ipv6_dev_routing_enable(dev);
            }

#endif
        }
        break;
        case 't':
        {
            char *nxt, *name = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
            struct pico_ip4 ipaddr, netmask, gateway, zero = ZERO_IP4;
            do {
                nxt = cpy_arg(&name, optarg);
                if (!nxt) break;

                nxt = cpy_arg(&addr, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&nm, nxt);
                if (!nxt) break;

                cpy_arg(&gw, nxt);
            } while(0);
            if (!nm) {
                fprintf(stderr, "Tun: bad configuration...\n");
                exit(1);
            }

            dev = pico_tun_create(name);
            if (!dev) {
                perror("Creating tun");
                exit(1);
            }

            pico_string_to_ipv4(addr, &ipaddr.addr);
            pico_string_to_ipv4(nm, &netmask.addr);
            pico_ipv4_link_add(dev, ipaddr, netmask);
            bcastAddr.addr = (ipaddr.addr) | (~netmask.addr);
            if (gw && *gw) {
                pico_string_to_ipv4(gw, &gateway.addr);
                printf("Adding default route via %08x\n", gateway.addr);
                pico_ipv4_route_add(zero, zero, gateway, 1, NULL);
            }

#ifdef PICO_SUPPORT_IPV6
            if (IPV6_MODE) {
                struct pico_ip6 ipaddr6 = {{0}}, netmask6 = {{0}}, gateway6 = {{0}}, zero6 = {{0}};
                pico_string_to_ipv6(addr, ipaddr6.addr);
                pico_string_to_ipv6(nm, netmask6.addr);
                pico_ipv6_link_add(dev, ipaddr6, netmask6);
                if (gw && *gw) {
                    pico_string_to_ipv6(gw, gateway6.addr);
                    pico_ipv6_route_add(zero6, zero6, gateway6, 1, NULL);
                }

                pico_ipv6_dev_routing_enable(dev);
            }

#endif
        }
        break;
        case 'v':
        {
            char *nxt, *name = NULL, *sock = NULL, *addr = NULL, *nm = NULL, *gw = NULL, *addr6 = NULL, *nm6 = NULL, *gw6 = NULL, *loss_in = NULL, *loss_out = NULL;
            struct pico_ip4 ipaddr, netmask, gateway, zero = ZERO_IP4;
            uint32_t i_pc = 0, o_pc = 0;
            printf("+++ OPTARG %s\n", optarg);
            do {
                nxt = cpy_arg(&name, optarg);
                if (!nxt) break;

                nxt = cpy_arg(&sock, nxt);
                if (!nxt) break;

                if (!IPV6_MODE) {
                    nxt = cpy_arg(&addr, nxt);
                    if (!nxt) break;

                    nxt = cpy_arg(&nm, nxt);
                    if (!nxt) break;

                    nxt = cpy_arg(&gw, nxt);
                    if (!nxt) break;

                    nxt = cpy_arg(&loss_in, nxt);
                    if (!nxt) break;

                    nxt = cpy_arg(&loss_out, nxt);
                    if (!nxt) break;
                } else {
                    nxt = cpy_arg(&addr6, nxt);
                    if (!nxt) break;

                    printf("addr6: %s\n", addr6);

                    nxt = cpy_arg(&nm6, nxt);
                    if (!nxt) break;

                    nxt = cpy_arg(&gw6, nxt);
                    if (!nxt) break;

                    nxt = cpy_arg(&loss_in, nxt);
                    if (!nxt) break;

                    nxt = cpy_arg(&loss_out, nxt);
                    if (!nxt) break;
                }
            } while(0);
            if (!nm && !nm6) {
                fprintf(stderr, "Vde: bad configuration...\n");
                exit(1);
            }

            macaddr[4] ^= (uint8_t)(getpid() >> 8);
            macaddr[5] ^= (uint8_t) (getpid() & 0xFF);
            dev = pico_vde_create(sock, name, macaddr);
            NXT_MAC(macaddr);
            if (!dev) {
                perror("Creating vde");
                exit(1);
            }

            printf("Vde created.\n");

            if (!IPV6_MODE) {
                pico_string_to_ipv4(addr, &ipaddr.addr);
                pico_string_to_ipv4(nm, &netmask.addr);
                pico_ipv4_link_add(dev, ipaddr, netmask);
                addr4 = ipaddr;
                bcastAddr.addr = (ipaddr.addr) | (~netmask.addr);
                if (gw && *gw) {
                    pico_string_to_ipv4(gw, &gateway.addr);
                    pico_ipv4_route_add(zero, zero, gateway, 1, NULL);
                }
            }

#ifdef PICO_SUPPORT_IPV6
            if (IPV6_MODE) {
                struct pico_ip6 ipaddr6 = {{0}}, netmask6 = {{0}}, gateway6 = {{0}}, zero6 = {{0}};
                printf("SETTING UP IPV6 ADDRESS\n");
                pico_string_to_ipv6(addr6, ipaddr6.addr);
                pico_string_to_ipv6(nm6, netmask6.addr);
                pico_ipv6_link_add(dev, ipaddr6, netmask6);
                if (gw6 && *gw6) {
                    pico_string_to_ipv6(gw6, gateway6.addr);
                    pico_ipv6_route_add(zero6, zero6, gateway6, 1, NULL);
                }

                pico_ipv6_dev_routing_enable(dev);
            }

#endif
            if (loss_in && (strlen(loss_in) > 0)) {
                i_pc = (uint32_t)atoi(loss_in);
            }

            if (loss_out && (strlen(loss_out) > 0)) {
                o_pc = (uint32_t)atoi(loss_out);
            }

            if (i_pc || o_pc) {
                printf(" ---------- >Setting vde packet loss %u:%u\n", i_pc, o_pc);
                pico_vde_set_packetloss(dev, i_pc, o_pc);
            }


        }
        break;
        case 'b':
        {
            char *nxt, *name = NULL, *sock = NULL;
            printf("+++ OPTARG %s\n", optarg);
            do {
                nxt = cpy_arg(&name, optarg);
                if (!nxt) break;

                nxt = cpy_arg(&sock, nxt);
            } while(0);
            if (!sock) {
                fprintf(stderr, "Vde: bad configuration...\n");
                exit(1);
            }

            macaddr[4] ^= (uint8_t)(getpid() >> 8);
            macaddr[5] ^= (uint8_t)(getpid() & 0xFF);
            dev = pico_vde_create(sock, name, macaddr);
            NXT_MAC(macaddr);
            if (!dev) {
                perror("Creating vde");
                exit(1);
            }

            printf("Vde created.\n");
        }
        break;
        case 'l':
        {
            struct pico_ip4 ipaddr, netmask;

            dev = pico_loop_create();
            if (!dev) {
                perror("Creating loop");
                exit(1);
            }

            pico_string_to_ipv4("127.0.0.1", &ipaddr.addr);
            pico_string_to_ipv4("255.0.0.0", &netmask.addr);
            pico_ipv4_link_add(dev, ipaddr, netmask);
            printf("Loopback created\n");
#ifdef PICO_SUPPORT_IPV6
            if (IPV6_MODE) {
                struct pico_ip6 ipaddr6 = {{0}}, netmask6 = {{0}};
                pico_string_to_ipv6("::1", ipaddr6.addr);
                pico_string_to_ipv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", netmask6.addr);
                pico_ipv6_link_add(dev, ipaddr6, netmask6);
            }

            pico_ipv6_dev_routing_enable(dev);

#endif
        }
        break;
        case 'r':
        {
            char *nxt, *addr, *nm, *gw;
            struct pico_ip4 ipaddr, netmask, gateway;
            /* XXX adjust for IPv6 */
            addr = NULL, nm = NULL, gw = NULL;
            printf("+++ ROUTEOPTARG %s\n", optarg);
            do {
                nxt = cpy_arg(&addr, optarg);
                if (!nxt) break;

                nxt = cpy_arg(&nm, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&gw, nxt);
            } while(0);
            if (!addr || !nm || !gw) {
                fprintf(stderr, "--route expects addr:nm:gw:\n");
                usage(argv[0]);
            }

            pico_string_to_ipv4(addr, &ipaddr.addr);
            pico_string_to_ipv4(nm, &netmask.addr);
            pico_string_to_ipv4(gw, &gateway.addr);
            if (pico_ipv4_route_add(ipaddr, netmask, gateway, 1, NULL) == 0)
                fprintf(stderr, "ROUTE ADDED *** to %s via %s\n", addr, gw);
            else
                fprintf(stderr, "ROUTE ADD: ERROR %s \n", strerror(pico_err));

            break;
        }
        case 'd':
        {
            /* Add a DNS nameserver IP address */
            char *straddr;
            struct pico_ip4 ipaddr;
            printf("DNS nameserver address = %s\n", optarg);
            cpy_arg(&straddr, optarg);
            pico_string_to_ipv4(straddr, &ipaddr.addr);
            pico_dns_client_nameserver(&ipaddr, PICO_DNS_NS_ADD);
            break;
        }
        case 'a':
        {
            char *name = NULL, *args = NULL;
            printf("+++ OPTARG %s\n", optarg);
            args = cpy_arg(&name, optarg);

            printf("+++ NAME: %s ARGS: %s\n", name, args);
            IF_APPNAME("udpecho") {
                app_udpecho(args);
            } else IF_APPNAME("tcpecho") {
                app_tcpecho(args);
            } else IF_APPNAME("udpclient") {
                app_udpclient(args);
            } else IF_APPNAME("tcpclient") {
                app_tcpclient(args);
            } else IF_APPNAME("tcpbench") {
                app_tcpbench(args);
            } else IF_APPNAME("natbox") {
                app_natbox(args);
            } else IF_APPNAME("udpdnsclient") {
                app_udpdnsclient(args);
            } else IF_APPNAME("udpnatclient") {
                app_udpnatclient(args);
            } else IF_APPNAME("mcastsend") {
#ifndef PICO_SUPPORT_MCAST
                return 0;
#endif
                app_mcastsend(args);
            } else IF_APPNAME("mcastreceive") {
#ifndef PICO_SUPPORT_MCAST
                return 0;
#endif
                app_mcastreceive(args);
            }
            else IF_APPNAME("mcastsend_ipv6") {
#ifndef PICO_SUPPORT_MCAST
                return 0;
#endif
                app_mcastsend_ipv6(args);
            } else IF_APPNAME("mcastreceive_ipv6") {
#ifndef PICO_SUPPORT_MCAST
                return 0;
#endif
                app_mcastreceive_ipv6(args);
            }
#ifdef PICO_SUPPORT_PING
            else IF_APPNAME("ping") {
                app_ping(args);
            }
#endif
            else IF_APPNAME("dhcpserver") {
#ifndef PICO_SUPPORT_DHCPD
                return 0;
#else
                app_dhcp_server(args);
#endif
            } else IF_APPNAME("dhcpclient") {
#ifndef PICO_SUPPORT_DHCPC
                return 0;
#else
                app_dhcp_client(args);
#endif
            } else IF_APPNAME("dns_sd") {
#ifndef PICO_SUPPORT_DNS_SD
                return 0;
#else
                app_dns_sd(args, addr4);
#endif
            } else IF_APPNAME("mdns") {
#ifndef PICO_SUPPORT_MDNS
                return 0;
#else
                app_mdns(args, addr4);
#endif
#ifdef PICO_SUPPORT_SNTP_CLIENT
            } else IF_APPNAME("sntp") {
                app_sntp(args);
#endif
            } else IF_APPNAME("bcast") {
                struct pico_ip4 any = {
                    .addr = 0xFFFFFFFFu
                };

                struct pico_socket *s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &__wakeup);
                pico_socket_sendto(s, "abcd", 5u, &any, 1000);

                pico_socket_sendto(s, "abcd", 5u, &bcastAddr, 1000);
#ifdef PICO_SUPPORT_TFTP
            } else IF_APPNAME("tftp") {
                app_tftp(args);
#endif
            } else IF_APPNAME("noop") {
                app_noop();
#ifdef PICO_SUPPORT_OLSR
            } else IF_APPNAME("olsr") {
                dev = pico_get_device("pic0");
                if(dev) {
                    pico_olsr_add(dev);
                }

                dev = pico_get_device("pic1");
                if(dev) {
                    pico_olsr_add(dev);
                }

                app_noop();
#endif
            } else IF_APPNAME("slaacv4") {
#ifndef PICO_SUPPORT_SLAACV4
                return 0;
#else
                app_slaacv4(args);
#endif
            } else IF_APPNAME("udp_sendto_test") {
                app_sendto_test(args);
            } else {
                fprintf(stderr, "Unknown application %s\n", name);
                usage(argv[0]);
            }
        }
        break;
        }
    }
    if (!dev) {
        printf("nodev");
        usage(argv[0]);
    }

#ifdef FAULTY
    atexit(memory_stats);
#endif
    printf("%s: launching PicoTCP loop\n", __FUNCTION__);
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
