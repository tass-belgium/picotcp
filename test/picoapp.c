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
#include "pico_dev_radiotest.h"
#include "pico_dev_radio_mgr.h"

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

void app_tcpecho(char *args);
void app_noop(void);

struct pico_ip4 ZERO_IP4 = {
    0
};

struct pico_ip_mreq ZERO_MREQ = {
    .mcast_group_addr = {{0}},
    .mcast_link_addr  = {{0}}
};
struct pico_ip_mreq_source ZERO_MREQ_SRC = {
    .mcast_group_addr.ip4  = {0},
    .mcast_link_addr.ip4   = {0},
    .mcast_source_addr.ip4 = {0}
};
struct pico_ip6 ZERO_IP6 = {
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
struct pico_ip_mreq ZERO_MREQ_IP6 = {
    .mcast_group_addr.ip6 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }},
    .mcast_link_addr.ip6  = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}
};
struct pico_ip_mreq_source ZERO_MREQ_SRC_IP6 = {
    .mcast_group_addr.ip6 =  {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }},
    .mcast_link_addr.ip6 =   {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }},
    .mcast_source_addr.ip6 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}
};

/* #define INFINITE_TCPTEST */
/* #define picoapp_dbg(...) do {} while(0) */
#define picoapp_dbg printf

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
    struct pico_device *dev = NULL;
    struct pico_ip4 addr4 = {
        0
    };
    struct pico_ip4 bcastAddr = ZERO_IP4;

    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"tap", 1, 0, 'T'},
        {"app", 1, 0, 'a'},
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

    pico_stack_init();
    /* Parse args */
    while(1) {
        c = getopt_long(argc, argv, "6:v:b:t:T:a:r:hl", long_options, &option_idx);
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
                fprintf(stderr, "Tap: bad configuration...\n");
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
        }
        break;
        case 'a':
        {
            char *name = NULL, *args = NULL;
            printf("+++ OPTARG %s\n", optarg);
            args = cpy_arg(&name, optarg);

            printf("+++ NAME: %s ARGS: %s\n", name, args);
            IF_APPNAME("tcpecho") {
                app_tcpecho(args);
            } else IF_APPNAME("noop") {
                app_noop();
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
        usleep(200);
    }
}
