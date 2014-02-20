/* PicoTCP Test application */

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
#include "pico_nat.h"
#include "pico_icmp4.h"
#include "pico_dns_client.h"
#include "pico_dev_loop.h"
#include "pico_dhcp_client.h"
#include "pico_dhcp_server.h"
#include "pico_ipfilter.h"
#include "pico_http_client.h"
#include "pico_http_server.h"
#include "pico_http_util.h"
#include "pico_zmq.h"
#include "pico_olsr.h"
#include "pico_slaacv4.h"

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

static struct pico_ip4 ZERO_IP4 = {
    0
};

/* #define INFINITE_TCPTEST */
#define picoapp_dbg(...) do {} while(0)
/* #define picoapp_dbg printf */

/* #define PICOAPP_IPFILTER 1 */

struct pico_ip4 inaddr_any = {
    0
};

static char *cpy_arg(char **dst, char *str);

/*** START HTTP server ***/
#define SIZE 4 * 1024

void serverWakeup(uint16_t ev, uint16_t conn)
{
    static FILE *f;
    char buffer[SIZE];

    if(ev & EV_HTTP_CON)
    {
        printf("New connection received....\n");
        pico_http_server_accept();
    }

    if(ev & EV_HTTP_REQ) /* new header received */
    {
        int read;
        char *resource;
        int method;
        printf("Header request was received...\n");
        printf("> Resource : %s\n", pico_http_getResource(conn));
        resource = pico_http_getResource(conn);
        method = pico_http_getMethod(conn);

        if(strcmp(resource, "/") == 0 || strcmp(resource, "index.html") == 0 || strcmp(resource, "/index.html") == 0)
        {
            if(method == HTTP_METHOD_GET)
            {
                /* Accepting request */
                printf("Received GET request\n");
                pico_http_respond(conn, HTTP_RESOURCE_FOUND);
                f = fopen("test/examples/form.html", "r");

                if(!f)
                {
                    fprintf(stderr, "Unable to open the file /test/examples/index.html\n");
                    exit(1);
                }

                read = fread(buffer, 1, SIZE, f);
                pico_http_submitData(conn, buffer, read);
            }
            else if(method == HTTP_METHOD_POST)
            {
                int len;
                printf("Received POST request\n");
                printf("Form fields: %s\n", pico_http_getBody(conn));
                len = pico_http_respond(conn, HTTP_RESOURCE_FOUND);
                /* printf("%d bytes written\n", len); */
                strcpy(buffer, "Thanks for posting your data");
                if(pico_http_submitData(conn, buffer, strlen(buffer)) == HTTP_RETURN_ERROR)
                {
                    printf("error submitting data\n");
                }
                else
                {
                    printf("data submitted correctly\n");
                }
            }
        }
        else
        { /* reject */
            printf("Rejected connection...\n");
            pico_http_respond(conn, HTTP_RESOURCE_NOT_FOUND);
        }

    }

    if(ev & EV_HTTP_PROGRESS) /* submitted data was sent */
    {
        uint16_t sent, total;
        pico_http_getProgress(conn, &sent, &total);
        printf("Chunk statistics : %d/%d sent\n", sent, total);
    }

    if(ev & EV_HTTP_SENT) /* submitted data was fully sent */
    {
        int method;
        method = pico_http_getMethod(conn);
        if(method == HTTP_METHOD_GET)
        {
            int read;
            read = fread(buffer, 1, SIZE, f);
            printf("Chunk was sent...\n");
            if(read > 0)
            {
                printf("Sending another chunk...\n");
                pico_http_submitData(conn, buffer, read);
            }
            else
            {
                printf("Last chunk get !\n");
                pico_http_submitData(conn, NULL, 0); /* send the final chunk */
                fclose(f);
            }
        }
        else if(method == HTTP_METHOD_POST)
        {
            printf("Last chunk post !\n");
            pico_http_submitData(conn, NULL, 0); /* send the final chunk */
        }
    }

    if(ev & EV_HTTP_CLOSE)
    {
        printf("Close request...\n");
        pico_http_close(conn);
    }

    if(ev & EV_HTTP_ERROR)
    {
        printf("Error on server...\n");
        pico_http_close(conn);
    }

    /* printf("end of wakeup (%d)\n", ev); */
}
/* END HTTP server */

#define NXT_MAC(x) ++ x[5]

/* Copy a string until the separator,
   terminate it and return the next index,
   or NULL if it encounters a EOS */
static char *cpy_arg(char **dst, char *str)
{
    char *p, *nxt = NULL;
    char *start = str;
    char *end = start + strlen(start);
    p = str;
    while (p) {
        if ((*p == ':') || (*p == '\0')) {
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

int main(int argc, char **argv)
{
    unsigned char macaddr[6] = {
        0, 0, 0, 0xa, 0xb, 0x0
    };
    uint16_t *macaddr_low = (uint16_t *) (macaddr + 2);
    struct pico_device *dev = NULL;

    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"vde", 1, 0, 'v'},
        {"barevde", 1, 0, 'b'},
        {"tun", 1, 0, 't'},
        {"route", 1, 0, 'r'},
        {"app", 1, 0, 'a'},
        {"loop", 0, 0, 'l'},
        {0, 0, 0, 0}
    };
    int option_idx = 0;
    int c;

    *macaddr_low ^= getpid();
    printf("My macaddr base is: %02x %02x\n", macaddr[2], macaddr[3]);

    pico_stack_init();
    /* Parse args */
    while(1) {
        c = getopt_long(argc, argv, "v:b:t:a:r:hl", long_options, &option_idx);
        if (c < 0)
            break;

        switch(c) {
        case 'v':
        {
            char *nxt, *name = NULL, *sock = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
            struct pico_ip4 ipaddr, netmask, gateway, zero = ZERO_IP4;
            printf("+++ OPTARG %s\n", optarg);
            do {
                nxt = cpy_arg(&name, optarg);
                if (!nxt) break;

                nxt = cpy_arg(&sock, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&addr, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&nm, nxt);
                if (!nxt) break;

                nxt = cpy_arg(&gw, nxt);
            } while(0);
            if (!nm) {
                fprintf(stderr, "Vde: bad configuration...\n");
                exit(1);
            }

            dev = pico_vde_create(sock, name, macaddr);
            NXT_MAC(macaddr);
            if (!dev) {
                perror("Creating vde");
                exit(1);
            }

            printf("Vde created.\n");
            pico_string_to_ipv4(addr, &ipaddr.addr);
            pico_string_to_ipv4(nm, &netmask.addr);
            pico_ipv4_link_add(dev, ipaddr, netmask);
            /* bcastAddr.addr = (ipaddr.addr) | (~netmask.addr); */
            if (gw && *gw) {
                pico_string_to_ipv4(gw, &gateway.addr);
                pico_ipv4_route_add(zero, zero, gateway, 1, NULL);
            }
        }
        break;
        }
    }
    if( pico_http_server_start(0, serverWakeup) < 0)
    {
        fprintf(stderr, "Unable to start the HTTP server on port 80\n");
    } else {
        printf("HTTP server started\n");
    }

    printf("%s: launching PicoTCP loop\n", __FUNCTION__);
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
