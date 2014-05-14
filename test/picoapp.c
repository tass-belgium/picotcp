/* PicoTCP Test application */

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
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
static struct pico_ip_mreq ZERO_MREQ = {
    .mcast_group_addr = {0}, .mcast_link_addr = {0}
};
static struct pico_ip_mreq_source ZERO_MREQ_SRC = { {0}, {0}, {0} };

/* #define INFINITE_TCPTEST */
#define picoapp_dbg(...) do {} while(0)
/* #define picoapp_dbg printf */

/* #define PICOAPP_IPFILTER 1 */

static int IPV6_MODE;


struct pico_ip4 inaddr_any = { };
struct pico_ip6 inaddr6_any = {{0}};

static char *cpy_arg(char **dst, char *str);

void deferred_exit(pico_time __attribute__((unused)) now, void *arg)
{
    if (arg) {
        free(arg);
        arg = NULL;
    }

    printf("%s: quitting\n", __FUNCTION__);
    exit(0);
}

/*** APPLICATIONS API: ***/
/* To create a new application, define your initialization
 * function and your callback here */


/*** UDP CLIENT ***/
/*
 * udpclient expects the following format: udpclient:dest_addr:sendto_port[:listen_port:datasize:loops:subloops]
 * dest_addr: IP address to send datagrams to
 * sendto_port: port number to send datagrams to
 * listen_port [OPTIONAL]: port number on which the udpclient listens
 * datasize [OPTIONAL]: size of the data given to the socket in one go
 * loops [OPTIONAL]: number of intervals in which data is send
 * subloops [OPTIONAL]: number of sends in one interval
 *
 * REMARK: once an optional parameter is given, all optional parameters need a value!
 *
 * f.e.: ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.255.0: -a udpclient:10.40.0.3:6667:6667:1400:100:10
 */
struct udpclient_pas {
    struct pico_socket *s;
    uint8_t loops;
    uint8_t subloops;
    uint16_t datasize;
    uint16_t sport;
    union pico_address dst;
}; /* per application struct */

static struct udpclient_pas *udpclient_pas;

void udpclient_send(pico_time __attribute__((unused)) now, void __attribute__((unused))  *arg)
{
    struct pico_socket *s = udpclient_pas->s;
    char end[4] = "end";
    char *buf = NULL;
    int i = 0, w = 0;
    static uint16_t loop = 0;

    if (++loop > udpclient_pas->loops) {
        for (i = 0; i < 3; i++) {
            w = pico_socket_send(s, end, 4);
            if (w <= 0)
                break;

            printf("%s: requested exit of echo\n", __FUNCTION__);
        }
        pico_timer_add(1000, deferred_exit, udpclient_pas);
        return;
    } else {
        buf = calloc(1, udpclient_pas->datasize);
        if (!buf) {
            printf("%s: no memory available\n", __FUNCTION__);
            return;
        }

        memset(buf, '1', udpclient_pas->datasize);
        picoapp_dbg("%s: performing loop %u\n", __FUNCTION__, loop);
        for (i = 0; i < udpclient_pas->subloops; i++) {
            w =  pico_socket_send(s, buf, udpclient_pas->datasize);
            if (w <= 0)
                break;
        }
        picoapp_dbg("%s: written %u byte(s) in each of %u subloops\n", __FUNCTION__, udpclient_pas->datasize, i);
        free(buf);
    }

    pico_timer_add(100, udpclient_send, NULL);
}

void cb_udpclient(uint16_t ev, struct pico_socket *s)
{
    char *recvbuf = NULL;
    int r = 0;

    if (ev & PICO_SOCK_EV_RD) {
        recvbuf = calloc(1, udpclient_pas->datasize);
        if (!recvbuf) {
            printf("%s: no memory available\n", __FUNCTION__);
            return;
        }

        do {
            r = pico_socket_recv(s, recvbuf, udpclient_pas->datasize);
        } while ( r > 0);
        free(recvbuf);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        printf("Socket Error received. Bailing out.\n");
        free(udpclient_pas);
        exit(7);
    }
}

void app_udpclient(char *arg)
{
    char *daddr = NULL, *lport = NULL, *sport = NULL, *s_datasize = NULL, *s_loops = NULL, *s_subloops = NULL;
    char *nxt = arg;
    char sinaddr_any[40] = {
        0
    };
    uint16_t listen_port = 0;
    int ret = 0;

    udpclient_pas = calloc(1, sizeof(struct udpclient_pas));
    if (!udpclient_pas) {
        printf("%s: no memory available\n", __FUNCTION__);
        exit(255);
    }

    udpclient_pas->s = NULL;
    udpclient_pas->loops = 100;
    udpclient_pas->subloops = 10;
    udpclient_pas->datasize = 1400;

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&daddr, arg);
        if (daddr) {
            if (!IPV6_MODE)
                pico_string_to_ipv4(daddr, &udpclient_pas->dst.ip4.addr);

      #ifdef PICO_SUPPORT_IPV6
            else
                pico_string_to_ipv6(daddr, udpclient_pas->dst.ip6.addr);
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing dest_addr */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            udpclient_pas->sport = short_be(atoi(sport));
        } else {
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            goto out;
        }
    } else {
        /* missing listen_port, use default */
        listen_port = 0;
    }

    if (nxt) {
        nxt = cpy_arg(&s_datasize, nxt);
        if (s_datasize && atoi(s_datasize)) {
            udpclient_pas->datasize = atoi(s_datasize);
        } else {
            goto out;
        }
    } else {
        /* missing datasize, incomplete optional parameters? -> exit */
        if (lport)
            goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&s_loops, nxt);
        if (s_loops && atoi(s_loops)) {
            udpclient_pas->loops = atoi(s_loops);
        } else {
            goto out;
        }
    } else {
        /* missing loops, incomplete optional parameters? -> exit */
        if (s_datasize)
            goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&s_subloops, nxt);
        if (s_subloops && atoi(s_subloops)) {
            udpclient_pas->subloops = atoi(s_subloops);
        } else {
            goto out;
        }
    } else {
        /* missing subloops, incomplete optional parameters? -> exit */
        if (s_loops)
            goto out;
    }

    /* end of argument parsing */

    if (!IPV6_MODE)
        pico_ipv4_to_string(sinaddr_any, inaddr_any.addr);

  #ifdef PICO_SUPPORT_IPV6
    else
        pico_ipv6_to_string(sinaddr_any, inaddr6_any.addr);
  #endif

    if (!IPV6_MODE)
        udpclient_pas->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpclient);
    else
        udpclient_pas->s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, &cb_udpclient);

    if (!udpclient_pas->s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        free(udpclient_pas);
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_bind(udpclient_pas->s, &inaddr_any, &listen_port);
    else
        ret = pico_socket_bind(udpclient_pas->s, &inaddr6_any, &listen_port);

    if (ret < 0) {
        free(udpclient_pas);
        printf("%s: error binding socket to %s:%u: %s\n", __FUNCTION__, sinaddr_any, short_be(listen_port), strerror(pico_err));
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_connect(udpclient_pas->s, &udpclient_pas->dst.ip4, udpclient_pas->sport);
    else
        ret = pico_socket_connect(udpclient_pas->s, &udpclient_pas->dst.ip6, udpclient_pas->sport);

    if (ret < 0) {
        printf("%s: error connecting to %s:%u: %s\n", __FUNCTION__, daddr, short_be(udpclient_pas->sport), strerror(pico_err));
        free(udpclient_pas);
        exit(1);
    }

    printf("\n%s: UDP client launched. Sending packets of %u bytes in %u loops and %u subloops to %s:%u\n\n",
           __FUNCTION__, udpclient_pas->datasize, udpclient_pas->loops, udpclient_pas->subloops, daddr, short_be(udpclient_pas->sport));

    pico_timer_add(100, udpclient_send, NULL);
    return;

out:
    fprintf(stderr, "udpclient expects the following format: udpclient:dest_addr:dest_port[:listen_port:datasize:loops:subloops]\n");
    free(udpclient_pas);
    exit(255);
}
/*** END UDP CLIENT ***/

/**** UDP ECHO ****/
/*
 * udpecho expects the following format: udpecho:bind_addr:listen_port[:sendto_port:datasize]
 * bind_addr: IP address to bind to
 * listen_port: port number on which the udpecho listens
 * sendto_port [OPTIONAL]: port number to echo datagrams to (echo to originating IP address)
 * datasize [OPTIONAL]: max size of the data red from the socket in one go
 *
 * REMARK: once an optional parameter is given, all optional parameters need a value!
 *
 * f.e.: ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.3:255.255.255.0: -a udpecho:10.40.0.3:6667:6667:1400
 */
static int udpecho_exit = 0;

struct udpecho_pas {
    struct pico_socket *s;
    uint16_t sendto_port; /* big-endian */
    uint16_t datasize;
}; /* per application struct */

static struct udpecho_pas *udpecho_pas;

void cb_udpecho(uint16_t ev, struct pico_socket *s)
{
    char *recvbuf = NULL;
    uint16_t port = 0;
    int r = 0;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } peer;

    if (udpecho_exit)
        return;

    if (ev == PICO_SOCK_EV_RD) {
        recvbuf = calloc(1, udpecho_pas->datasize);
        if (!recvbuf) {
            printf("%s: no memory available\n", __FUNCTION__);
            return;
        }

        do {
            r = pico_socket_recvfrom(s, recvbuf, udpecho_pas->datasize, IPV6_MODE ? (void *)peer.ip6.addr : (void *)&peer.ip4.addr, &port);
            /* printf("UDP recvfrom returned %d\n", r); */
            if (r > 0) {
                if (strncmp(recvbuf, "end", 3) == 0) {
                    printf("Client requested to exit... test successful.\n");
                    pico_timer_add(1000, deferred_exit, udpecho_pas);
                    udpecho_exit++;
                }

                pico_socket_sendto(s, recvbuf, r, IPV6_MODE ? (void *)peer.ip6.addr : (void *)&peer.ip4.addr, port);
            }
        } while (r > 0);
        free(recvbuf);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        printf("Socket Error received. Bailing out.\n");
        free(udpecho_pas);
        exit(7);
    }

    picoapp_dbg("%s: received packet from %08X:%u\n", __FUNCTION__, long_be(peer), short_be(port));
}

void app_udpecho(char *arg)
{
    char *baddr = NULL, *lport = NULL, *sport = NULL, *s_datasize = NULL;
    char *nxt = arg;
    uint16_t listen_port = 0;
    struct pico_ip4 inaddr_bind = { };
    struct pico_ip6 inaddr_bind6 = { };
    int ret = 0;

    udpecho_pas = calloc(1, sizeof(struct udpecho_pas));
    if (!udpecho_pas) {
        printf("%s: no memory available\n", __FUNCTION__);
        exit(255);
    }

    udpecho_pas->s = NULL;
    udpecho_pas->sendto_port = 0;
    udpecho_pas->datasize = 1400;

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&baddr, nxt);
        if (baddr) {
            if (!IPV6_MODE)
                pico_string_to_ipv4(baddr, &inaddr_bind.addr);

      #ifdef PICO_SUPPORT_IPV6
            else
                pico_string_to_ipv6(baddr, inaddr_bind6.addr);
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing bind_addr */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            listen_port = short_be(5555);
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            udpecho_pas->sendto_port = atoi(sport);
        } else {
            /* incorrect send_port */
            goto out;
        }
    } else {
        /* missing send_port, use default */
    }

    if (nxt) {
        nxt = cpy_arg(&s_datasize, nxt);
        if (s_datasize && atoi(s_datasize)) {
            udpecho_pas->datasize = atoi(s_datasize);
        } else {
            /* incorrect datasize */
            goto out;
        }
    } else {
        /* missing datasize, incomplete optional parameters? -> exit */
        if (sport)
            goto out;
    }

    /* end of argument parsing */

    if (!IPV6_MODE)
        udpecho_pas->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpecho);
    else
        udpecho_pas->s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, &cb_udpecho);

    if (!udpecho_pas->s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        free(udpecho_pas);
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_bind(udpecho_pas->s, &inaddr_bind, &listen_port);
    else {
        ret = pico_socket_bind(udpecho_pas->s, &inaddr_bind6, &listen_port);
        printf("udpecho> Bound to [%s]:%d.\n", baddr, short_be(listen_port));
    }

    if (ret != 0) {
        free(udpecho_pas);
        if (!IPV6_MODE)
            printf("%s: error binding socket to %08X:%u: %s\n", __FUNCTION__, long_be(inaddr_bind.addr), short_be(listen_port), strerror(pico_err));
        else
            printf("%s: error binding socket to [%s]:%u: %s\n", __FUNCTION__, "TODO_IPV6_ADDR", short_be(listen_port), strerror(pico_err));

        exit(1);
    }

#ifdef PICOAPP_IPFILTER
    {
        struct pico_ip4 address, in_addr_netmask, in_addr;
        /* struct pico_ipv4_link *link; */
        int ret = 0;
        address.addr = 0x0800280a;
        in_addr_netmask.addr = 0x00FFFFFF;
        in_addr.addr = 0x0000320a;
        /* link = pico_ipv4_link_get(&address); */

        printf("udpecho> IPFILTER ENABLED\n");

        /*Adjust your IPFILTER*/
        ret |= pico_ipv4_filter_add(NULL, 17, NULL, NULL, &in_addr, &in_addr_netmask, 0, 5555, 0, 0, FILTER_DROP);

        if (ret < 0)
            printf("Filter_add invalid argument\n");
    }
#endif

    printf("\n%s: UDP echo launched. Receiving packets of %u bytes on port %u\n\n", __FUNCTION__, udpecho_pas->datasize, short_be(listen_port));

    return;

out:
    fprintf(stderr, "udpecho expects the following format: udpecho:bind_addr:listen_port[:sendto_port:datasize]\n");
    free(udpecho_pas);
    exit(255);
}
/*** END UDP ECHO ***/

/*** Multicast SEND ***/
/*
 * multicast send expects the following format: mcastsend:link_addr:mcast_addr:sendto_port:listen_port
 * link_addr: mcastsend picoapp IP address
 * mcast_addr: multicast IP address to send to
 * sendto_port: port number to send multicast traffic to
 * listen_port: port number on which the mcastsend can receive data
 *
 * f.e.: ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.255.0: -a mcastsend:10.40.0.2:224.7.7.7:6667:6667
 */
#ifdef PICO_SUPPORT_MCAST
void app_mcastsend(char *arg)
{
    char *maddr = NULL, *laddr = NULL, *lport = NULL, *sport = NULL;
    uint16_t sendto_port = 0;
    struct pico_ip4 inaddr_link = {
        0
    }, inaddr_mcast = {
        0
    };
    char *new_arg = NULL, *p = NULL, *nxt = arg;
    struct pico_ip_mreq mreq = ZERO_MREQ;

    /* start of parameter parsing */
    if (nxt) {
        nxt = cpy_arg(&laddr, nxt);
        if (laddr) {
            pico_string_to_ipv4(laddr, &inaddr_link.addr);
        } else {
            goto out;
        }
    } else {
        /* no arguments */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&maddr, nxt);
        if (maddr) {
            pico_string_to_ipv4(maddr, &inaddr_mcast.addr);
        } else {
            goto out;
        }
    } else {
        /* missing multicast address */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            sendto_port = short_be(atoi(sport));
        } else {
            /* incorrect send_port */
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            /* unused at this moment */
            /* listen_port = short_be(atoi(lport)); */
        } else {
            /* incorrect listen_port */
            goto out;
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    printf("\n%s: mcastsend started. Sending packets to %08X:%u\n\n", __FUNCTION__, long_be(inaddr_mcast.addr), short_be(sendto_port));

    /* udpclient:dest_addr:sendto_port[:listen_port:datasize:loops:subloops] */
    new_arg = calloc(1, strlen(maddr) + 1 + strlen(sport) + 1 + strlen(lport) + strlen(":64:10:5") + 1);
    p = strcat(new_arg, maddr);
    p = strcat(p + strlen(maddr), ":");
    p = strcat(p + 1, sport);
    p = strcat(p + strlen(sport), ":");
    p = strcat(p + 1, lport);
    p = strcat(p + strlen(lport), ":64:10:5");

    app_udpclient(new_arg);

    mreq.mcast_group_addr = inaddr_mcast;
    mreq.mcast_link_addr = inaddr_link;
    if(pico_socket_setoption(udpclient_pas->s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
        exit(1);
    }

    return;

out:
    fprintf(stderr, "mcastsend expects the following format: mcastsend:link_addr:mcast_addr:sendto_port:listen_port\n");
    exit(255);
}
#else
void app_mcastsend(char *arg)
{
    printf("ERROR: PICO_SUPPORT_MCAST disabled\n");
    return;
}
#endif
/*** END Multicast SEND ***/

/*** Multicast RECEIVE + ECHO ***/
/*
 * multicast receive expects the following format: mcastreceive:link_addr:mcast_addr:listen_port:sendto_port
 * link_addr: mcastreceive picoapp IP address
 * mcast_addr: multicast IP address to receive
 * listen_port: port number on which the mcastreceive listens
 * sendto_port: port number to echo multicast traffic to (echo to originating IP address)
 *
 * f.e.: ./build/test/picoapp.elf --vde pic1:/tmp/pic0.ctl:10.40.0.3:255.255.0.0: -a mcastreceive:10.40.0.3:224.7.7.7:6667:6667
 */
#ifdef PICO_SUPPORT_MCAST
void app_mcastreceive(char *arg)
{
    char *new_arg = NULL, *p = NULL, *nxt = arg;
    char *laddr = NULL, *maddr = NULL, *lport = NULL, *sport = NULL;
    uint16_t listen_port = 0;
    struct pico_ip4 inaddr_link = {
        0
    }, inaddr_mcast = {
        0
    };
    struct pico_ip_mreq mreq = ZERO_MREQ;
    struct pico_ip_mreq_source mreq_source = ZERO_MREQ_SRC;

    /* start of parameter parsing */
    if (nxt) {
        nxt = cpy_arg(&laddr, nxt);
        if (laddr) {
            pico_string_to_ipv4(laddr, &inaddr_link.addr);
        } else {
            goto out;
        }
    } else {
        /* no arguments */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&maddr, nxt);
        if (maddr) {
            pico_string_to_ipv4(maddr, &inaddr_mcast.addr);
        } else {
            goto out;
        }
    } else {
        /* missing multicast address */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            /* incorrect listen_port */
            goto out;
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            /* unused at this moment */
            /* send_port = short_be(atoi(sport)); */
        } else {
            /* incorrect send_port */
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    /* end of parameter parsing */

    printf("\n%s: multicast receive started. Receiving packets on %s:%d\n\n", __FUNCTION__, maddr, short_be(listen_port));

    /* udpecho:bind_addr:listen_port[:sendto_port:datasize] */
    new_arg = calloc(1, strlen(laddr) + 1 + strlen(lport) + 1 + strlen(sport) + strlen(":64") + 1);
    p = strcat(new_arg, laddr);
    p = strcat(p + strlen(laddr), ":");
    p = strcat(p + 1, lport);
    p = strcat(p + strlen(lport), ":");
    p = strcat(p + 1, sport);
    p = strcat(p + strlen(sport), ":64");

    app_udpecho(new_arg);

    mreq.mcast_group_addr = mreq_source.mcast_group_addr = inaddr_mcast;
    mreq.mcast_link_addr = mreq_source.mcast_link_addr = inaddr_link;
    mreq_source.mcast_source_addr.addr = long_be(0XAC100101);
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_BLOCK_SOURCE, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_BLOCK_SOURCE failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_UNBLOCK_SOURCE, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_UNBLOCK_SOURCE failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    mreq_source.mcast_source_addr.addr = long_be(0XAC10010A);
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    mreq_source.mcast_source_addr.addr = long_be(0XAC100101);
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    mreq_source.mcast_group_addr.addr = long_be(0XE0010101);
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    return;

out:
    fprintf(stderr, "mcastreceive expects the following format: mcastreceive:link_addr:mcast_addr:listen_port[:send_port]\n");
    exit(255);
}
#else
void app_mcastreceive(char *arg)
{
    printf("ERROR: PICO_SUPPORT_MCAST disabled\n");
    return;
}
#endif
/*** END Multicast RECEIVE + ECHO ***/

/*** UDP NAT CLIENT ***/
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10: -a udpnatclient:10.50.0.8:6667: */
static struct pico_ip4 udpnatclient_inaddr_dst;
static uint16_t udpnatclient_port_be;

void udpnatclient_send(pico_time __attribute__((unused)) now, void *arg)
{
    int i, w;
    struct pico_socket *s = (struct pico_socket *)arg;
    char buf[1400] = { };
    char end[4] = "end";
    static int loop = 0;

    for ( i = 0; i < 3; i++) {
        w = pico_socket_send(s, buf, 1400);
    }
    if (++loop > 1000) {
        udpnatclient_port_be = 0;
        for (i = 0; i < 3; i++) {
            w = pico_socket_send(s, end, 4);
            if (w <= 0)
                break;

            printf("End!\n");
        }
        pico_timer_add(1000, deferred_exit, NULL);
        return;
    }
}

void cb_udpnatclient(uint16_t ev, struct pico_socket *s)
{
    char recvbuf[1400];
    int r = 0;

    if (ev & PICO_SOCK_EV_RD) {
        do {
            r = pico_socket_recv(s, recvbuf, 1400);
        } while(r > 0);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        printf("Socket Error received. Bailing out.\n");
        exit(7);
    }

    /* Not closing to test port check */
    /* pico_socket_close(s); */
}

void udpnatclient_open_socket(pico_time __attribute__((unused)) now, void __attribute__((unused)) *arg)
{
    struct pico_socket *s = NULL;
    static int loop;

    if (!udpnatclient_port_be)
        return;

    loop++;
    picoapp_dbg(">>>>> Loop %d\n", loop);
    if (!(loop % 100))
        printf("Created %d sockets\n", loop);

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpnatclient);
    if (!s)
        exit(1);

    if (pico_socket_connect(s, &udpnatclient_inaddr_dst, udpnatclient_port_be) != 0)
    {
        printf("Error connecting\n");
        exit(1);
    }

    picoapp_dbg("New socket with port %u\n", s->local_port);

    pico_timer_add(25, udpnatclient_send, s);
    pico_timer_add(25, udpnatclient_open_socket, 0);
}

void app_udpnatclient(char *arg)
{
    struct pico_socket *s;
    char *daddr, *dport;
    int port = 0;
    uint16_t port_be = 0;
    struct pico_ip4 inaddr_dst = ZERO_IP4;
    char *nxt;

    nxt = cpy_arg(&daddr, arg);
    if (!daddr) {
        fprintf(stderr, " udpnatclient expects the following format: udpnatclient:dest_addr[:dest_port]\n");
        exit(255);
    }

    if (nxt) {
        nxt = cpy_arg(&dport, nxt);
        if (dport) {
            port = atoi(dport);
            if (port > 0)
                port_be = short_be(port);
        }
    }

    if (port == 0) {
        port_be = short_be(5555);
    }

    printf("UDP NAT client started. Sending packets to %s:%d\n", daddr, short_be(port_be));

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpnatclient);
    if (!s)
        exit(1);

    pico_string_to_ipv4(daddr, &inaddr_dst.addr);

    if (pico_socket_connect(s, &inaddr_dst, port_be) != 0)
    {
        printf("Error binding the port \n");
        exit(1);
    }

    picoapp_dbg("New socket with port %u\n", s->local_port);

    udpnatclient_inaddr_dst = inaddr_dst;
    udpnatclient_port_be = port_be;

    pico_timer_add(100, udpnatclient_send, s);
    pico_timer_add(1000, udpnatclient_open_socket, 0);
}
/*** END UDP NAT CLIENT ***/

/*** UDP DNS CLIENT ***/
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
        printf("%s: ERROR occured! (id: %u)\n", __FUNCTION__, *id);
        return;
    }

    printf("%s: ip %s (id: %u)\n", __FUNCTION__, ip, *id);
    if (arg)
        PICO_FREE(arg);
}

void cb_udpdnsclient_getname(char *name, void *arg)
{
    uint8_t *id = (uint8_t *) arg;

    if (!name) {
        printf("%s: ERROR occured! (id: %u)\n", __FUNCTION__, *id);
        return;
    }

    printf("%s: name %s (id: %u)\n", __FUNCTION__, name, *id);
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
        fprintf(stderr, " udpdnsclient expects the following format: udpdnsclient:dest_name:dest_ip:[ipv6]\n");
        exit(255);
    }

    nxt = cpy_arg(&daddr, nxt);
    if (!daddr || !nxt) {
        fprintf(stderr, " udpdnsclient expects the following format: udpdnsclient:dest_name:dest_ip:[ipv6]\n");
        exit(255);
    }

    nxt = cpy_arg(&ipver, nxt);
    if (!ipver || strcmp("ipv6", ipver) != 0)
        v = 4;
    else
        v = 6;

    printf("UDP DNS client started.\n");

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
            printf("Mode: IPv4\n");
            getaddr_id = calloc(1, sizeof(uint8_t));
            *getaddr_id = 1;
            printf(">>>>> DNS GET ADDR OF %s\n", dname);
            pico_dns_client_getaddr(dname, &cb_udpdnsclient_getaddr, getaddr_id);

            getname_id = calloc(1, sizeof(uint8_t));
            *getname_id = 2;
            printf(">>>>> DNS GET NAME OF %s\n", daddr);
            pico_dns_client_getname(daddr, &cb_udpdnsclient_getname, getname_id);
            return;
        }

        printf("Mode: IPv6\n");

#ifdef PICO_SUPPORT_IPV6
        getaddr6_id = calloc(1, sizeof(uint8_t));
        *getaddr6_id = 3;
        printf(">>>>> DNS GET ADDR6 OF %s\n", dname);
        pico_dns_client_getaddr6(dname, &cb_udpdnsclient_getaddr, getaddr6_id);
        getname6_id = calloc(1, sizeof(uint8_t));
        *getname6_id = 4;
        printf(">>>>> DNS GET NAME OF ipv6 addr 2a00:1450:400c:c06::64\n");
        pico_dns_client_getname6("2a00:1450:400c:c06::64", &cb_udpdnsclient_getname, getname6_id);
#endif
    }

    return;
}
/*** END UDP DNS CLIENT ***/

/*** TCP CLIENT ***/
#define TCPSIZ (1024 * 1024 * 5) 
static char *buffer1;
static char *buffer0;

void compare_results(pico_time __attribute__((unused)) now, void __attribute__((unused)) *arg)
{
#ifdef CONSISTENCY_CHECK /* TODO: Enable */
    int i;
    printf("Calculating result.... (%p)\n", buffer1);

    if (memcmp(buffer0, buffer1, TCPSIZ) == 0)
        exit(0);

    for (i = 0; i < TCPSIZ; i++) {
        if (buffer0[i] != buffer1[i]) {
            fprintf(stderr, "Error at byte %d - %c!=%c\n", i, buffer0[i], buffer1[i]);
            exit(115);
        }
    }
#endif
    exit(0);

}

void cb_tcpclient(uint16_t ev, struct pico_socket *s)
{
    static int w_size = 0;
    static int r_size = 0;
    static int closed = 0;
    int r, w;
    static unsigned long count = 0;

    count++;
    picoapp_dbg("tcpclient> wakeup %lu, event %u\n", count, ev);

    if (ev & PICO_SOCK_EV_RD) {
        do {
            r = pico_socket_read(s, buffer1 + r_size, TCPSIZ - r_size);
            if (r > 0) {
                r_size += r;
                picoapp_dbg("SOCKET READ - %d\n", r_size);
            }

            if (r < 0)
                exit(5);
        } while(r > 0);
    }

    if (ev & PICO_SOCK_EV_CONN) {
        printf("Connection established with server.\n");
    }

    if (ev & PICO_SOCK_EV_FIN) {
        printf("Socket closed. Exit normally. \n");
        pico_timer_add(2000, compare_results, NULL);
    }

    if (ev & PICO_SOCK_EV_ERR) {
        printf("Socket error received: %s. Bailing out.\n", strerror(pico_err));
        exit(1);
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        printf("Socket received close from peer - Wrong case if not all client data sent!\n");
        pico_socket_close(s);
        return;
    }

    if (ev & PICO_SOCK_EV_WR) {
        if (w_size < TCPSIZ) {
            do {
                w = pico_socket_write(s, buffer0 + w_size, TCPSIZ - w_size);
                if (w > 0) {
                    w_size += w;
                    picoapp_dbg("SOCKET WRITTEN - %d\n", w_size);
                    if (w < 0)
                        exit(5);
                }
            } while(w > 0);
        } else {
#ifdef INFINITE_TCPTEST
            w_size = 0;
            return;
#endif
            if (!closed) {
                pico_socket_shutdown(s, PICO_SHUT_WR);
                printf("Called shutdown()\n");
                closed = 1;
            }
        }
    }
}

void app_tcpclient(char *arg)
{
    char *daddr = NULL, *dport = NULL;
    char *nxt = arg;
    uint16_t send_port = 0, listen_port = short_be(5555);
    int i = 0, ret = 0, yes = 1;
    struct pico_socket *s = NULL;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } dst = {
        .ip4 = {0}, .ip6 = {{0}}
    };
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } inaddr_any = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&daddr, arg);
        if (daddr) {
            if (!IPV6_MODE)
                pico_string_to_ipv4(daddr, &dst.ip4.addr);

      #ifdef PICO_SUPPORT_IPV6
            else
                pico_string_to_ipv6(daddr, dst.ip6.addr);
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing dest_addr */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&dport, nxt);
        if (dport && atoi(dport)) {
            send_port = short_be(atoi(dport));
        } else {
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    /* end of argument parsing */

    buffer0 = malloc(TCPSIZ);
    buffer1 = malloc(TCPSIZ);
    printf("Buffer1 (%p)\n", buffer1);
    for (i = 0; i < TCPSIZ; i++) {
        char c = (i % 26) + 'a';
        buffer0[i] = c;
    }
    memset(buffer1, 'a', TCPSIZ);

    printf("Connecting to: %s:%d\n", daddr, short_be(send_port));

    if (!IPV6_MODE)
        s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpclient);
    else
        s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpclient);

    if (!s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        exit(1);
    }

    pico_socket_setoption(s, PICO_TCP_NODELAY, &yes);

    if (!IPV6_MODE)
        ret = pico_socket_bind(s, &inaddr_any.ip4, &listen_port);
    else
        ret = pico_socket_bind(s, &inaddr_any.ip6, &listen_port);

    if (ret < 0) {
        printf("%s: error binding socket to port %u: %s\n", __FUNCTION__, short_be(listen_port), strerror(pico_err));
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_connect(s, &dst.ip4, send_port);
    else
        ret = pico_socket_connect(s, &dst.ip6, send_port);

    if (ret < 0) {
        printf("%s: error connecting to %s:%u: %s\n", __FUNCTION__, daddr, short_be(send_port), strerror(pico_err));
        exit(1);
    }

    return;

out:
    fprintf(stderr, "tcpclient expects the following format: tcpclient:dest_addr:dest_port\n");
    exit(255);
}
/*** END TCP CLIENT ***/

/*** TCP ECHO ***/
#define BSIZE (1024 * 10)
static char recvbuf[BSIZE];
static int pos = 0, len = 0;
static int flag = 0;

int send_tcpecho(struct pico_socket *s)
{
    int w, ww = 0;
    if (len > pos) {
        do {
            w = pico_socket_write(s, recvbuf + pos, len - pos);
            if (w > 0) {
                pos += w;
                ww += w;
                if (pos >= len) {
                    pos = 0;
                    len = 0;
                }
            } else {
                errno = pico_err;
            }
        } while((w > 0) && (pos < len));
    }

    return ww;
}

void cb_tcpecho(uint16_t ev, struct pico_socket *s)
{
    int r = 0;

    picoapp_dbg("tcpecho> wakeup ev=%u\n", ev);

    if (ev & PICO_SOCK_EV_RD) {
        if (flag & PICO_SOCK_EV_CLOSE)
            printf("SOCKET> EV_RD, FIN RECEIVED\n");

        while (len < BSIZE) {
            r = pico_socket_read(s, recvbuf + len, BSIZE - len);
            if (r > 0) {
                len += r;
                flag &= ~(PICO_SOCK_EV_RD);
            } else {
                flag |= PICO_SOCK_EV_RD;
                break;
            }
        }
    }

    if (ev & PICO_SOCK_EV_CONN) {
        struct pico_socket *sock_a = {
            0
        };
        struct pico_ip4 orig = {
            0
        };
        uint16_t port = 0;
        char peer[30] = {
            0
        };
        int yes = 1;

        sock_a = pico_socket_accept(s, &orig, &port);
        pico_ipv4_to_string(peer, orig.addr);
        printf("Connection established with %s:%d.\n", peer, short_be(port));
        pico_socket_setoption(sock_a, PICO_TCP_NODELAY, &yes);
    }

    if (ev & PICO_SOCK_EV_FIN) {
        printf("Socket closed. Exit normally. \n");
        pico_timer_add(2000, deferred_exit, NULL);
    }

    if (ev & PICO_SOCK_EV_ERR) {
        printf("Socket error received: %s. Bailing out.\n", strerror(pico_err));
        exit(1);
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        printf("Socket received close from peer.\n");
        flag |= PICO_SOCK_EV_CLOSE;
        if ((flag & PICO_SOCK_EV_RD) && (flag & PICO_SOCK_EV_CLOSE)) {
            pico_socket_shutdown(s, PICO_SHUT_WR);
            printf("SOCKET> Called shutdown write, ev = %d\n", ev);
        }
    }

    if (ev & PICO_SOCK_EV_WR) {
        r = send_tcpecho(s);
        if (r == 0)
            flag |= PICO_SOCK_EV_WR;
        else
            flag &= (~PICO_SOCK_EV_WR);
    }
}

void app_tcpecho(char *arg)
{
    char *nxt = arg;
    char *lport = NULL;
    uint16_t listen_port = 0;
    int ret = 0, yes = 1;
    struct pico_socket *s = NULL;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } inaddr_any = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            goto out;
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    /* end of argument parsing */

    if (!IPV6_MODE)
        s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpecho);
    else
        s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpecho);

    if (!s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        exit(1);
    }

    pico_socket_setoption(s, PICO_TCP_NODELAY, &yes);

    if (!IPV6_MODE)
        ret = pico_socket_bind(s, &inaddr_any.ip4, &listen_port);
    else
        ret = pico_socket_bind(s, &inaddr_any.ip6, &listen_port);

    if (ret < 0) {
        printf("%s: error binding socket to port %u: %s\n", __FUNCTION__, short_be(listen_port), strerror(pico_err));
        exit(1);
    }

    if (pico_socket_listen(s, 40) != 0) {
        printf("%s: error listening on port %u\n", __FUNCTION__, short_be(listen_port));
        exit(1);
    }

    printf("Launching PicoTCP echo server\n");
    return;

out:
    fprintf(stderr, "tcpecho expects the following format: tcpecho:listen_port\n");
    exit(255);

#ifdef PICOAPP_IPFILTER
    if (!IPV6_MODE) {
        struct pico_ip4 address, in_addr_netmask, in_addr;
        int ret = 0;
        address.addr = 0x0800280a;
        in_addr_netmask.addr = 0x00FFFFFF;
        in_addr.addr = 0x0000320a;

        printf("tcpecho> IPFILTER ENABLED\n");

        /*Adjust your IPFILTER*/
        ret |= pico_ipv4_filter_add(NULL, 6, NULL, NULL, &in_addr, &in_addr_netmask, 0, 5555, 0, 0, FILTER_REJECT);

        if (ret < 0)
            printf("Filter_add invalid argument\n");
    }

#endif
}
/*** END TCP ECHO ***/

/*** START TCP BENCH ***/
#define TCP_BENCH_TX  1
#define TCP_BENCH_RX  2
#define TCP_BENCH_TX_FOREVER 3

int tcpbench_mode = 0;
struct pico_socket *tcpbench_sock = NULL;
static pico_time tcpbench_time_start, tcpbench_time_end;

void cb_tcpbench(uint16_t ev, struct pico_socket *s)
{
    static int closed = 0;
    static unsigned long count = 0;
    uint8_t recvbuf[1500];
    uint16_t port;
    char peer[200];
    /* struct pico_socket *sock_a; */

    static int tcpbench_wr_size = 0;
    static int tcpbench_rd_size = 0;
    int tcpbench_w = 0;
    int tcpbench_r = 0;
    double tcpbench_time = 0;

    count++;

    if (ev & PICO_SOCK_EV_RD) {
        do {
            /* read data, but discard */
            tcpbench_r = pico_socket_read(s, recvbuf, 1500);
            if (tcpbench_r > 0) {
                tcpbench_rd_size += tcpbench_r;
            }
        } while (tcpbench_r > 0);
        if (tcpbench_time_start == 0)
            tcpbench_time_start = PICO_TIME_MS();

        printf("tcpbench_rd_size = %d      \r", tcpbench_rd_size);
    }

    if (ev & PICO_SOCK_EV_CONN) {
        if (!IPV6_MODE) {
            struct pico_ip4 orig;
            if (tcpbench_mode == TCP_BENCH_TX || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
                printf("tcpbench> Connection established with server.\n");
            } else if (tcpbench_mode == TCP_BENCH_RX) {
                /* sock_a = pico_socket_accept(s, &orig, &port); */
                pico_socket_accept(s, &orig, &port);
                pico_ipv4_to_string(peer, orig.addr);
                printf("tcpbench> Connection established with %s:%d.\n", peer, short_be(port));
            }
        } else {
            struct pico_ip6 orig;
            if (tcpbench_mode == TCP_BENCH_TX || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
                printf("tcpbench> Connection established with server.\n");
            } else if (tcpbench_mode == TCP_BENCH_RX) {
                /* sock_a = pico_socket_accept(s, &orig, &port); */
                pico_socket_accept(s, &orig, &port);
#ifdef PICO_SUPPORT_IPV6
                pico_ipv6_to_string(peer, orig.addr);
                printf("tcpbench> Connection established with [%s]:%d.\n", peer, short_be(port));
#endif
            }
        }
    }

    if (ev & PICO_SOCK_EV_FIN) {
        printf("tcpbench> Socket closed. Exit normally. \n");
        if (tcpbench_mode == TCP_BENCH_RX) {
            tcpbench_time_end = PICO_TIME_MS();
            tcpbench_time = (tcpbench_time_end - tcpbench_time_start) / 1000.0; /* get number of seconds */
            printf("tcpbench> received %d bytes in %lf seconds\n", tcpbench_rd_size, tcpbench_time);
            printf("tcpbench> average read throughput %lf kbit/sec\n", ((tcpbench_rd_size * 8.0) / tcpbench_time) / 1000);
            pico_socket_shutdown(s, PICO_SHUT_WR);
            printf("tcpbench> Called shutdown write, ev = %d\n", ev);
        }

        exit(0);
    }

    if (ev & PICO_SOCK_EV_ERR) {
        printf("tcpbench> ---- Socket Error received: %s. Bailing out.\n", strerror(pico_err));
        exit(1);
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        printf("tcpbench> event close\n");
        if (tcpbench_mode == TCP_BENCH_RX) {
            pico_socket_shutdown(s, PICO_SHUT_WR);
            printf("tcpbench> Called shutdown write, ev = %d\n", ev);
        } else if (tcpbench_mode == TCP_BENCH_TX || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
            pico_socket_close(s);
            return;
        }
    }

    if (ev & PICO_SOCK_EV_WR) {
        if (((tcpbench_wr_size < TCPSIZ) && (tcpbench_mode == TCP_BENCH_TX)) || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
            do {
                tcpbench_w = pico_socket_write(tcpbench_sock, buffer0 + (tcpbench_wr_size % TCPSIZ), TCPSIZ - (tcpbench_wr_size % TCPSIZ));
                if (tcpbench_w > 0) {
                    tcpbench_wr_size += tcpbench_w;
                    /* printf("tcpbench> SOCKET WRITTEN - %d\n",tcpbench_w); */
                } else {
                    /* printf("pico_socket_write returned %d\n", tcpbench_w); */
                }

                if (tcpbench_time_start == 0)
                    tcpbench_time_start = PICO_TIME_MS();
            } while(tcpbench_w > 0);
            printf("tcpbench_wr_size = %d      \r", tcpbench_wr_size);
        } else {
            if (!closed && tcpbench_mode == TCP_BENCH_TX) {
                tcpbench_time_end = PICO_TIME_MS();
                pico_socket_shutdown(s, PICO_SHUT_WR);
                printf("tcpbench> TCPSIZ written\n");
                printf("tcpbench> Called shutdown()\n");
                tcpbench_time = (tcpbench_time_end - tcpbench_time_start) / 1000.0; /* get number of seconds */
                printf("tcpbench> Transmitted %u bytes in %lf seconds\n", TCPSIZ, tcpbench_time);
                printf("tcpbench> average write throughput %lf kbit/sec\n", ((TCPSIZ * 8.0) / tcpbench_time) / 1000);
                closed = 1;
            }
        }
    }
}

void app_tcpbench(char *arg)
{
    struct pico_socket *s;
    char *dport;
    char *dest;
    char *mode;
    char *nagle;
    int port = 0, i;
    uint16_t port_be = 0;
    char *nxt;
    char *sport;
    int nagle_off = 1;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } inaddr_any = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    nxt = cpy_arg(&mode, arg);

    if ((*mode == 't') || (*mode == 'f')) { /* TEST BENCH SEND MODE */
        if (*mode == 't')
            tcpbench_mode = TCP_BENCH_TX;
        else
            tcpbench_mode = TCP_BENCH_TX_FOREVER;

        printf("tcpbench> TX\n");

        nxt = cpy_arg(&dest, nxt);
        if (!dest) {
            fprintf(stderr, "tcpbench send needs the following format: tcpbench:tx:dst_addr[:dport][:n] -- 'n' is for nagle\n");
            exit(255);
        }

        printf ("+++ Dest is %s\n", dest);
        if (nxt) {
            printf("Next arg: %s\n", nxt);
            nxt = cpy_arg(&dport, nxt);
            printf("Dport: %s\n", dport);
        }
        if (nxt) {
            printf("Next arg: %s\n", nxt);
            nxt = cpy_arg(&nagle, nxt);
            printf("nagle: %s\n", nagle);
            if (strlen(nagle) == 1 && nagle[0] == 'n') {
                nagle_off = 0;
                printf("Nagle algorithm enabled\n");
            }
        }

        if (dport) {
            port = atoi(dport);
            port_be = short_be((uint16_t)port);
        }

        if (port == 0) {
            port_be = short_be(5555);
        }

        buffer0 = malloc(TCPSIZ);
        buffer1 = malloc(TCPSIZ);
        printf("Buffer1 (%p)\n", buffer1);
        for (i = 0; i < TCPSIZ; i++) {
            char c = (i % 26) + 'a';
            buffer0[i] = c;
        }
        memset(buffer1, 'a', TCPSIZ);
        printf("tcpbench> Connecting to: %s:%d\n", dest, short_be(port_be));

        if (!IPV6_MODE) {
            struct pico_ip4 server_addr;
            s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpbench);
            if (!s)
                exit(1);

            pico_socket_setoption(s, PICO_TCP_NODELAY, &nagle_off);

            /* NOTE: used to set a fixed local port and address
               local_port = short_be(6666);
               pico_string_to_ipv4("10.40.0.11", &local_addr.addr);
               pico_socket_bind(s, &local_addr, &local_port);*/

            pico_string_to_ipv4(dest, &server_addr.addr);
            pico_socket_connect(s, &server_addr, port_be);
        } else {
            struct pico_ip6 server_addr;
            s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpbench);
            if (!s)
                exit(1);

            pico_socket_setoption(s, PICO_TCP_NODELAY, &nagle_off);

            /* NOTE: used to set a fixed local port and address
               local_port = short_be(6666);
               pico_string_to_ipv4("10.40.0.11", &local_addr.addr);
               pico_socket_bind(s, &local_addr, &local_port);*/
#ifdef PICO_SUPPORT_IPV6
            pico_string_to_ipv6(dest, server_addr.addr);
            pico_socket_connect(s, &server_addr, port_be);
#endif

        }

    } else if (*mode == 'r') { /* TEST BENCH RECEIVE MODE */
        int ret;
        tcpbench_mode = TCP_BENCH_RX;
        printf("tcpbench> RX\n");

        cpy_arg(&sport, nxt);
        if (!sport) {
            fprintf(stderr, "tcpbench receive needs the following format: tcpbench:rx[:dport]\n");
            exit(255);
        }

        if (sport) {
            printf("s-port is %s\n", sport);
            port = atoi(sport);
            port_be = short_be((uint16_t)port);
            printf("tcpbench> Got port %d\n", port);
        }

        if (port == 0) {
            port_be = short_be(5555);
        }

        printf("tcpbench> OPEN\n");
        if (!IPV6_MODE)
            s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpbench);
        else
            s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpbench);

        if (!s)
            exit(1);

        printf("tcpbench> BIND\n");
        if (!IPV6_MODE)
            ret = pico_socket_bind(s, &inaddr_any.ip4, &port_be);
        else
            ret = pico_socket_bind(s, &inaddr_any.ip6, &port_be);

        if (ret < 0) {
            printf("tcpbench> BIND failed because %s\n", strerror(pico_err));
            exit(1);
        }

        printf("tcpbench> LISTEN\n");
        if (pico_socket_listen(s, 40) != 0)
            exit(1);

        printf("tcpbench> listening port %u ...\n", short_be(port_be));
    } else {
        printf("tcpbench> wrong mode argument\n");
        exit(1);
    }

    tcpbench_sock = s;


    return;
}
/*** END TCP BENCH ***/

/*** START NATBOX ***/
void app_natbox(char *arg)
{
    char *dest = NULL;
    struct pico_ip4 ipdst, pub_addr, priv_addr;
    struct pico_ipv4_link *link;

    cpy_arg(&dest, arg);
    if (!dest) {
        fprintf(stderr, "natbox needs the following format: natbox:dst_addr\n");
        exit(255);
    }

    pico_string_to_ipv4(dest, &ipdst.addr);
    link = pico_ipv4_link_get(&ipdst);
    if (!link) {
        fprintf(stderr, "natbox: Destination not found.\n");
        exit(255);
    }

    pico_ipv4_nat_enable(link);
    pico_string_to_ipv4("10.50.0.10", &pub_addr.addr);
    pico_string_to_ipv4("10.40.0.08", &priv_addr.addr);
    pico_ipv4_port_forward(pub_addr, short_be(5555), priv_addr, short_be(6667), PICO_PROTO_UDP, PICO_NAT_PORT_FORWARD_ADD);
    fprintf(stderr, "natbox: started.\n");
}
/*** END NATBOX ***/

/*** START PING ***/
#ifdef PICO_SUPPORT_PING
#define NUM_PING 10

void cb_ping(struct pico_icmp4_stats *s)
{
    char host[30];
    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=%lu time=%lu ms\n", s->size, host, s->seq, s->ttl, s->time);
        if (s->seq >= NUM_PING)
            exit(0);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
        exit(1);
    }
}

#ifdef PICO_SUPPORT_IPV6
void cb_ping6(struct pico_icmp6_stats *s)
{
    char host[30];
    pico_ipv6_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=%lu time=%lu ms\n", s->size, host, s->seq, s->ttl, s->time);
        if (s->seq >= NUM_PING)
            exit(0);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
        exit(1);
    }
}
#endif

void app_ping(char *arg)
{
    char *dest = NULL;
    cpy_arg(&dest, arg);
    if (!dest) {
        fprintf(stderr, "ping needs the following format: ping:dst_addr\n");
        exit(255);
    }

    if (!IPV6_MODE)
        pico_icmp4_ping(dest, NUM_PING, 1000, 10000, 64, cb_ping);

#ifdef PICO_SUPPORT_IPV6
    else
        pico_icmp6_ping(dest, NUM_PING, 1000, 10000, 64, cb_ping6);
#endif
}
#endif
/*** END PING ***/

/*** START DHCP Server ***/
#ifdef PICO_SUPPORT_DHCPD
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.1:255.255.0.0: -a dhcpserver:pic0:10.40.0.1:255.255.255.0:64:128
 * ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.255.0: \
 * -a dhcpserver:pic0:10.40.0.10:255.255.255.0:64:128:pic1:10.50.0.10:255.255.255.0:64:128
 */
void app_dhcp_server(char *arg)
{
    struct pico_device *dev = NULL;
    struct pico_dhcp_server_setting s = {
        0
    };
    int pool_start = 0, pool_end = 0;
    char *s_name = NULL, *s_addr = NULL, *s_netm = NULL, *s_pool_start = NULL, *s_pool_end = NULL;
    char *nxt = arg;

    if (!nxt)
        goto out;

    while (nxt) {
        if (nxt) {
            nxt = cpy_arg(&s_name, nxt);
            if (!s_name) {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_addr, nxt);
            if (s_addr) {
                pico_string_to_ipv4(s_addr, &s.server_ip.addr);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_netm, nxt);
            if (s_netm) {
                pico_string_to_ipv4(s_netm, &s.netmask.addr);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_pool_start, nxt);
            if (s_pool_start && atoi(s_pool_start)) {
                pool_start = atoi(s_pool_start);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_pool_end, nxt);
            if (s_pool_end && atoi(s_pool_end)) {
                pool_end = atoi(s_pool_end);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        dev = pico_get_device(s_name);
        if (dev == NULL) {
            fprintf(stderr, "No device with name %s found\n", s_name);
            exit(255);
        }

        s.dev = dev;
        s.pool_start = (s.server_ip.addr & s.netmask.addr) | long_be(pool_start);
        s.pool_end = (s.server_ip.addr & s.netmask.addr) | long_be(pool_end);

        pico_dhcp_server_initiate(&s);
    }
    return;

out:
    fprintf(stderr, "dhcpserver expects the following format: dhcpserver:dev_name:dev_addr:dev_netm:pool_start:pool_end\n");
    exit(255);

}
#endif
/*** END DHCP Server ***/

/*** DHCP Client ***/
#ifdef PICO_SUPPORT_DHCPC
static uint8_t dhcpclient_devices = 0;
static uint32_t dhcpclient_xid = 0;

void ping_callback_dhcpclient(struct pico_icmp4_stats *s)
{
    char host[30] = { };

    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("DHCP client: %lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
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

void callback_dhcpclient(void __attribute__((unused)) *cli, int code)
{
    struct pico_ip4 address = ZERO_IP4, gateway = ZERO_IP4;
    char s_address[16] = { }, s_gateway[16] = { };
    void *identifier = NULL;

    printf("DHCP client: callback happened with code %d!\n", code);
    if (code == PICO_DHCP_SUCCESS) {
        identifier = pico_dhcp_get_identifier(dhcpclient_xid);
        if (!identifier) {
            printf("DHCP client: incorrect transaction ID %u\n", dhcpclient_xid);
            return;
        }

        address = pico_dhcp_get_address(identifier);
        gateway = pico_dhcp_get_gateway(identifier);
        pico_ipv4_to_string(s_address, address.addr);
        pico_ipv4_to_string(s_gateway, gateway.addr);
        printf("DHCP client: got IP %s assigned with xid %u\n", s_address, dhcpclient_xid);
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

#ifdef PICO_SUPPORT_MDNS

void mdns_getname6_callback(char *str, void *arg)
{
    (void) arg;
    if (!str)
        printf("Getname6: timeout occurred!\n");
    else 
        printf("Getname6 callback called, str: %s\n", str);
    exit(0);
}

void mdns_getaddr6_callback(char *str, void *arg)
{
    (void) arg;
    if (!str)
        printf("Getaddr6: timeout occurred!\n");
    else
        printf("Getaddr6 callback called, str: %s\n", str);
    if(pico_mdns_getname6(str, &mdns_getname6_callback, NULL)!=0)
        printf("Getaddr returned with error!\n");
}

void mdns_getname_callback(char *str, void *arg)
{
    char *peername = (char *)arg;
    if(!peername) {
        printf("No system name supplied!\n");
        exit(-1);
    }
    if (!str)
        printf("Getname: timeout occurred!\n");
    else 
        printf("Getname callback called, str: %s\n", str);
    if(pico_mdns_getaddr6(peername, &mdns_getaddr6_callback, NULL)!=0)
        printf("Getname returned with error!\n");
}

void mdns_getaddr_callback(char *str, void *arg)
{
    if (!str)
        printf("Getaddr: timeout occurred!\n");
    else
        printf("Getaddr callback called, str: %s\n", str);
    if(pico_mdns_getname(str, &mdns_getname_callback, arg)!=0)
        printf("Getaddr returned with error!\n");
}

void mdns_init_callback(char *str, void *arg)
{
    char *peername = (char *)arg;
    printf("Init callback called, str: %s\n", str);
    if(!peername) {
        printf("No system name supplied!\n");
        exit(-1);
    }

    if(pico_mdns_getaddr(peername, &mdns_getaddr_callback, peername)!=0)
        printf("Getaddr returned with error!\n");
}

void app_mdns(char *arg)
{
    char *hostname, *peername;
    char *nxt = arg;

    if (!nxt)
        exit(255);

    nxt = cpy_arg(&hostname, nxt);
    if(!hostname) {
        exit(255);
    }
    if(!nxt){
        printf("Not enough args supplied!\n");
        exit(255);
    }
    nxt = cpy_arg(&peername, nxt);
    if(!peername) {
        exit(255);
    }

    printf("Starting to claim name: %s, system name: %s\n", hostname, peername);
    if(pico_mdns_init(hostname, &mdns_init_callback, peername)!=0)
        printf("Init returned with error\n");
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
#endif

#ifdef PICO_SUPPORT_SNTP_CLIENT

void sntp_timeout(pico_time __attribute__((unused)) now, void *arg)
{
    struct pico_timeval ptv;
    struct timeval tv;
    pico_sntp_gettimeofday(&ptv);
    gettimeofday(&tv, NULL);
    printf("Linux   sec: %u, msec: %u\n", tv.tv_sec, tv.tv_usec / 1000);
    printf("Picotcp sec: %u, msec: %u\n", ptv.tv_sec, ptv.tv_msec);
    printf("SNTP test succesfull!\n");
    exit(0);
}

void cb_synced(pico_err_t status)
{
    if(status == PICO_ERR_ENETDOWN) {
        printf("SNTP: Cannot resolve ntp server name\n");
        exit(1);
    } else if (status == PICO_ERR_ETIMEDOUT) {
        printf("SNTP: Timed out, did not receive ntp packet from server\n");
        exit(1);
    } else if (status == PICO_ERR_EINVAL) {
        printf("SNTP: Conversion error\n");
        exit(1);
    } else if (status == PICO_ERR_ENOTCONN) {
        printf("SNTP: Socket error\n");
        exit(1);
    } else if (status == PICO_ERR_NOERR) {
        pico_timer_add(2000, sntp_timeout, NULL);
    } else {
        printf("SNTP: Invalid status received in cb_synced\n");
        exit(1);
    }
}

void app_sntp(char *servername)
{
    struct pico_timeval tv;
    printf("Starting SNTP query towards %s\n", servername);
    if(pico_sntp_gettimeofday(&tv) == 0)
        printf("Wrongly succesfull gettimeofday\n");
    else
        printf("Unsuccesfull gettimeofday (not synced)\n");

    if(pico_sntp_sync(servername, &cb_synced) == 0)
        printf("Succesfull sync call!\n");
    else
        printf("Error in  sync\n");
}
#endif

void ping_callback_slaacv4(struct pico_icmp4_stats *s)
{
    char host[30] = { };

    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("SLAACV4: %lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
        if (s->seq >= 3) {
            dbg("SLAACV4: TEST SUCCESS!\n");
            pico_slaacv4_unregisterip();
            exit(0);
        }
    } else {
        dbg("SLAACV4: ping %lu to %s error %d\n", s->seq, host, s->err);
        dbg("SLAACV4: TEST FAILED!\n");
        exit(1);
    }
}

void slaacv4_cb(struct pico_ip4 *ip, uint8_t code)
{
    char dst[16] = "169.254.22.5";
    printf("SLAACV4 CALLBACK ip:0x%X code:%d \n", ip->addr, code);
    if (code == 0)
    {
#ifdef PICO_SUPPORT_PING
        pico_icmp4_ping(dst, 3, 1000, 5000, 32, ping_callback_slaacv4);
#else
        exit(0);
#endif
    }
    else
    {
        exit(255);
    }

}


void app_slaacv4(char *arg)
{
    char *sdev = NULL;
    char *nxt = arg;
    struct pico_device *dev = NULL;

    if (!nxt)
        exit(255);

    while (nxt) {
        if (nxt) {
            nxt = cpy_arg(&sdev, nxt);
            if(!sdev) {
                exit(255);
            }
        }
    }
    dev = pico_get_device(sdev);
    if(dev == NULL) {
        printf("%s: error getting device %s: %s\n", __FUNCTION__, dev->name, strerror(pico_err));
        exit(255);
    }

    pico_slaacv4_claimip(dev, slaacv4_cb);
}

/* NOOP */
void app_noop(void)
{
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}

/* end NOOP */


/** From now on, parsing the command line **/
#define NXT_MAC(x) ++ x[5]

/* Copy a string until the separator,
   terminate it and return the next index,
   or NULL if it encounters a EOS */
static char *cpy_arg(char **dst, char *str)
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

void __wakeup(uint16_t __attribute__((unused)) ev, struct pico_socket __attribute__((unused)) *s)
{

}


void usage(char *arg0)
{
    printf("Usage: %s [--vde name:sock:address:netmask[:gateway]] [--vde ...] [--tun name:address:netmask[:gateway]] [--tun ...] [--app name[:args]]\n\n\n", arg0);
    printf("\tall arguments can be repeated, e.g. to run on multiple links or applications\n");
    printf("\t*** --app arguments must be at the end  ***\n");
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
    struct pico_ip4 bcastAddr = ZERO_IP4;

    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"vde", 1, 0, 'v'},
        {"barevde", 1, 0, 'b'},
        {"tun", 1, 0, 't'},
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
            ; /* do nothing */

        p++;
    }
    if (strcmp(app, "picoapp6.elf") == 0)
        IPV6_MODE = 1;

    *macaddr_low ^= getpid();
    printf("My macaddr base is: %02x %02x\n", macaddr[2], macaddr[3]);
    printf("My macaddr is: %02x %02x %02x %02x %02x %02x\n", macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

#ifdef PICO_SUPPORT_MM
    pico_mem_init(64 * 1024);
#endif
    pico_stack_init();
    /* Parse args */
    while(1) {
        c = getopt_long(argc, argv, "v:b:t:a:r:hl", long_options, &option_idx);
        if (c < 0)
            break;

        switch(c) {
        case 'h':
            usage(argv[0]);
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
            }

#endif
        }
        break;
        case 'v':
        {
            char *nxt, *name = NULL, *sock = NULL, *addr = NULL, *nm = NULL, *gw = NULL, *addr6 = NULL, *nm6 = NULL, *gw6 = NULL, *loss_in = NULL, *loss_out = NULL ;
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

            macaddr[4] ^= (getpid() >> 8);
            macaddr[5] ^= (getpid() & 0xFF);
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
            }
#endif
            if (loss_in && (strlen(loss_in) > 0)) {
                i_pc = atoi(loss_in);
            }
            if (loss_out && (strlen(loss_out) > 0)) {
                o_pc = atoi(loss_out);
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

            macaddr[4] ^= (getpid() >> 8);
            macaddr[5] ^= (getpid() & 0xFF);
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
                                                    } else IF_APPNAME("mdns") {
#ifndef PICO_SUPPORT_MDNS
                                                            return 0;
#else
                                                            app_mdns(args);
#endif
#ifdef PICO_SUPPORT_SNTP_CLIENT
                                                        }else IF_APPNAME("sntp") {
                                                                app_sntp(args);
#endif
                                                        } else IF_APPNAME("bcast") {
                                                                struct pico_ip4 any = {
                                                                    .addr = 0xFFFFFFFFu
                                                                };

                                                                struct pico_socket *s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &__wakeup);
                                                                pico_socket_sendto(s, "abcd", 5u, &any, 1000);

                                                                pico_socket_sendto(s, "abcd", 5u, &bcastAddr, 1000);
                                                            } else IF_APPNAME("noop") {
                                                                    app_noop();
                                                                } else IF_APPNAME("olsr") {
                                                                        pico_olsr_init();
                                                                        dev = pico_get_device("pic0");
                                                                        if(dev) {
                                                                            pico_olsr_add(dev);
                                                                        }

                                                                        dev = pico_get_device("pic1");
                                                                        if(dev) {
                                                                            pico_olsr_add(dev);
                                                                        }

                                                                        app_noop();
                                                                    } else IF_APPNAME("slaacv4"){
#ifndef PICO_SUPPORT_SLAACV4
                                                                            return 0;
#else
                                                                            app_slaacv4(args);
#endif
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

    printf("%s: launching PicoTCP loop\n", __FUNCTION__);
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
