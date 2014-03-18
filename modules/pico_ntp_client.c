/*********************************************************************
    PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
    See LICENSE and COPYING for usage.

    Author: Toon Stegen
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_NTP_CLIENT

#define ntp_dbg(...) do {} while(0)
/* #define ntp_dbg dbg */

#define IPV6 6
#define IPV4 4

/* Disable IPV6 support for now */
#ifdef PICO_SUPPORT_IPV6
#undef PICO_SUPPORT_IPV6
#endif

/* Global parameters as by RFC5905 */
#define PORT      123      /* NTP port number                 */
#define VERSION   4        /* NTP version number              */ 
#define TOLERANCE 15e-6    /* frequency tolerance PHI (s/s)   */
#define MINPOLL   4        /* minimum poll exponent (16 s)    */
#define MAXPOLL   17       /* maximum poll exponent (36 h)    */
#define MAXDISP   16       /* maximum dispersion (16 s)       */
#define MINDISP   .005     /* minimum dispersion increment (s)*/
#define MAXDIST   1        /* distance threshold (1 s)        */
#define MAXSTRAT  16       /* maximum stratum number          */ 


static uint16_t ntp_port = 123;

struct pico_ip4 inaddr_any = { };

PACKED_STRUCT_DEF pico_ntp_timestamp
{
    uint32_t sec;       /* Seconds */
    uint32_t frac;      /* Fraction */
}

PACKED_STRUCT_DEF pico_ntp_header
{
    uint8_t li : 2;     /* Leap indicator */
    uint8_t stat : 6;   /* Status */
    uint8_t type;       /* Type */
    uint16_t prec;      /* Precision */
    uint32_t est_err;   /* Estimated Error*/
    uint32_t est_dr;    /* Estimated drift rate*/
    uint32_t ref_id;    /* Reference clock ID */
    struct pico_ntp_timestamp ref_ts;    /* Reference time stamp */
    struct pico_ntp_timestamp orig_ts;   /* Originate time stamp */
    struct pico_ntp_timestamp recv_ts;   /* Receive time stamp */
    struct pico_ntp_timestamp trs_ts;    /* Transmit time stamp */

};

static void pico_ntp_send(struct pico_socket *sock, void *dst)
{

    pico_socket_sendto(sock, buf, len, &dst, ntp_port);
}

static void pico_ntp_parse(char *buf, int len)
{
    struct pico_ntp_header * header;
    printf("To parse:%s, length:%d", buf, len);
    header = (struct pico_ntp_header*) buf;
}

/* callback for UDP socket events */
static void pico_ntp_client_wakeup(uint16_t ev, struct pico_socket *s)
{
    char recvbuf[1400];
    int read = 0;
    uint32_t peer;
    uint16_t port;
    int len = 1400;

    /* process read event, data available */
    if (ev == PICO_SOCK_EV_RD) {
        /* receive while data available in socket buffer */
        do {
            read = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port);
        } while(read > 0);
        pico_ntp_parse(recvbuf, len);
    }
    /* process error event, socket error occured */
    else if(ev == PICO_SOCK_EV_ERR) {
        printf("Socket Error received. Bailing out.\n");
        exit(1);
    }
    printf("Received data from %08X:%u\n", peer, port);
}


/* used for getting a response from DNS servers */
static void dnsCallback(char *ip, void *arg)
{
    int *version = (int*) arg;
    struct pico_ip4 ipv4;
    struct pico_socket *sock;

    if(version)
    {
        dbg("No ip version specified\n");
        return;
    }

    if(ip)
    {
        /* add the ip address to the client, and start a tcp connection socket */
        pico_string_to_ipv4(ip, &ipv4.addr);
        sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_ntp_client_wakeup);

        if (!sock)
            exit(1);
        /* bind the socket to port */
        if (pico_socket_bind(sock, &inaddr_any, &ntp_port) != 0)
            exit(1);
        pico_ntp_send(sock, &ip);
    }
    else
    {
        /* wakeup client and let know error occured */
    }
    if (arg)
        PICO_FREE(arg);
}


int pico_ntp_sync(char *ntp_server)
{
    int ip6 = IPV6;
    int ip4 = IPV4;

    if (ntp_server == NULL)
        return -1;

#ifdef PICO_SUPPORT_IPV6
    if(pico_dns_client_getaddr6(ntp_server, &dnsCallback, &ip6))
        return 0;
#endif
    if(pico_dns_client_getaddr6(ntp_server, &dnsCallback, &ip4))
        return 0;

    return -1;
}

#endif /* PICO_SUPPORT_NTP_CLIENT */
