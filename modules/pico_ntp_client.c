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

//#define ntp_dbg(...) do {} while(0)
#define ntp_dbg printf

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

#define NTP_VERSION 4

/* Ntp modes */
#define NTP_MODE_CLIENT 3
#define NTP_MODE_SERVER 4


uint16_t ntp_port = 123;

union pico_address ntp_inaddr_any = {.ip6.addr = {} };
struct pico_timeval
{
    pico_time tv_sec;
    pico_time tv_msec;
};

PACKED_STRUCT_DEF pico_ntp_ts
{
    uint32_t sec;       /* Seconds */
    int32_t frac;      /* Fraction */
};

PACKED_STRUCT_DEF pico_ntp_header
{
    uint8_t mode : 3;   /* Mode */
    uint8_t vn : 3;     /* Version number */
    uint8_t li : 2;     /* Leap indicator */
    uint8_t stratum;    /* Stratum */
    uint8_t poll;       /* Poll, only significant in server messages */
    uint8_t prec;       /* Precision, only significant in server messages */
    int32_t rt_del;    /* Root delay, only significant in server messages */
    int32_t rt_dis;    /* Root dispersion, only significant in server messages */
    int32_t ref_id;    /* Reference clock ID, only significant in server messages */
    struct pico_ntp_ts ref_ts;    /* Reference time stamp */
    struct pico_ntp_ts orig_ts;   /* Originate time stamp */
    struct pico_ntp_ts recv_ts;   /* Receive time stamp */
    struct pico_ntp_ts trs_ts;    /* Transmit time stamp */

};

static struct pico_timeval timestamp_convert(struct pico_ntp_ts *ts)
{
    struct pico_timeval tv;
    ntp_dbg("Inside timestamp convert function\n");
    tv.tv_sec = (pico_time) (long_be(ts->sec) - 0x83AA7E80);   /* nr of seconds from Jan 1, 1900 to Jan 1, 1970 */
    tv.tv_msec = (pico_time) (long_be(ts->frac)*232/1000000000);  //Temporary inaccurate solution
    return tv;
}

static void pico_ntp_send(struct pico_socket *sock, union pico_address *dst)
{
    struct pico_ntp_header header;

    header.li = 0;  /* no leap seconds */
    header.vn = NTP_VERSION;
    header.mode = NTP_MODE_CLIENT;
    header.stratum = 15;    /* secondary reference with highest stratum */

    pico_socket_sendto(sock, &header, sizeof(header), dst, short_be(ntp_port));
}

static void pico_ntp_parse(char *buf, int len)
{
    struct pico_ntp_header *hp;
    struct pico_timeval server_time;

    //ntp_dbg("To parse:%s, length:%d\n", buf, len);
    hp = (struct pico_ntp_header*) buf;
    ntp_dbg("Received mode: %u, version: %u, stratum: %u\n",hp->mode, hp->vn, hp->stratum);
    
    server_time = timestamp_convert(&(hp->trs_ts));
    ntp_dbg("Server time: %u seconds and %u milisecs since 1970\n",server_time.tv_sec, server_time.tv_msec);
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
        ntp_dbg("Socket Error received. Bailing out.\n");
        return;
    }
    ntp_dbg("Received data from %08X:%u\n", peer, port);
}


struct ntp_server_ns_cookie {
    uint16_t proto;
    char *hostname;
};

/* used for getting a response from DNS servers */
static void dnsCallback(char *ip, void *arg)
{
    struct ntp_server_ns_cookie *ck = (struct ntp_server_ns_cookie *)arg;
    union pico_address address;
    struct pico_socket *sock;
    int retval = -1;

    if(!ck)
    {
        ntp_dbg("dnsCallback: Invalid argument\n");
        return;
    }

    if(ck->proto == PICO_PROTO_IPV6)
    {
        if (ip) { 
            /* add the ip address to the client, and start a tcp connection socket */
            ntp_dbg("using IPv6 address: %s\n", ip);
            retval = pico_string_to_ipv6(ip, address.ip6.addr);
        }
    } else {
        if(ip) {
            ntp_dbg("using IPv4 address: %s\n", ip);
            retval = pico_string_to_ipv4(ip, &address.ip4.addr);
        } else {
            ntp_dbg("Invalid query response, cannot continue\n");
        }
    }

    if (retval >= 0) {
        sock = pico_socket_open(ck->proto, PICO_PROTO_UDP, &pico_ntp_client_wakeup);
        if ((sock) && (pico_socket_bind(sock, &ntp_inaddr_any, &ntp_port) == 0))
            pico_ntp_send(sock, &address);
    }
    ntp_dbg("FREE!\n");
    PICO_FREE(ck);
}


int pico_ntp_sync(char *ntp_server)
{
    struct ntp_server_ns_cookie *ck;
    struct ntp_server_ns_cookie *ck6;
    int retval = -1, retval6 = -1;
    if (ntp_server == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* IPv4 query */
    ck = PICO_ZALLOC(sizeof(struct ntp_server_ns_cookie));
    if (!ck) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    ck->proto = PICO_PROTO_IPV4;
    ck->hostname = PICO_ZALLOC(strlen(ntp_server));
    if (!ck->hostname) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    strcpy(ck->hostname, ntp_server);
#ifdef PICO_SUPPORT_IPV6
    /* IPv6 query */
    ck6 = PICO_ZALLOC(sizeof(struct ntp_server_ns_cookie));
    if (!ck6) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    ck6->proto = PICO_PROTO_IPV6;
    ck6->hostname = PICO_ZALLOC(strlen(ntp_server));
    if (!ck6->hostname) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    strcpy(ck6->hostname, ntp_server);
    ck6->proto = PICO_PROTO_IPV6;
    ntp_dbg("Resolving AAAA %s\n", ck6->hostname);
    retval6 = pico_dns_client_getaddr6(ntp_server, &dnsCallback, ck6);
#endif
    ntp_dbg("Resolving A %s\n", ck->hostname);
    retval = pico_dns_client_getaddr(ntp_server, &dnsCallback, ck);

    if (!retval || !retval6)
        return 0;
    return -1;
}

#endif /* PICO_SUPPORT_NTP_CLIENT */
