/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Author: Toon Stegen
 *********************************************************************/
#include "pico_sntp_client.h"
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"
#include "pico_stack.h"

#ifdef PICO_SUPPORT_SNTP_CLIENT

#ifdef DEBUG_SNTP
#define sntp_dbg dbg
#else
#define sntp_dbg(...) do {} while(0)
#endif

#define SNTP_VERSION 4
#define PICO_SNTP_MAXBUF (1400)

/* Sntp mode */
#define SNTP_MODE_CLIENT 3

/* SNTP conversion parameters */
#define SNTP_FRAC_TO_PICOSEC (4294967llu)
#define SNTP_THOUSAND (1000llu)
#define SNTP_UNIX_OFFSET (2208988800llu)    /* nr of seconds from 1900 to 1970 */
#define SNTP_BITMASK (0X00000000FFFFFFFF)   /* mask to convert from 64 to 32 */

PACKED_STRUCT_DEF pico_sntp_ts
{
    uint32_t sec;       /* Seconds */
    uint32_t frac;      /* Fraction */
};

PACKED_STRUCT_DEF pico_sntp_header
{
    uint8_t mode : 3;   /* Mode */
    uint8_t vn : 3;     /* Version number */
    uint8_t li : 2;     /* Leap indicator */
    uint8_t stratum;    /* Stratum */
    uint8_t poll;       /* Poll, only significant in server messages */
    uint8_t prec;       /* Precision, only significant in server messages */
    int32_t rt_del;     /* Root delay, only significant in server messages */
    int32_t rt_dis;     /* Root dispersion, only significant in server messages */
    int32_t ref_id;     /* Reference clock ID, only significant in server messages */
    struct pico_sntp_ts ref_ts;    /* Reference time stamp */
    struct pico_sntp_ts orig_ts;   /* Originate time stamp */
    struct pico_sntp_ts recv_ts;   /* Receive time stamp */
    struct pico_sntp_ts trs_ts;    /* Transmit time stamp */

};

struct sntp_server_ns_cookie
{
    int rec;                    /* Indicates wheter an sntp packet has been received */
    uint16_t proto;             /* IPV4 or IPV6 prototype */
    pico_time stamp;            /* Timestamp of the moment the sntp packet is sent */
    char *hostname;             /* Hostname of the (s)ntp server*/
    struct pico_socket *sock;   /* Socket which contains the cookie */
    void (*cb_synced)(pico_err_t status);    /* Callback function for telling the user
                                                wheter/when the time is synchronised */
    uint32_t timer;   /* Timer that will signal timeout */
};

/* global variables */
static uint16_t sntp_port = 123u;
static struct pico_timeval server_time = {
    0
};
static pico_time tick_stamp = 0ull;
static union pico_address sntp_inaddr_any = {
    .ip6.addr = { 0 }
};

/*************************************************************************/

/* Converts a sntp time stamp to a pico_timeval struct */
static int timestamp_convert(const struct pico_sntp_ts *ts, struct pico_timeval *tv, pico_time delay)
{
    if(long_be(ts->sec) < SNTP_UNIX_OFFSET) {
        pico_err = PICO_ERR_EINVAL;
        tv->tv_sec = 0;
        tv->tv_msec = 0;
        sntp_dbg("Error: input too low\n");
        return -1;
    }

    sntp_dbg("Delay: %lu\n", delay);
    tv->tv_msec = (pico_time) (((uint32_t)(long_be(ts->frac))) / SNTP_FRAC_TO_PICOSEC + delay);
    tv->tv_sec = (pico_time) (long_be(ts->sec) - SNTP_UNIX_OFFSET + (uint32_t)tv->tv_msec / SNTP_THOUSAND);
    tv->tv_msec = (uint32_t) (tv->tv_msec & SNTP_BITMASK) % SNTP_THOUSAND;
    sntp_dbg("Converted time stamp: %lusec, %lumsec\n", tv->tv_sec, tv->tv_msec);
    return 0;
}

/* Cleanup function that is called when the time is synced or an error occured */
static void pico_sntp_cleanup(struct sntp_server_ns_cookie *ck, pico_err_t status)
{
    sntp_dbg("Cleanup called\n");
    if(!ck)
        return;

    pico_timer_cancel(ck->timer);

    ck->cb_synced(status);
    if(ck->sock)
        ck->sock->priv = NULL;

    sntp_dbg("FREE!\n");
    PICO_FREE(ck->hostname);
    PICO_FREE(ck);

}

/* Extracts the current time from a server sntp packet*/
static int pico_sntp_parse(char *buf, struct sntp_server_ns_cookie *ck)
{
    int ret = 0;
    struct pico_sntp_header *hp = (struct pico_sntp_header*) buf;

    if(!ck) {
        sntp_dbg("pico_sntp_parse: invalid cookie\n");
        return -1;
    }

    sntp_dbg("Received mode: %u, version: %u, stratum: %u\n", hp->mode, hp->vn, hp->stratum);

    tick_stamp = pico_tick;
    /* tick_stamp - ck->stamp is the delay between sending and receiving the ntp packet */
    ret = timestamp_convert(&(hp->trs_ts), &server_time, (tick_stamp - ck->stamp) / 2);
    if(ret != 0) {
        sntp_dbg("Conversion error!\n");
        pico_sntp_cleanup(ck, PICO_ERR_EINVAL);
        return ret;
    }

    sntp_dbg("Server time: %lu seconds and %lu milisecs since 1970\n", server_time.tv_sec,  server_time.tv_msec);

    /* Call back the user saying the time is synced */
    pico_sntp_cleanup(ck, PICO_ERR_NOERR);
    return ret;
}

/* callback for UDP socket events */
static void pico_sntp_client_wakeup(uint16_t ev, struct pico_socket *s)
{
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)s->priv;
    char *recvbuf;
    int read = 0;
    uint32_t peer;
    uint16_t port;

    if(!ck) {
        sntp_dbg("pico_sntp_client_wakeup: invalid cookie\n");
        return;
    }

    /* process read event, data available */
    if (ev == PICO_SOCK_EV_RD) {
        ck->rec = 1;
        /* receive while data available in socket buffer */
        recvbuf = PICO_ZALLOC(PICO_SNTP_MAXBUF);
        if (!recvbuf)
            return;

        do {
            read = pico_socket_recvfrom(s, recvbuf, PICO_SNTP_MAXBUF, &peer, &port);
        } while(read > 0);
        pico_sntp_parse(recvbuf, s->priv);
        s->priv = NULL; /* make sure UDP callback does not try to read from freed mem again */
        PICO_FREE(recvbuf);
    }
    /* socket is closed */
    else if(ev == PICO_SOCK_EV_CLOSE) {
        sntp_dbg("Socket is closed. Bailing out.\n");
        pico_sntp_cleanup(ck, PICO_ERR_ENOTCONN);
        return;
    }
    /* process error event, socket error occured */
    else if(ev == PICO_SOCK_EV_ERR) {
        sntp_dbg("Socket Error received. Bailing out.\n");
        pico_sntp_cleanup(ck, PICO_ERR_ENOTCONN);
        return;
    }

    sntp_dbg("Received data from %08X:%u\n", peer, port);
}

/* Function that is called after the receive timer expires */
static void sntp_receive_timeout(pico_time now, void *arg)
{
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)arg;
    (void) now;

    if(!ck) {
        sntp_dbg("sntp_timeout: invalid cookie\n");
        return;
    }

    if(!ck->rec) {
        pico_sntp_cleanup(ck, PICO_ERR_ETIMEDOUT);
    }
}

/* Sends an sntp packet on sock to dst*/
static void pico_sntp_send(struct pico_socket *sock, union pico_address *dst)
{
    struct pico_sntp_header header = {
        0
    };
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)sock->priv;

    if(!ck) {
        sntp_dbg("pico_sntp_sent: invalid cookie\n");
        return;
    }

    ck->timer = pico_timer_add(5000, sntp_receive_timeout, ck);
    if (!ck->timer) {
        sntp_dbg("SNTP: Failed to start timeout timer\n");
        pico_sntp_cleanup(ck, pico_err);
        pico_socket_close(sock);
        pico_socket_del(sock);
        return;
    }
    header.vn = SNTP_VERSION;
    header.mode = SNTP_MODE_CLIENT;
    /* header.trs_ts.frac = long_be(0ul); */
    ck->stamp = pico_tick;
    pico_socket_sendto(sock, &header, sizeof(header), dst, short_be(sntp_port));
}

static int pico_sntp_sync_start(struct sntp_server_ns_cookie *ck, union pico_address *addr)
{
    uint16_t any_port = 0;
    struct pico_socket *sock;

    sock = pico_socket_open(ck->proto, PICO_PROTO_UDP, &pico_sntp_client_wakeup);
    if (!sock)
        return -1;

    sock->priv = ck;
    ck->sock = sock;
    if ((pico_socket_bind(sock, &sntp_inaddr_any, &any_port) < 0)) {
        pico_socket_close(sock);
        return -1;
    }
    pico_sntp_send(sock, addr);

    return 0;
}

#ifdef PICO_SUPPORT_DNS_CLIENT
/* used for getting a response from DNS servers */
static void dnsCallback(char *ip, void *arg)
{
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)arg;
    union pico_address address;
    int retval = -1;

    if(!ck) {
        sntp_dbg("dnsCallback: Invalid argument\n");
        return;
    }

    if(ck->proto == PICO_PROTO_IPV6) {
#ifdef PICO_SUPPORT_IPV6
        if (ip) {
            /* add the ip address to the client, and start a tcp connection socket */
            sntp_dbg("using IPv6 address: %s\n", ip);
            retval = pico_string_to_ipv6(ip, address.ip6.addr);
        } else {
            sntp_dbg("Invalid query response for AAAA\n");
            retval = -1;
            pico_sntp_cleanup(ck, PICO_ERR_ENETDOWN);
        }
#endif
    } else if(ck->proto == PICO_PROTO_IPV4) {
#ifdef PICO_SUPPORT_IPV4
        if(ip) {
            sntp_dbg("using IPv4 address: %s\n", ip);
            retval = pico_string_to_ipv4(ip, (uint32_t *)&address.ip4.addr);
        } else {
            sntp_dbg("Invalid query response for A\n");
            retval = -1;
            pico_sntp_cleanup(ck, PICO_ERR_ENETDOWN);
        }
#endif
    }

    if (retval >= 0) {
        retval = pico_sntp_sync_start(ck, &address);
        if (retval < 0)
            pico_sntp_cleanup(ck, PICO_ERR_ENOTCONN);
    }
}
#endif

#ifdef PICO_SUPPORT_IPV4
#ifdef PICO_SUPPORT_DNS_CLIENT
static int pico_sntp_sync_start_dns_ipv4(const char *sntp_server, void (*cb_synced)(pico_err_t status))
{
    int retval = -1;
    struct sntp_server_ns_cookie *ck;
    /* IPv4 query */
    ck = PICO_ZALLOC(sizeof(struct sntp_server_ns_cookie));
    if (!ck) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ck->proto = PICO_PROTO_IPV4;
    ck->stamp = 0ull;
    ck->rec = 0;
    ck->sock = NULL;
    ck->hostname = PICO_ZALLOC(strlen(sntp_server) + 1);
    if (!ck->hostname) {
        PICO_FREE(ck);
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    strcpy(ck->hostname, sntp_server);

    ck->cb_synced = cb_synced;

    sntp_dbg("Resolving A %s\n", ck->hostname);
    retval = pico_dns_client_getaddr(sntp_server, &dnsCallback, ck);
    if (retval != 0) {
        PICO_FREE(ck->hostname);
        PICO_FREE(ck);
        return -1;
    }

    return 0;
}
#endif
static int pico_sntp_sync_start_ipv4(union pico_address *addr, void (*cb_synced)(pico_err_t status))
{
    int retval = -1;
    struct sntp_server_ns_cookie *ck;
    ck = PICO_ZALLOC(sizeof(struct sntp_server_ns_cookie));
    if (!ck) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ck->proto = PICO_PROTO_IPV4;
    ck->stamp = 0ull;
    ck->rec = 0;
    ck->sock = NULL;
    /* Set the given IP address as hostname, allocate the maximum IPv4 string length  + 1 */
    ck->hostname = PICO_ZALLOC(15 + 1);
    if (!ck->hostname) {
        PICO_FREE(ck);
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    retval = pico_ipv4_to_string(ck->hostname, addr->ip4.addr);
    if (retval < 0) {
        PICO_FREE(ck->hostname);
        PICO_FREE(ck);
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    ck->cb_synced = cb_synced;

    retval = pico_sntp_sync_start(ck, addr);
    if (retval < 0) {
        pico_sntp_cleanup(ck, PICO_ERR_ENOTCONN);
        return -1;
    }

    return 0;
}
#endif

#ifdef PICO_SUPPORT_IPV6
#ifdef PICO_SUPPORT_DNS_CLIENT
static int pico_sntp_sync_start_dns_ipv6(const char *sntp_server, void (*cb_synced)(pico_err_t status))
{
    struct sntp_server_ns_cookie *ck6;
    int  retval6 = -1;
    /* IPv6 query */
    ck6 = PICO_ZALLOC(sizeof(struct sntp_server_ns_cookie));
    if (!ck6) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ck6->proto = PICO_PROTO_IPV6;
    ck6->hostname = PICO_ZALLOC(strlen(sntp_server) + 1);
    if (!ck6->hostname) {
        PICO_FREE(ck6);
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    strcpy(ck6->hostname, sntp_server);
    ck6->proto = PICO_PROTO_IPV6;
    ck6->stamp = 0ull;
    ck6->rec = 0;
    ck6->sock = NULL;
    ck6->cb_synced = cb_synced;
    sntp_dbg("Resolving AAAA %s\n", ck6->hostname);
    retval6 = pico_dns_client_getaddr6(sntp_server, &dnsCallback, ck6);
    if (retval6 != 0) {
        PICO_FREE(ck6->hostname);
        PICO_FREE(ck6);
        return -1;
    }

    return 0;
}
#endif
static int pico_sntp_sync_start_ipv6(union pico_address *addr, void (*cb_synced)(pico_err_t status))
{
    struct sntp_server_ns_cookie *ck6;
    int  retval6 = -1;
    ck6 = PICO_ZALLOC(sizeof(struct sntp_server_ns_cookie));
    if (!ck6) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ck6->proto = PICO_PROTO_IPV6;
    ck6->stamp = 0ull;
    ck6->rec = 0;
    ck6->sock = NULL;
    ck6->cb_synced = cb_synced;
    /* Set the given IP address as hostname, allocate the maximum IPv6 string length + 1 */
    ck6->hostname = PICO_ZALLOC(39 + 1);
    if (!ck6->hostname) {
        PICO_FREE(ck6);
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    retval6 = pico_ipv6_to_string(ck6->hostname, addr->ip6.addr);
    if (retval6 < 0) {
        PICO_FREE(ck6->hostname);
        PICO_FREE(ck6);
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    retval6 = pico_sntp_sync_start(ck6, addr);
    if (retval6 < 0) {
        pico_sntp_cleanup(ck6, PICO_ERR_ENOTCONN);
        return -1;
    }

    return 0;
}
#endif

/* user function to sync the time from a given sntp source in string notation, DNS resolution is needed */
int pico_sntp_sync(const char *sntp_server, void (*cb_synced)(pico_err_t status))
{
#ifdef PICO_SUPPORT_DNS_CLIENT
    int retval4 = -1, retval6 = -1;
    if (sntp_server == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if(cb_synced == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

#ifdef PICO_SUPPORT_IPV4
    retval4 = pico_sntp_sync_start_dns_ipv4(sntp_server, cb_synced);
#endif
#ifdef PICO_SUPPORT_IPV6
    retval6 = pico_sntp_sync_start_dns_ipv6(sntp_server, cb_synced);
#endif

    if (retval4 != 0 && retval6 != 0)
        return -1;

    return 0;
#else
    sntp_debug("No DNS support available\n");
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
#endif
}

/* user function to sync the time from a given sntp source in pico_address notation */
int pico_sntp_sync_ip(union pico_address *sntp_addr, void (*cb_synced)(pico_err_t status))
{
    int retval4 = -1, retval6 = -1;
    if (sntp_addr == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (cb_synced == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

#ifdef PICO_SUPPORT_IPV4
    retval4 = pico_sntp_sync_start_ipv4(sntp_addr, cb_synced);
#endif
#ifdef PICO_SUPPORT_IPV6
    retval6 = pico_sntp_sync_start_ipv6(sntp_addr, cb_synced);
#endif

    if (retval4 != 0 && retval6 != 0)
        return -1;

    return 0;
}

/* user function to get the current time */
int pico_sntp_gettimeofday(struct pico_timeval *tv)
{
    pico_time diff, temp;
    uint32_t diffH, diffL;
    int ret = 0;
    if (tick_stamp == 0) {
        /* TODO: set pico_err */
        ret = -1;
        sntp_dbg("Error: Unsynchronised\n");
        return ret;
    }

    diff = pico_tick - tick_stamp;
    diffL = ((uint32_t) (diff & SNTP_BITMASK)) / 1000;
    diffH = ((uint32_t) (diff >> 32)) / 1000;

    temp = server_time.tv_msec + (uint32_t)(diff & SNTP_BITMASK) % SNTP_THOUSAND;
    tv->tv_sec = server_time.tv_sec + ((uint64_t)diffH << 32) + diffL + (uint32_t)temp / SNTP_THOUSAND;
    tv->tv_msec = (uint32_t)(temp & SNTP_BITMASK) % SNTP_THOUSAND;
    sntp_dbg("Time of day: %lu seconds and %lu milisecs since 1970\n", tv->tv_sec,  tv->tv_msec);
    return ret;
}

#endif /* PICO_SUPPORT_SNTP_CLIENT */
