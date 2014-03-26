/*********************************************************************
    PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
    See LICENSE and COPYING for usage.

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

#ifdef PICO_SUPPORT_SNTP_CLIENT

#define sntp_dbg(...) do {} while(0)
/*#define sntp_dbg printf*/

#define SNTP_VERSION 4

/* Sntp mode */
#define SNTP_MODE_CLIENT 3

/* SNTP conversion parameters */
#define SNTP_FRAC_TO_PICOSEC (4294967295llu)
#define SNTP_THOUSAND (1000llu)
#define SNTP_UNIX_OFFSET (2208988800llu) /* nr of seconds from 1900 to 1970 */


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
enum state_en
{
    SNTP_UNRES = 0, SNTP_SENT = 1, SNTP_RECV = 2, SNTP_SYNC = 3,
};

struct sntp_server_ns_cookie
{
    enum state_en state;    /* state of the ntp client */
    uint16_t proto;         /* IPV4 or IPV6 prototype */
    pico_time stamp;        /* Timestamp of the moment the sntp packet is sent */
    char *hostname;         /* Hostname of the (s)ntp server*/
    void (*cb_synced)(pico_err_t status);    /* Callback function for telling the user wheter/when the time is synchronised */
};

/* global variables */
static uint16_t sntp_port = 123u;
static struct pico_timeval server_time = {
    0
};
static pico_time tick_stamp = 0ull;
static union pico_address sntp_inaddr_any = {
    .ip6.addr = {}
};

/*************************************************************************/

/* Converts a sntp time stamp to a pico_timeval struct */
static int timestamp_convert(struct pico_sntp_ts *ts, struct pico_timeval *tv, pico_time delay)
{
    if(long_be(ts->sec) < SNTP_UNIX_OFFSET) {
        pico_err = PICO_ERR_EINVAL;
        tv->tv_sec = 0;
        tv->tv_msec = 0;
        sntp_dbg("Error: input too low\n");
        return -1;
    }

    sntp_dbg("Delay: %llu\n", delay);
    tv->tv_msec = (pico_time) (((uint64_t)(long_be(ts->frac))) * SNTP_THOUSAND / SNTP_FRAC_TO_PICOSEC + delay);
    tv->tv_sec = (pico_time) (long_be(ts->sec) - SNTP_UNIX_OFFSET + tv->tv_msec / SNTP_THOUSAND);
    tv->tv_msec %= SNTP_THOUSAND;
    return 0;
}

static void pico_sntp_cleanup(struct sntp_server_ns_cookie *ck, pico_err_t status)
{
    ck->cb_synced(status);
    sntp_dbg("FREE!\n");
    PICO_FREE(ck->hostname);
    PICO_FREE(ck);
}

/* Extracts the current time from a server sntp packet*/
static int pico_sntp_parse(char *buf, struct sntp_server_ns_cookie *ck)
{
    int ret = 0;
    struct pico_sntp_header *hp = (struct pico_sntp_header*) buf;
    sntp_dbg("Received mode: %u, version: %u, stratum: %u\n", hp->mode, hp->vn, hp->stratum);

    tick_stamp = pico_tick;
    /* tick_stamp - ck->stamp is the delay between sending and receiving the ntp packet */
    ret = timestamp_convert(&(hp->trs_ts), &server_time, (tick_stamp - ck->stamp) / 2);
    if(ret != 0) {
        sntp_dbg("Conversion error!\n");
        pico_sntp_cleanup(ck, PICO_ERR_EINVAL);
        return ret;
    }

    sntp_dbg("Server time: %llu seconds and %llu milisecs since 1970\n", server_time.tv_sec,  server_time.tv_msec);

    /* Call back the user saying the time is synced */
    sntp_dbg("Changed ipv6 state to SYNC\n");
    ck->state = SNTP_SYNC;
    pico_sntp_cleanup(ck, PICO_ERR_NOERR);
    return ret;
}

/* callback for UDP socket events */
static void pico_sntp_client_wakeup(uint16_t ev, struct pico_socket *s)
{
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)s->priv;
    char recvbuf[1400];
    int read = 0;
    uint32_t peer;
    uint16_t port;

    /* process read event, data available */
    if (ev == PICO_SOCK_EV_RD) {
        sntp_dbg("Changed ipv6 state to RECV\n");
        ck->state = SNTP_RECV;
        /* receive while data available in socket buffer */
        do {
            read = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port);
        } while(read > 0);
        pico_sntp_parse(recvbuf, s->priv);
    }
    /* process error event, socket error occured */
    else if(ev == PICO_SOCK_EV_ERR) {
        sntp_dbg("Socket Error received. Bailing out.\n");
        pico_sntp_cleanup(ck, PICO_ERR_ENOTCONN);
        return;
    }

    sntp_dbg("Received data from %08X:%u\n", peer, port);
}

static void sntp_timeout(pico_time __attribute__((unused)) now, void *arg)
{
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)arg;
    if(ck->state == SNTP_SENT) {
        sntp_dbg("cb_sync called with error\n");
        pico_sntp_cleanup(ck, PICO_ERR_ETIMEDOUT);
    }

    sntp_dbg("Timer expired! State: %d \n", ck->state);
}

/* Sends an sntp packet on sock to dst*/
static void pico_sntp_send(struct pico_socket *sock, union pico_address *dst)
{
    struct pico_sntp_header header = {
        0
    };
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)sock->priv;

    pico_timer_add(5000, sntp_timeout, ck);
    header.vn = SNTP_VERSION;
    header.mode = SNTP_MODE_CLIENT;
    /* header.trs_ts.frac = long_be(3865470566ul); */
    ck->stamp = pico_tick;
    pico_socket_sendto(sock, &header, sizeof(header), dst, short_be(sntp_port));
}

/* used for getting a response from DNS servers */
static void dnsCallback(char *ip, void *arg)
{
    struct sntp_server_ns_cookie *ck = (struct sntp_server_ns_cookie *)arg;
    union pico_address address;
    struct pico_socket *sock;
    int retval = -1;

    if(!ck) {
        sntp_dbg("dnsCallback: Invalid argument\n");
        return;
    }

#ifdef PICO_SUPPORT_IPV6
    if(ck->proto == PICO_PROTO_IPV6) {
        if (ip) {
            /* add the ip address to the client, and start a tcp connection socket */
            sntp_dbg("using IPv6 address: %s\n", ip);
            retval = pico_string_to_ipv6(ip, address.ip6.addr);
        }
    }

#endif
    if(ck->proto == PICO_PROTO_IPV4) {
        if(ip) {
            sntp_dbg("using IPv4 address: %s\n", ip);
            retval = pico_string_to_ipv4(ip, &address.ip4.addr);
        } else {
            sntp_dbg("Invalid query response, cannot continue\n");
            retval = -1;
            pico_sntp_cleanup(ck, PICO_ERR_ENETDOWN);
        }
    }

    if (retval >= 0) {
        sock = pico_socket_open(ck->proto, PICO_PROTO_UDP, &pico_sntp_client_wakeup);
        sock->priv = ck;
        if ((sock) && (pico_socket_bind(sock, &sntp_inaddr_any, &sntp_port) == 0)) {
            sntp_dbg("Changed state to SENT\n");
            ck->state = SNTP_SENT;
            sntp_dbg("State: %d \n", ck->state);
            pico_sntp_send(sock, &address);
        }
    }

    /* sntp_dbg("FREE!\n"); */
    /* PICO_FREE(ck); */
}

/* user function to sync the time from a given sntp source */
int pico_sntp_sync(const char *sntp_server, void (*cb_synced)(pico_err_t status))
{
    struct sntp_server_ns_cookie *ck;
    struct sntp_server_ns_cookie *ck6;
    int retval = -1, retval6 = -1;
    if (sntp_server == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* IPv4 query */
    ck = PICO_ZALLOC(sizeof(struct sntp_server_ns_cookie));
    if (!ck) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ck->proto = PICO_PROTO_IPV4;
    ck->stamp = 0ull;
    sntp_dbg("Changed state to UNRES\n");
    ck->state = SNTP_UNRES;
    ck->hostname = PICO_ZALLOC(strlen(sntp_server));
    if (!ck->hostname) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    strcpy(ck->hostname, sntp_server);

    if(cb_synced == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    ck->cb_synced = cb_synced;

#ifdef PICO_SUPPORT_IPV6
    /* IPv6 query */
    ck6 = PICO_ZALLOC(sizeof(struct sntp_server_ns_cookie));
    if (!ck6) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ck6->proto = PICO_PROTO_IPV6;
    ck6->hostname = PICO_ZALLOC(strlen(sntp_server));
    if (!ck6->hostname) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    strcpy(ck6->hostname, sntp_server);
    ck6->proto = PICO_PROTO_IPV6;
    ck6->stamp = 0ull;
    sntp_dbg("Changed ipv6 state to UNRES\n");
    ck6->state = SNTP_UNRES;
    ck6->cb_synced = cb_synced;
    sntp_dbg("Resolving AAAA %s\n", ck6->hostname);
    retval6 = pico_dns_client_getaddr6(sntp_server, &dnsCallback, ck6);
#endif
    sntp_dbg("Resolving A %s\n", ck->hostname);
    retval = pico_dns_client_getaddr(sntp_server, &dnsCallback, ck);

    if (!retval || !retval6)
        return 0;

    return -1;
}

/* user function to get the current time */
int pico_sntp_gettimeofday(struct pico_timeval *tv)
{
    pico_time diff, temp;
    int ret = 0;
    if (tick_stamp == 0) {
        /* TODO: set pico_err */
        ret = -1;
        sntp_dbg("Error: Unsynchronised\n");
        return ret;
    }

    diff = pico_tick - tick_stamp;
    temp = server_time.tv_msec + diff % SNTP_THOUSAND;
    tv->tv_sec = server_time.tv_sec + diff / SNTP_THOUSAND + temp / SNTP_THOUSAND;
    tv->tv_msec = temp % SNTP_THOUSAND;
    sntp_dbg("Time of day: %llu seconds and %llu milisecs since 1970\n", tv->tv_sec,  tv->tv_msec);
    return ret;
}

#endif /* PICO_SUPPORT_SNTP_CLIENT */
