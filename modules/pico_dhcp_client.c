/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Kristof Roelants, Frederik Van Slycken
 *********************************************************************/


#include "pico_dhcp_client.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_eth.h"

#ifdef PICO_SUPPORT_DHCPC
#define dhcpc_dbg(...) do {} while(0)
/* #define dhcpc_dbg dbg */

/* timer values */
#define DHCP_CLIENT_REINIT             3000 /* msec */
#define DHCP_CLIENT_RETRANS            4 /* sec */
#define DHCP_CLIENT_RETRIES            3

#define DHCP_CLIENT_TIMER_STOPPED      0
#define DHCP_CLIENT_TIMER_STARTED      1

/* custom statuses */
#define DHCP_CLIENT_STATUS_INIT        0
#define DHCP_CLIENT_STATUS_SOCKET      1
#define DHCP_CLIENT_STATUS_BOUND       2
#define DHCP_CLIENT_STATUS_LINKED      3
#define DHCP_CLIENT_STATUS_TRANSMITTED 4
#define DHCP_CLIENT_STATUS_INITIALIZED 5

/* maximum size of a DHCP message */
#define DHCP_CLIENT_MAXMSGZISE         PICO_IP_MTU

/* serialize client negotiations if multiple devices */
/* NOTE: ONLY initialization is serialized! */
static uint8_t pico_dhcp_client_mutex = 1;

enum dhcp_client_state {
    DHCP_CLIENT_STATE_INIT_REBOOT = 0,
    DHCP_CLIENT_STATE_REBOOTING,
    DHCP_CLIENT_STATE_INIT,
    DHCP_CLIENT_STATE_SELECTING,
    DHCP_CLIENT_STATE_REQUESTING,
    DHCP_CLIENT_STATE_BOUND,
    DHCP_CLIENT_STATE_RENEWING,
    DHCP_CLIENT_STATE_REBINDING
};

struct dhcp_client_timer
{
    uint8_t state;
    uint32_t time;
};

struct pico_dhcp_client_cookie
{
    uint8_t status;
    uint8_t event;
    uint8_t retry;
    uint32_t xid;
    uint32_t *uid;
    enum dhcp_client_state state;
    void (*cb)(void*dhcpc, int code);
    pico_time init_timestamp;
    struct pico_socket *s;
    struct pico_ip4 address;
    struct pico_ip4 netmask;
    struct pico_ip4 gateway;
    struct pico_ip4 nameserver;
    struct pico_ip4 server_id;
    struct pico_device *dev;
    struct dhcp_client_timer init_timer;
    struct dhcp_client_timer requesting_timer;
    struct dhcp_client_timer renewing_timer;
    struct dhcp_client_timer rebinding_timer;
    struct dhcp_client_timer T1_timer;
    struct dhcp_client_timer T2_timer;
    struct dhcp_client_timer lease_timer;
};

static int pico_dhcp_client_init(struct pico_dhcp_client_cookie *dhcpc);
static int reset(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
static int8_t pico_dhcp_client_msg(struct pico_dhcp_client_cookie *dhcpc, uint8_t msg_type);
static void pico_dhcp_client_wakeup(uint16_t ev, struct pico_socket *s);
static void pico_dhcp_state_machine(uint8_t event, struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);

static int dhcp_cookies_cmp(void *ka, void *kb)
{
    struct pico_dhcp_client_cookie *a = ka, *b = kb;
    if (a->xid == b->xid)
        return 0;

    return (a->xid < b->xid) ? (-1) : (1);
}
PICO_TREE_DECLARE(DHCPCookies, dhcp_cookies_cmp);

static struct pico_dhcp_client_cookie *pico_dhcp_client_add_cookie(uint32_t xid, struct pico_device *dev, void (*cb)(void *dhcpc, int code), uint32_t *uid)
{
    struct pico_dhcp_client_cookie *dhcpc = NULL, *found = NULL, test = {
        0
    };

    test.xid = xid;
    found = pico_tree_findKey(&DHCPCookies, &test);
    if (found) {
        pico_err = PICO_ERR_EAGAIN;
        return NULL;
    }

    dhcpc = PICO_ZALLOC(sizeof(struct pico_dhcp_client_cookie));
    if (!dhcpc) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    dhcpc->state = DHCP_CLIENT_STATE_INIT;
    dhcpc->status = DHCP_CLIENT_STATUS_INIT;
    dhcpc->xid = xid;
    dhcpc->uid = uid;
    *(dhcpc->uid) = 0;
    dhcpc->cb = cb;
    dhcpc->dev = dev;

    pico_tree_insert(&DHCPCookies, dhcpc);
    return dhcpc;
}

static int pico_dhcp_client_del_cookie(uint32_t xid)
{
    struct pico_dhcp_client_cookie test = {
        0
    }, *found = NULL;

    test.xid = xid;
    found = pico_tree_findKey(&DHCPCookies, &test);
    if (!found)
        return -1;

    pico_socket_close(found->s);
    pico_ipv4_link_del(found->dev, found->address);
    pico_tree_delete(&DHCPCookies, found);
    PICO_FREE(found);
    return 0;
}

static struct pico_dhcp_client_cookie *pico_dhcp_client_find_cookie(uint32_t xid)
{
    struct pico_dhcp_client_cookie test = {
        0
    }, *found = NULL;

    test.xid = xid;
    found = pico_tree_findKey(&DHCPCookies, &test);
    if (found)
        return found;
    else
        return NULL;
}

static void pico_dhcp_client_init_timer(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;
    if (dhcpc->init_timer.state == DHCP_CLIENT_TIMER_STOPPED)
        return;

    if (++dhcpc->retry >= DHCP_CLIENT_RETRIES) {
        pico_err = PICO_ERR_EAGAIN;
        dhcpc->cb(dhcpc, PICO_DHCP_ERROR);
        pico_dhcp_client_del_cookie(dhcpc->xid);
        pico_dhcp_client_mutex++;
        return;
    }

    /* init_timer is restarted in retransmit function,
     * otherwise an old init_timer would go on indefinitely */
    dhcpc->event = PICO_DHCP_EVENT_RETRANSMIT;
    pico_dhcp_state_machine(dhcpc->event, dhcpc, NULL);
    return;
}

static void pico_dhcp_client_requesting_timer(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;

    if (dhcpc->requesting_timer.state == DHCP_CLIENT_TIMER_STOPPED)
        return;

    if (++dhcpc->retry > DHCP_CLIENT_RETRIES) {
        pico_dhcp_client_mutex++;
        reset(dhcpc, NULL);
        return;
    }

    /* requesting_timer is restarted in retransmit function,
     * otherwise an old requesting_timer would go on indefinitely */
    dhcpc->event = PICO_DHCP_EVENT_RETRANSMIT;
    pico_dhcp_state_machine(dhcpc->event, dhcpc, NULL);
    return;
}

static void pico_dhcp_client_renewing_timer(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;

    if (dhcpc->renewing_timer.state == DHCP_CLIENT_TIMER_STOPPED)
        return;

    /* renewing_timer is restarted in retransmit function,
     * otherwise an old renewing_timer would go on indefinitely */
    dhcpc->retry++;
    dhcpc->event = PICO_DHCP_EVENT_RETRANSMIT;
    pico_dhcp_state_machine(dhcpc->event, dhcpc, NULL);
    return;
}

static void pico_dhcp_client_rebinding_timer(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;

    if (dhcpc->rebinding_timer.state == DHCP_CLIENT_TIMER_STOPPED)
        return;

    /* rebinding_timer is restarted in retransmit function,
     * otherwise an old rebinding_timer would go on indefinitely */
    dhcpc->retry++;
    dhcpc->event = PICO_DHCP_EVENT_RETRANSMIT;
    pico_dhcp_state_machine(dhcpc->event, dhcpc, NULL);
    return;
}

static void pico_dhcp_client_T1_timer(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;

    if (dhcpc->T1_timer.state == DHCP_CLIENT_TIMER_STOPPED)
        return;

    /* T1 state is set to stopped in renew function,
     * otherwise an old T1 could stop a valid T1 */
    dhcpc->event = PICO_DHCP_EVENT_T1;
    pico_dhcp_state_machine(dhcpc->event, dhcpc, NULL);
    return;
}

static void pico_dhcp_client_T2_timer(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;

    if (dhcpc->T2_timer.state == DHCP_CLIENT_TIMER_STOPPED)
        return;

    /* T2 state is set to stopped in rebind function,
     * otherwise an old T2 could stop a valid T2.
     * Likewise for renewing_timer */
    dhcpc->event = PICO_DHCP_EVENT_T2;
    pico_dhcp_state_machine(dhcpc->event, dhcpc, NULL);
    return;
}

static void pico_dhcp_client_lease_timer(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;

    if (dhcpc->lease_timer.state == DHCP_CLIENT_TIMER_STOPPED)
        return;

    /* lease state is set to stopped in reset function,
     * otherwise an old lease could stop a valid lease.
     * Likewise for rebinding_timer */
    dhcpc->event = PICO_DHCP_EVENT_LEASE;
    pico_dhcp_state_machine(dhcpc->event, dhcpc, NULL);
    return;
}

static void pico_dhcp_client_reinit(pico_time now, void *arg)
{
    struct pico_dhcp_client_cookie *dhcpc = (struct pico_dhcp_client_cookie *)arg;
    (void) now;

    if (++dhcpc->retry > DHCP_CLIENT_RETRIES) {
        pico_err = PICO_ERR_EAGAIN;
        dhcpc->cb(dhcpc, PICO_DHCP_ERROR);
        pico_dhcp_client_del_cookie(dhcpc->xid);
        return;
    }

    pico_dhcp_client_init(dhcpc);
    return;
}

static void pico_dhcp_client_stop_timers(struct pico_dhcp_client_cookie *dhcpc)
{
    dhcpc->retry = 0;
    dhcpc->init_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->requesting_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->renewing_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->rebinding_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->T1_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->T2_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->lease_timer.state = DHCP_CLIENT_TIMER_STOPPED;

    return;
}

static void pico_dhcp_client_start_init_timer(struct pico_dhcp_client_cookie *dhcpc)
{
    uint32_t time = 0;

    /* timer value is doubled with every retry (exponential backoff) */
    dhcpc->init_timer.state = DHCP_CLIENT_TIMER_STARTED;
    dhcpc->init_timer.time = DHCP_CLIENT_RETRANS;
    time = dhcpc->init_timer.time << dhcpc->retry;
    pico_timer_add(time * 1000, pico_dhcp_client_init_timer, dhcpc);

    return;
}

static void pico_dhcp_client_start_requesting_timer(struct pico_dhcp_client_cookie *dhcpc)
{
    uint32_t time = 0;

    /* timer value is doubled with every retry (exponential backoff) */
    dhcpc->init_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->requesting_timer.state = DHCP_CLIENT_TIMER_STARTED;
    dhcpc->requesting_timer.time = DHCP_CLIENT_RETRANS;
    time = dhcpc->requesting_timer.time << dhcpc->retry;
    pico_timer_add(time * 1000, pico_dhcp_client_requesting_timer, dhcpc);

    return;
}

static void pico_dhcp_client_start_renewing_timer(struct pico_dhcp_client_cookie *dhcpc)
{
    uint32_t halftime = 0;

    /* wait one-half of the remaining time until T2, down to a minimum of 60 seconds */
    /* (dhcpc->retry + 1): initial -> divide by 2, 1st retry -> divide by 4, 2nd retry -> divide by 8, etc */
    dhcpc->T1_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->renewing_timer.state = DHCP_CLIENT_TIMER_STARTED;
    halftime = dhcpc->renewing_timer.time >> (dhcpc->retry + 1);
    if (halftime < 60)
        halftime = 60;

    pico_timer_add(halftime * 1000, pico_dhcp_client_renewing_timer, dhcpc);

    return;
}

static void pico_dhcp_client_start_rebinding_timer(struct pico_dhcp_client_cookie *dhcpc)
{
    uint32_t halftime = 0;

    /* wait one-half of the remaining time until T2, down to a minimum of 60 seconds */
    /* (dhcpc->retry + 1): initial -> divide by 2, 1st retry -> divide by 4, 2nd retry -> divide by 8, etc */
    dhcpc->T2_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->renewing_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->rebinding_timer.state = DHCP_CLIENT_TIMER_STARTED;
    halftime = dhcpc->rebinding_timer.time >> (dhcpc->retry + 1);
    if (halftime < 60)
        halftime = 60;

    pico_timer_add(halftime * 1000, pico_dhcp_client_rebinding_timer, dhcpc);

    return;
}

static void pico_dhcp_client_start_reacquisition_timers(struct pico_dhcp_client_cookie *dhcpc)
{
    dhcpc->requesting_timer.state = DHCP_CLIENT_TIMER_STOPPED;
    dhcpc->T1_timer.state = DHCP_CLIENT_TIMER_STARTED;
    dhcpc->T2_timer.state = DHCP_CLIENT_TIMER_STARTED;
    dhcpc->lease_timer.state = DHCP_CLIENT_TIMER_STARTED;
    pico_timer_add(dhcpc->T1_timer.time * 1000, pico_dhcp_client_T1_timer, dhcpc);
    pico_timer_add(dhcpc->T2_timer.time * 1000, pico_dhcp_client_T2_timer, dhcpc);
    pico_timer_add(dhcpc->lease_timer.time * 1000, pico_dhcp_client_lease_timer, dhcpc);

    return;
}

static int pico_dhcp_client_init(struct pico_dhcp_client_cookie *dhcpc)
{
    uint16_t port = PICO_DHCP_CLIENT_PORT;
    struct pico_ip4 inaddr_any = {
        0
    }, netmask = {
        0
    };

    /* serialize client negotations if multiple devices */
    /* NOTE: ONLY initialization is serialized! */
    if (!pico_dhcp_client_mutex) {
        pico_timer_add(DHCP_CLIENT_REINIT, pico_dhcp_client_reinit, dhcpc);
        return 0;
    }

    pico_dhcp_client_mutex--;

    switch (dhcpc->status)
    {
    case DHCP_CLIENT_STATUS_INIT:
        dhcpc->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dhcp_client_wakeup);
        if (!dhcpc->s) {
            pico_dhcp_client_mutex++;
            pico_timer_add(DHCP_CLIENT_REINIT, pico_dhcp_client_reinit, dhcpc);
            break;
        }

        dhcpc->s->dev = dhcpc->dev;
        dhcpc->status = DHCP_CLIENT_STATUS_SOCKET;
    /* fallthrough */

    case DHCP_CLIENT_STATUS_SOCKET:
        if (pico_socket_bind(dhcpc->s, &inaddr_any, &port) < 0) {
            pico_dhcp_client_mutex++;
            pico_timer_add(DHCP_CLIENT_REINIT, pico_dhcp_client_reinit, dhcpc);
            break;
        }

        dhcpc->status = DHCP_CLIENT_STATUS_BOUND;
    /* fallthrough */

    case DHCP_CLIENT_STATUS_BOUND:
        /* adding a link with address 0.0.0.0 and netmask 0.0.0.0,
         * automatically adds a route for a global broadcast */
        if (pico_ipv4_link_add(dhcpc->dev, inaddr_any, netmask) < 0) {
            pico_dhcp_client_mutex++;
            pico_timer_add(DHCP_CLIENT_REINIT, pico_dhcp_client_reinit, dhcpc);
            break;
        }

        dhcpc->status = DHCP_CLIENT_STATUS_LINKED;
    /* fallthrough */

    case DHCP_CLIENT_STATUS_LINKED:
        if (pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_DISCOVER) < 0) {
            pico_dhcp_client_mutex++;
            pico_timer_add(DHCP_CLIENT_REINIT, pico_dhcp_client_reinit, dhcpc);
            break;
        }

        dhcpc->status = DHCP_CLIENT_STATUS_TRANSMITTED;
    /* fallthrough */

    case DHCP_CLIENT_STATUS_TRANSMITTED:
        dhcpc->retry = 0;
        dhcpc->init_timestamp = PICO_TIME_MS();
        pico_dhcp_client_start_init_timer(dhcpc);
        break;

    default:
        return -1;
    }
    return 0;
}

int pico_dhcp_initiate_negotiation(struct pico_device *dev, void (*cb)(void *dhcpc, int code), uint32_t *uid)
{
    uint8_t retry = 32;
    uint32_t xid = 0;
    struct pico_dhcp_client_cookie *dhcpc = NULL;

    if (!dev || !cb || !uid) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (!dev->eth) {
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;
    }

    /* attempt to generate a correct xid, else fail */
    do {
        xid = pico_rand();
    } while (!xid && --retry);

    if (!xid) {
        pico_err = PICO_ERR_EAGAIN;
        return -1;
    }

    dhcpc = pico_dhcp_client_add_cookie(xid, dev, cb, uid);
    if (!dhcpc)
        return -1;

    dhcpc_dbg("DHCP client: cookie with xid %u\n", dhcpc->xid);
    return pico_dhcp_client_init(dhcpc);
}

static void pico_dhcp_client_recv_params(struct pico_dhcp_client_cookie *dhcpc, struct pico_dhcp_opt *opt)
{
    do {
        switch (opt->code)
        {
        case PICO_DHCP_OPT_PAD:
            break;

        case PICO_DHCP_OPT_END:
            break;

        case PICO_DHCP_OPT_MSGTYPE:
            dhcpc->event = opt->ext.msg_type.type;
            dhcpc_dbg("DHCP client: message type %u\n", dhcpc->event);
            break;

        case PICO_DHCP_OPT_LEASETIME:
            dhcpc->lease_timer.time = long_be(opt->ext.lease_time.time);
            dhcpc_dbg("DHCP client: lease time %u\n", dhcpc->lease_timer.time);
            break;

        case PICO_DHCP_OPT_RENEWALTIME:
            dhcpc->T1_timer.time = long_be(opt->ext.renewal_time.time);
            dhcpc_dbg("DHCP client: renewal time %u\n", dhcpc->T1_timer.time);
            break;

        case PICO_DHCP_OPT_REBINDINGTIME:
            dhcpc->T2_timer.time = long_be(opt->ext.rebinding_time.time);
            dhcpc_dbg("DHCP client: rebinding time %u\n", dhcpc->T2_timer.time);
            break;

        case PICO_DHCP_OPT_ROUTER:
            dhcpc->gateway = opt->ext.router.ip;
            dhcpc_dbg("DHCP client: router %08X\n", dhcpc->gateway.addr);
            break;

        case PICO_DHCP_OPT_DNS:
            dhcpc->nameserver = opt->ext.dns.ip;
            dhcpc_dbg("DHCP client: dns %08X\n", dhcpc->nameserver.addr);
            break;

        case PICO_DHCP_OPT_NETMASK:
            dhcpc->netmask = opt->ext.netmask.ip;
            dhcpc_dbg("DHCP client: netmask %08X\n", dhcpc->netmask.addr);
            break;

        case PICO_DHCP_OPT_SERVERID:
            dhcpc->server_id = opt->ext.server_id.ip;
            dhcpc_dbg("DHCP client: server ID %08X\n", dhcpc->server_id.addr);
            break;

        case PICO_DHCP_OPT_OPTOVERLOAD:
            dhcpc_dbg("DHCP client: WARNING option overload present (not processed)");
            break;

        default:
            dhcpc_dbg("DHCP client: WARNING unsupported option %u\n", opt->code);
            break;
        }
    } while (pico_dhcp_next_option(&opt));

    /* default values for T1 and T2 when not provided */
    if (!dhcpc->T1_timer.time)
        dhcpc->T1_timer.time = dhcpc->lease_timer.time >> 1;

    if (!dhcpc->T2_timer.time)
        dhcpc->T2_timer.time = (dhcpc->lease_timer.time * 875) / 1000;

    return;
}

static int recv_offer(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf)
{
    struct pico_dhcp_hdr *hdr = (struct pico_dhcp_hdr *)buf;
    struct pico_dhcp_opt *opt = (struct pico_dhcp_opt *)hdr->options;

    pico_dhcp_client_recv_params(dhcpc, opt);
    if ((dhcpc->event != PICO_DHCP_MSG_OFFER) || !dhcpc->server_id.addr || !dhcpc->netmask.addr || !dhcpc->lease_timer.time)
        return -1;

    dhcpc->address.addr = hdr->yiaddr;

    /* we skip state SELECTING, process first offer received */
    dhcpc->state = DHCP_CLIENT_STATE_REQUESTING;
    dhcpc->retry = 0;
    pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_REQUEST);
    pico_dhcp_client_start_requesting_timer(dhcpc);
    return 0;
}

static int recv_ack(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf)
{
    struct pico_dhcp_hdr *hdr = (struct pico_dhcp_hdr *)buf;
    struct pico_dhcp_opt *opt = (struct pico_dhcp_opt *)hdr->options;
    struct pico_ip4 address = {
        0
    }, netmask = {
        0
    }, bcast = {
        .addr = 0xFFFFFFFF
    };

    pico_dhcp_client_recv_params(dhcpc, opt);
    if ((dhcpc->event != PICO_DHCP_MSG_ACK) || !dhcpc->server_id.addr || !dhcpc->netmask.addr || !dhcpc->lease_timer.time)
        return -1;

    /* Issue #20 the server can transmit on ACK a different IP than the one in OFFER */
    /* RFC2131 ch 4.3.2 ... The client SHOULD use the parameters in the DHCPACK message for configuration */
    if (dhcpc->state == DHCP_CLIENT_STATE_REQUESTING)
        dhcpc->address.addr = hdr->yiaddr;


    /* close the socket used for address (re)acquisition */
    pico_socket_close(dhcpc->s);
    /* delete the link with address 0.0.0.0, add new link with acquired address */
    if (dhcpc->status == DHCP_CLIENT_STATUS_TRANSMITTED) {
        pico_ipv4_link_del(dhcpc->dev, address);
        pico_ipv4_link_add(dhcpc->dev, dhcpc->address, dhcpc->netmask);
        dhcpc->status = DHCP_CLIENT_STATUS_INITIALIZED;
    }

    /* delete the default route for our global broadcast messages, otherwise another interface can not rebind */
    if (dhcpc->state == DHCP_CLIENT_STATE_REBINDING)
        pico_ipv4_route_del(bcast, netmask, 1);

    dbg("DHCP client: renewal time (T1) %u\n", dhcpc->T1_timer.time);
    dbg("DHCP client: rebinding time (T2) %u\n", dhcpc->T2_timer.time);
    dbg("DHCP client: lease time %u\n", dhcpc->lease_timer.time);

    dhcpc->retry = 0;
    dhcpc->renewing_timer.time = dhcpc->T2_timer.time - dhcpc->T1_timer.time;
    dhcpc->rebinding_timer.time = dhcpc->lease_timer.time - dhcpc->T2_timer.time;
    pico_dhcp_client_start_reacquisition_timers(dhcpc);

    pico_dhcp_client_mutex++;
    *(dhcpc->uid) = dhcpc->xid;
    dhcpc->cb(dhcpc, PICO_DHCP_SUCCESS);
    dhcpc->state = DHCP_CLIENT_STATE_BOUND;
    return 0;
}

static int renew(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf)
{
    uint16_t port = PICO_DHCP_CLIENT_PORT;
    (void) buf;
    dhcpc->state = DHCP_CLIENT_STATE_RENEWING;
    dhcpc->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dhcp_client_wakeup);
    if (!dhcpc->s) {
        dhcpc_dbg("DHCP client ERROR: failure opening socket on renew, aborting DHCP! (%s)\n", strerror(pico_err));
        dhcpc->cb(dhcpc, PICO_DHCP_ERROR);
        return -1;
    }

    if (pico_socket_bind(dhcpc->s, &dhcpc->address, &port) != 0) {
        dhcpc_dbg("DHCP client ERROR: failure binding socket on renew, aborting DHCP! (%s)\n", strerror(pico_err));
        pico_socket_close(dhcpc->s);
        dhcpc->cb(dhcpc, PICO_DHCP_ERROR);
        return -1;
    }

    dhcpc->retry = 0;
    pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_REQUEST);
    pico_dhcp_client_start_renewing_timer(dhcpc);

    return 0;
}

static int rebind(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf)
{
    struct pico_ip4 bcast = {
        .addr = 0xFFFFFFFF
    }, netmask = {
        0
    }, inaddr_any = {
        0
    };
    (void) buf;

    dhcpc->state = DHCP_CLIENT_STATE_REBINDING;
    dhcpc->retry = 0;
    /* we need a default route for our global broadcast messages, otherwise they get dropped. */
    pico_ipv4_route_add(bcast, netmask, inaddr_any, 1, pico_ipv4_link_get(&dhcpc->address));
    pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_REQUEST);
    pico_dhcp_client_start_rebinding_timer(dhcpc);

    return 0;
}

static int reset(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf)
{
    struct pico_ip4 address = {
        0
    };
    (void) buf;

    if (dhcpc->state == DHCP_CLIENT_STATE_REQUESTING)
        address.addr = PICO_IP4_ANY;
    else
        address.addr = dhcpc->address.addr;

    /* close the socket used for address (re)acquisition */
    pico_socket_close(dhcpc->s);
    /* delete the link with the currently in use address */
    pico_ipv4_link_del(dhcpc->dev, address);

    dhcpc->cb(dhcpc, PICO_DHCP_RESET);
    if (dhcpc->state < DHCP_CLIENT_STATE_BOUND)
    {
        pico_dhcp_client_mutex++;
    }

    dhcpc->state = DHCP_CLIENT_STATE_INIT;
    dhcpc->status = DHCP_CLIENT_STATUS_INIT;
    pico_dhcp_client_stop_timers(dhcpc);
    pico_dhcp_client_init(dhcpc);
    return 0;
}

static int retransmit(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf)
{
    (void) buf;
    switch (dhcpc->state)
    {
    case DHCP_CLIENT_STATE_INIT:
        pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_DISCOVER);
        pico_dhcp_client_start_init_timer(dhcpc);
        break;

    case DHCP_CLIENT_STATE_REQUESTING:
        pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_REQUEST);
        pico_dhcp_client_start_requesting_timer(dhcpc);
        break;

    case DHCP_CLIENT_STATE_RENEWING:
        pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_REQUEST);
        pico_dhcp_client_start_renewing_timer(dhcpc);
        break;

    case DHCP_CLIENT_STATE_REBINDING:
        pico_dhcp_client_msg(dhcpc, PICO_DHCP_MSG_DISCOVER);
        pico_dhcp_client_start_rebinding_timer(dhcpc);
        break;

    default:
        dhcpc_dbg("DHCP client WARNING: retransmit in incorrect state (%u)!\n", dhcpc->state);
        return -1;
    }
    return 0;
}

struct dhcp_action_entry {
    int (*offer)(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
    int (*ack)(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
    int (*nak)(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
    int (*timer1)(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
    int (*timer2)(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
    int (*timer_lease)(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
    int (*timer_retransmit)(struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf);
};

static struct dhcp_action_entry dhcp_fsm[] =
{ /* event                |offer      |ack      |nak    |T1    |T2     |lease  |retransmit */
/* state init-reboot */
    { NULL,       NULL,     NULL,   NULL,  NULL,   NULL,  NULL       },
/* state rebooting   */ { NULL,       NULL,     NULL,   NULL,  NULL,   NULL,  NULL       },
/* state init        */ { recv_offer, NULL,     NULL,   NULL,  NULL,   NULL,  retransmit },
/* state selecting   */ { NULL,       NULL,     NULL,   NULL,  NULL,   NULL,  NULL       },
/* state requesting  */ { NULL,       recv_ack, reset,  NULL,  NULL,   NULL,  retransmit },
/* state bound       */ { NULL,       NULL,     NULL,   renew, NULL,   NULL,  NULL       },
/* state renewing    */ { NULL,       recv_ack, reset,  NULL,  rebind, NULL,  retransmit },
/* state rebinding   */ { NULL,       recv_ack, reset,  NULL,  NULL,   reset, retransmit },
};

/* TIMERS REMARK:
 * In state bound we have T1, T2 and the lease timer running. If T1 goes off, we attempt to renew.
 * If the renew succeeds a new T1, T2 and lease timer is started. The former T2 and lease timer is
 * still running though. This poses no concerns as the T2 and lease event in state bound have a NULL
 * pointer in the fsm. If the former T2 or lease timer goes off, nothing happens. Same situation
 * applies for T2 and a succesfull rebind. */

static void pico_dhcp_state_machine(uint8_t event, struct pico_dhcp_client_cookie *dhcpc, uint8_t *buf)
{
    switch (event)
    {
    case PICO_DHCP_MSG_OFFER:
        dhcpc_dbg("DHCP client: received OFFER\n");
        if (dhcp_fsm[dhcpc->state].offer)
            dhcp_fsm[dhcpc->state].offer(dhcpc, buf);

        break;

    case PICO_DHCP_MSG_ACK:
        dhcpc_dbg("DHCP client: received ACK\n");
        if (dhcp_fsm[dhcpc->state].ack)
            dhcp_fsm[dhcpc->state].ack(dhcpc, buf);

        break;

    case PICO_DHCP_MSG_NAK:
        dhcpc_dbg("DHCP client: received NAK\n");
        if (dhcp_fsm[dhcpc->state].nak)
            dhcp_fsm[dhcpc->state].nak(dhcpc, buf);

        break;

    case PICO_DHCP_EVENT_T1:
        dhcpc_dbg("DHCP client: received T1 timeout\n");
        if (dhcp_fsm[dhcpc->state].timer1)
            dhcp_fsm[dhcpc->state].timer1(dhcpc, NULL);

        break;

    case PICO_DHCP_EVENT_T2:
        dhcpc_dbg("DHCP client: received T2 timeout\n");
        if (dhcp_fsm[dhcpc->state].timer2)
            dhcp_fsm[dhcpc->state].timer2(dhcpc, NULL);

        break;

    case PICO_DHCP_EVENT_LEASE:
        dhcpc_dbg("DHCP client: received LEASE timeout\n");
        if (dhcp_fsm[dhcpc->state].timer_lease)
            dhcp_fsm[dhcpc->state].timer_lease(dhcpc, NULL);

        break;

    case PICO_DHCP_EVENT_RETRANSMIT:
        dhcpc_dbg("DHCP client: received RETRANSMIT timeout\n");
        if (dhcp_fsm[dhcpc->state].timer_retransmit)
            dhcp_fsm[dhcpc->state].timer_retransmit(dhcpc, NULL);

        break;

    default:
        dhcpc_dbg("DHCP client WARNING: unrecognized event (%u)!\n", dhcpc->event);
        return;
    }
    return;
}

static int16_t pico_dhcp_client_opt_parse(void *ptr, uint16_t len)
{
    uint32_t optlen = len - (uint32_t)sizeof(struct pico_dhcp_hdr);
    struct pico_dhcp_hdr *hdr = (struct pico_dhcp_hdr *)ptr;
    struct pico_dhcp_opt *opt = NULL;

    if (hdr->dhcp_magic != PICO_DHCPD_MAGIC_COOKIE)
        return -1;

    if (!pico_dhcp_are_options_valid(hdr->options, (int32_t)optlen))
        return -1;

    opt = (struct pico_dhcp_opt *)hdr->options;
    do {
        if (opt->code == PICO_DHCP_OPT_MSGTYPE)
            return opt->ext.msg_type.type;
    } while (pico_dhcp_next_option(&opt));

    return -1;
}

static int8_t pico_dhcp_client_msg(struct pico_dhcp_client_cookie *dhcpc, uint8_t msg_type)
{
    int32_t r = 0;
    uint16_t optlen = 0, offset = 0;
    struct pico_ip4 destination = {
        .addr = 0xFFFFFFFF
    };
    struct pico_dhcp_hdr *hdr = NULL;

    switch (msg_type)
    {
    case PICO_DHCP_MSG_DISCOVER:
        dhcpc_dbg("DHCP client: sent DHCPDISCOVER\n");
        optlen = PICO_DHCP_OPTLEN_MSGTYPE + PICO_DHCP_OPTLEN_MAXMSGSIZE + PICO_DHCP_OPTLEN_PARAMLIST + PICO_DHCP_OPTLEN_END;
        hdr = PICO_ZALLOC((size_t)(sizeof(struct pico_dhcp_hdr) + optlen));
        if (!hdr) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        /* specific options */
        offset = (uint16_t)(offset + pico_dhcp_opt_maxmsgsize(&hdr->options[offset], DHCP_CLIENT_MAXMSGZISE));
        break;

    case PICO_DHCP_MSG_REQUEST:
        dhcpc_dbg("DHCP client: sent DHCPREQUEST\n");
        optlen = PICO_DHCP_OPTLEN_MSGTYPE + PICO_DHCP_OPTLEN_MAXMSGSIZE + PICO_DHCP_OPTLEN_PARAMLIST + PICO_DHCP_OPTLEN_REQIP + PICO_DHCP_OPTLEN_SERVERID
                 + PICO_DHCP_OPTLEN_END;
        hdr = PICO_ZALLOC(sizeof(struct pico_dhcp_hdr) + optlen);
        if (!hdr) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        /* specific options */
        offset = (uint16_t)(offset + pico_dhcp_opt_maxmsgsize(&hdr->options[offset], DHCP_CLIENT_MAXMSGZISE));
        if (dhcpc->state == DHCP_CLIENT_STATE_REQUESTING) {
            offset = (uint16_t)(offset + pico_dhcp_opt_reqip(&hdr->options[offset], &dhcpc->address));
            offset = (uint16_t)(offset + pico_dhcp_opt_serverid(&hdr->options[offset], &dhcpc->server_id));
        }

        break;

    default:
        return -1;
    }

    /* common options */
    offset = (uint16_t)(offset + pico_dhcp_opt_msgtype(&hdr->options[offset], msg_type));
    offset = (uint16_t)(offset + pico_dhcp_opt_paramlist(&hdr->options[offset]));
    offset = (uint16_t)(offset + pico_dhcp_opt_end(&hdr->options[offset]));

    switch (dhcpc->state)
    {
    case DHCP_CLIENT_STATE_BOUND:
        destination.addr = dhcpc->server_id.addr;
        hdr->ciaddr = dhcpc->address.addr;
        break;

    case DHCP_CLIENT_STATE_RENEWING:
        destination.addr = dhcpc->server_id.addr;
        hdr->ciaddr = dhcpc->address.addr;
        break;

    case DHCP_CLIENT_STATE_REBINDING:
        hdr->ciaddr = dhcpc->address.addr;
        break;

    default:
        /* do nothing */
        break;
    }

    /* header information */
    hdr->op = PICO_DHCP_OP_REQUEST;
    hdr->htype = PICO_DHCP_HTYPE_ETH;
    hdr->hlen = PICO_SIZE_ETH;
    hdr->xid = dhcpc->xid;
    /* hdr->flags = short_be(PICO_DHCP_FLAG_BROADCAST); / * Nope: see bug #96! * / */
    hdr->dhcp_magic = PICO_DHCPD_MAGIC_COOKIE;
    /* copy client hardware address */
    memcpy(hdr->hwaddr, &dhcpc->dev->eth->mac, PICO_SIZE_ETH);

    r = pico_socket_sendto(dhcpc->s, hdr, (int)(sizeof(struct pico_dhcp_hdr) + optlen), &destination, PICO_DHCPD_PORT);
    PICO_FREE(hdr);
    if (r < 0)
        return -1;

    return 0;
}

static void pico_dhcp_client_wakeup(uint16_t ev, struct pico_socket *s)
{
    uint8_t buf[DHCP_CLIENT_MAXMSGZISE] = {
        0
    };
    int r = 0;
    struct pico_dhcp_hdr *hdr = NULL;
    struct pico_dhcp_client_cookie *dhcpc = NULL;

    if (ev != PICO_SOCK_EV_RD)
        return;

    r = pico_socket_recvfrom(s, buf, DHCP_CLIENT_MAXMSGZISE, NULL, NULL);
    if (r < 0)
        return;

    /* If the 'xid' of an arriving message does not match the 'xid'
     * of the most recent transmitted message, the message must be
     * silently discarded. */
    hdr = (struct pico_dhcp_hdr *)buf;
    dhcpc = pico_dhcp_client_find_cookie(hdr->xid);
    if (!dhcpc)
        return;

    dhcpc->event = (uint8_t)pico_dhcp_client_opt_parse(buf, (uint16_t)r);
    pico_dhcp_state_machine(dhcpc->event, dhcpc, buf);
}

void *pico_dhcp_get_identifier(uint32_t xid)
{
    return (void *)pico_dhcp_client_find_cookie(xid);
}

struct pico_ip4 pico_dhcp_get_address(void*dhcpc)
{
    return ((struct pico_dhcp_client_cookie*)dhcpc)->address;
}

struct pico_ip4 pico_dhcp_get_gateway(void*dhcpc)
{
    return ((struct pico_dhcp_client_cookie*)dhcpc)->gateway;
}

struct pico_ip4 pico_dhcp_get_netmask(void *dhcpc)
{
    return ((struct pico_dhcp_client_cookie*)dhcpc)->netmask;
}


struct pico_ip4 pico_dhcp_get_nameserver(void*dhcpc)
{
    return ((struct pico_dhcp_client_cookie*)dhcpc)->nameserver;
}
#endif
