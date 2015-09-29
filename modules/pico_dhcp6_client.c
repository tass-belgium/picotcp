/*********************************************************************
   PicoTCP. Copyright (c) 2015 Altran. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Sam Van Den Berge
 *********************************************************************/

#include "pico_dhcp6_client.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv6.h"
#include "pico_socket.h"
#include "pico_eth.h"

#if (defined PICO_SUPPORT_DHCP6C && defined PICO_SUPPORT_UDP)

//#define dhcp6_dbg(...) do {} while(0)
#define dhcp6_dbg(x, args ...) dbg("\033[33m[%s:%s:%i] "x" \033[0m\n",__FILE__,__func__,__LINE__ ,##args )

enum dhcp6_client_state {
    DHCP6_CLIENT_STATE_REQUESTING = 0,
    DHCP6_CLIENT_STATE_SOLICITING,
    DHCP6_CLIENT_STATE_RENEWING,
    DHCP6_CLIENT_STATE_BOUND,
};


struct pico_dhcp6_client_cookie cookie; /* TODO: use a pico tree to store cookies */

# define PICO_DHCP6_BUFF_SIZE 200
uint8_t buff[PICO_DHCP6_BUFF_SIZE];

/* Generate DUID Based on Link-Layer Address [DUID-LL] */
static void generate_duid_ll(struct pico_device *dev, struct pico_dhcp6_duid_ll * client_duid_ll)
{
    client_duid_ll->type = short_be(PICO_DHCP6_DUID_LL);
    client_duid_ll->hw_type = short_be(PICO_DHCP6_HW_TYPE_ETHERNET);
    memcpy(&client_duid_ll->addr.mac.addr, &dev->eth->mac.addr, PICO_SIZE_ETH); /* Copy MAC from device */
}

/* Generate random transaction ID. The transaction ID is stored in the cookie so it can later be used to
 * compare it with the transaction ID that will be in the response from the server. */
void generate_transaction_id()
{
    uint32_t t = pico_rand();
    cookie.transaction_id[0] = (uint8_t)t;
    cookie.transaction_id[1] = (uint8_t)(t >> 8);
    cookie.transaction_id[2] = (uint8_t)(t >> 16);
}

/* Parse all the options from a message and store them in the cookie */
static void pico_dhcp6_parse_options(struct pico_dhcp6_opt *options, size_t len)
{
    while(len > 0)
    {
        switch(short_be(options->type))
        {
            case PICO_DHCP6_OPT_CLIENTID:
                dhcp6_dbg("Received CID option");
                /* TODO: check if it matches the one that was sent out */
                break;
            case PICO_DHCP6_OPT_SERVERID:
                dhcp6_dbg("Received SID option");
                cookie.sid = (struct pico_dhcp6_opt_sid *)options;
                break;
            case PICO_DHCP6_OPT_IA_NA:
                dhcp6_dbg("Received IANA option");
                cookie.iana = (struct pico_dhcp6_opt_ia_na *)options;
                break;
            default:
                dhcp6_dbg("Received unknown option");
                break;
        }
        len -= short_be(options->len) + sizeof(struct pico_dhcp6_opt);
        options = (struct pico_dhcp6_opt *)(((uint8_t *)options) + sizeof(struct pico_dhcp6_opt) + short_be(options->len));
    }
}

/* Get the proposed address from the DHCP server and add it to the device */
static void pico_dhcp6_add_addr()
{
    struct pico_dhcp6_opt_ia_addr *ia_addr;
    struct pico_ip6 nm;

    if(cookie.iana->len > PICO_DHCP6_OPT_SIZE_IA_NA)
    {
        ia_addr = (struct pico_dhcp6_opt_ia_addr *)(cookie.iana->options);
        if(short_be(ia_addr->type) == PICO_DHCP6_OPT_IADDR)
        {
            /* Don't insert link it it already exists */
            if(!pico_ipv6_link_get(&ia_addr->addr))
            {
                pico_string_to_ipv6("ffff:ffff:ffff:ffff:0000:0000:0000:0000", nm.addr); /* Need submask for pico_ipv6_link_add */
                pico_ipv6_link_add(cookie.dev, ia_addr->addr, nm); /* pico_ipv6_link_add will start DAD */
            }

            if(cookie.cb)
                cookie.cb(&cookie, PICO_DHCP6_SUCCESS);
        }
    }
}

static void pico_dhcp6_send_msg(struct pico_dhcp6_hdr *msg, size_t len)
{
    struct pico_ip6 dst = {{0}};
    struct pico_msginfo info = {0};

    info.dev = cookie.dev;
    pico_string_to_ipv6(ALL_DHCP_RELAY_AGENTS_AND_SERVERS, dst.addr);
    if(pico_socket_sendto_extended(cookie.sock, msg, (int)len, &dst, short_be(PICO_DHCP6_SERVER_PORT), &info) < 0)
        dhcp6_dbg("pico_socket_sendto_extended failed!!");
}

static void pico_dhcp6_fill_msg_with_options(struct pico_dhcp6_hdr *msg)
{
    size_t cid_len, sid_len, iana_len;
    cid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.cid->len);
    sid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.sid->len);
    iana_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.iana->len);

    /* First option is CID. Copy the CID from cookie to msg */
    memcpy(&msg->options, cookie.cid, cid_len);
    
    /* Copy SID from cookie to msg */
    memcpy(((uint8_t*)msg->options) + cid_len, cookie.sid, sid_len);

    /* Copy IANA from cookie to msg */
    memcpy(((uint8_t*)msg->options) + cid_len + sid_len, cookie.iana, iana_len);
}

static void pico_dhcp6_send_req()
{
    size_t len, cid_len, sid_len, iana_len;
    struct pico_dhcp6_hdr *msg;

    cid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.cid->len);
    sid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.sid->len);
    iana_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.iana->len);
    len = sizeof(struct pico_dhcp6_hdr) + cid_len + sid_len + iana_len;

    msg = (struct pico_dhcp6_hdr *)PICO_ZALLOC(len);
    msg->type = PICO_DHCP6_REQUEST;
    generate_transaction_id();
    memcpy(msg->transaction_id, cookie.transaction_id, 3);

    pico_dhcp6_fill_msg_with_options(msg);
    
    /* Send out request msg */
    cookie.state = DHCP6_CLIENT_STATE_REQUESTING;
    pico_dhcp6_send_msg(msg, len);
    PICO_FREE(msg);
}

static void pico_dhcp6_renew_timeout(pico_time t, void * arg)
{
    size_t len, cid_len, sid_len, iana_len;
    struct pico_dhcp6_hdr *msg;
    (void)(arg);
    (void)(t);

    dhcp6_dbg("SEND OUT RENEW MSG NOW!!!");
    cid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.cid->len);
    sid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.sid->len);
    iana_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.iana->len);
    len = sizeof(struct pico_dhcp6_hdr) + cid_len + sid_len + iana_len;

    msg = (struct pico_dhcp6_hdr *)PICO_ZALLOC(len);
    msg->type = PICO_DHCP6_RENEW;
    generate_transaction_id();
    memcpy(msg->transaction_id, cookie.transaction_id, 3);

    pico_dhcp6_fill_msg_with_options(msg);

    /* Send out request msg */
    pico_dhcp6_send_msg(msg, len);
    cookie.state = DHCP6_CLIENT_STATE_RENEWING;
    PICO_FREE(msg);
}

static void recv_adv(struct pico_dhcp6_hdr *msg, size_t len)
{
    pico_dhcp6_parse_options((struct pico_dhcp6_opt *)msg->options, len-sizeof(struct pico_dhcp6_hdr));
    pico_timer_cancel(cookie.rto_timer);
    /* Skip waiting for other advertisements and immediately sent a request to the server */
    pico_dhcp6_send_req();
}

static void recv_reply(struct pico_dhcp6_hdr *msg, size_t len)
{
    uint32_t renew_timer;

    dhcp6_dbg("Reply packet received!");
    pico_dhcp6_parse_options((struct pico_dhcp6_opt *)msg->options, len-sizeof(struct pico_dhcp6_hdr));
    pico_dhcp6_add_addr();
    renew_timer = long_be(((struct pico_dhcp6_opt_ia_addr *)cookie.iana->options)->preferred_lt);
    //valid_timer = long_be(((struct pico_dhcp6_opt_ia_addr *)cookie.iana->options)->valid_lt);
    pico_timer_add((pico_time)(renew_timer * 1000), &pico_dhcp6_renew_timeout, 0);
    //pico_timer_add((pico_time)(valid_timer * 1000), &pico_dhcp6_valid_timeout, 0);
    cookie.state = DHCP6_CLIENT_STATE_BOUND;
    }

static void sm_process_msg(struct pico_dhcp6_hdr *msg, size_t len);
/* this is the picotcp socket callback */
static void dhcp6c_cb(uint16_t ev, struct pico_socket *s)
{
    size_t len;
    dhcp6_dbg("DHCP6C: in dhcp6c pico socket callback");

    if(ev & PICO_SOCK_EV_RD)
    {
        len = (size_t)pico_socket_read(s, buff, (int)PICO_DHCP6_BUFF_SIZE);
        sm_process_msg((struct pico_dhcp6_hdr *)buff, len);
    }
}


static void pico_dhcp6_send_sol(); /* Declare function here because used in sol_timeout */

/* When a solicit message times out, increase the retransmission timeout with an upper
 * boundary of PICO_DHCP6_SOL_MAX_RT 
 */
static void pico_dhcp6_sol_timeout(pico_time t, void * arg)
{
    dhcp6_dbg("SOL timeout. Retransmit SOL");
    (void)(t);
    (void)(arg);

    cookie.rtc++;
    cookie.rto = (uint8_t)(cookie.rto << 1); /* TODO: add random factor. See rfc3315 section 14 */
    if(cookie.rto > PICO_DHCP6_SOL_MAX_RT)
        cookie.rto = PICO_DHCP6_SOL_MAX_RT;

    pico_dhcp6_send_sol();
}


static void pico_dhcp6_send_sol()
{
    struct pico_dhcp6_hdr *dhcp6_hdr;
    struct pic_dhcp6_opt_cid *dhcp6_cid;
    struct pico_dhcp6_opt_oro *oro_opt;
    struct pico_dhcp6_opt_elapsed_time *elt_opt;
    struct pico_dhcp6_opt_ia_na *iana_opt;
    size_t len, cid_len, oro_len, elt_len, iana_len; 

    cid_len = sizeof(struct pico_dhcp6_opt_cid) + sizeof(struct pico_dhcp6_duid_ll);
    oro_len = sizeof(struct pico_dhcp6_opt_oro);
    elt_len = sizeof(struct pico_dhcp6_opt_elapsed_time);
    iana_len = sizeof(struct pico_dhcp6_opt_ia_na);
    len = sizeof(struct pico_dhcp6_hdr) + cid_len + oro_len + elt_len + iana_len;

    dhcp6_hdr = (struct pico_dhcp6_hdr*)PICO_ZALLOC(len);
    dhcp6_hdr->type = PICO_DHCP6_SOLICIT;

    /* Don't create a new transaction ID & CID if this is a retransmission */
    if(cookie.rtc == 0)
    {
        generate_transaction_id();

        cookie.cid = PICO_ZALLOC(cid_len);
        cookie.cid->type = short_be(PICO_DHCP6_OPT_CLIENTID);
        cookie.cid->len = short_be(sizeof(struct pico_dhcp6_duid_ll));
        generate_duid_ll(cookie.dev, (struct pico_dhcp6_duid_ll*)cookie.cid->duid); /* Generate DUID, store in cookie */
    }
    dhcp6_cid = (struct pic_dhcp6_opt_cid *)(dhcp6_hdr->options);
    memcpy(dhcp6_hdr->transaction_id, cookie.transaction_id, PICO_DHCP6_TRANSACTION_ID_SIZE);
    memcpy(dhcp6_cid, cookie.cid, (size_t)cid_len); /* copy DUID into current packet */

    oro_opt = (struct pico_dhcp6_opt_oro*)((uint8_t *)dhcp6_cid + cid_len);
    oro_opt->type = short_be(PICO_DHCP6_OPT_ORO);
    oro_opt->len = short_be(PICO_DHCP6_OPT_SIZE_ORO); /* No additional options requested for now */

    elt_opt = (struct pico_dhcp6_opt_elapsed_time*)((uint8_t *)oro_opt + oro_len);
    elt_opt->type = short_be(PICO_DHCP6_OPT_ELAPSED_TIME);
    elt_opt->len = short_be(PICO_DHCP6_OPT_SIZE_ELAPSED_TIME);
    elt_opt->elapsed_time = short_be(0);

    iana_opt = (struct pico_dhcp6_opt_ia_na*)((uint8_t *)elt_opt + elt_len);
    iana_opt->type = short_be(PICO_DHCP6_OPT_IA_NA);
    iana_opt->len = short_be(PICO_DHCP6_OPT_SIZE_IA_NA); /* We don't include IA addr option in IA_NA from solicit msgs */
    memcpy(&iana_opt->iaid,((uint8_t *) &cookie.dev->eth->mac.addr) + (PICO_SIZE_ETH - sizeof(iana_opt->iaid)), sizeof(iana_opt->iaid)); /* Use lower 4 bytes of MAC as IAID */
    iana_opt->t1 = long_be(0); /* No preferred time when we will contact the server from whom address was obtained */
    iana_opt->t2 = long_be(0); /* No preffered time when we will contact any server again */

    dhcp6_dbg("Sending DHCP solicit");
    cookie.state = DHCP6_CLIENT_STATE_SOLICITING;
    pico_dhcp6_send_msg(dhcp6_hdr, len);

    cookie.rto_timer = pico_timer_add((pico_time)(cookie.rto * 1000), &pico_dhcp6_sol_timeout, 0);
    PICO_FREE(dhcp6_hdr);
}

/* Initiate the request of an IP address via DHCPv6. 
 *
 * NOTE: only call this function if there is already a link-local address assigned to the device!!
 */
int pico_dhcp6_initiate_negotiation(struct pico_device *device, void (*callback)(void*cli, int code), uint32_t *xid)
{
    uint16_t local_port;
    (void)(xid);

    cookie.sock = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, &dhcp6c_cb);
    cookie.dev = device;
    cookie.cb = callback;
    cookie.rtc = 0;
    cookie.rto = PICO_DHCP6_SOL_TIMEOUT;

    local_port = short_be(PICO_DHCP6_CLIENT_PORT);
    pico_socket_bind(cookie.sock, &pico_ipv6_linklocal_get(cookie.dev)->address, &local_port);
    pico_dhcp6_send_sol();

    return 0;
}

struct dhcp6_action_entry {
    int (*sol)(void);
    int (*adv)(struct pico_dhcp6_hdr *msg, size_t len);
    int (*req)(void);
    int (*confirm)(void);
    int (*renew)(void);
    int (*rebind)(void);
    int (*reply)(struct pico_dhcp6_hdr *msg, size_t len);
};

static struct dhcp6_action_entry dhcp6_fsm[] =
{   /* event                |sol       |adv      |req    |confirm  |renew    |rebind  |reply     */
    /* state REQUESTING  */ { NULL,    NULL,     NULL,   NULL,     NULL,     NULL,    recv_reply },
    /* state SOLICITING  */ { NULL,    recv_adv, NULL,   NULL,     NULL,     NULL,    NULL       },
    /* state RENEWING    */ { NULL,    NULL,     NULL,   NULL,     NULL,     NULL,    recv_reply },
    /* state BOUND       */ { NULL,    NULL,     NULL,   NULL,     NULL,     NULL,    NULL       },
};

static void sm_process_msg(struct pico_dhcp6_hdr *msg, size_t len)
{
    switch(msg->type)
    {
        case PICO_DHCP6_SOLICIT:
        case PICO_DHCP6_ADVERTISE:
            if(dhcp6_fsm[cookie.state].adv != NULL)
                dhcp6_fsm[cookie.state].adv(msg, len);
            break;
        case PICO_DHCP6_REPLY:
            if(dhcp6_fsm[cookie.state].reply != NULL)
                dhcp6_fsm[cookie.state].reply(msg, len);

        default: 
            break;
    }
}
#endif
