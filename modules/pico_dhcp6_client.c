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

#if defined(PICO_SUPPORT_DHCP6C) && defined(PICO_SUPPORT_UDP)

/* For debugging */
//#define DEBUG_PICO_DHCP6

#ifdef DEBUG_PICO_DHCP6
#define dhcp6_dbg(x, args ...) dbg("\033[33m[%s:%s:%i] "x" \033[0m\n",__FILE__,__func__,__LINE__ ,##args )
#else
#define dhcp6_dbg(...) do {} while(0)
#endif

#ifdef DEBUG_PICO_DHCP6
void print_hex_array(void* array, size_t size){
    unsigned int i;
    uint8_t* arr;
    /* For debugging */
    if(size > 100){
        printf("length corrected: %zu\n", size);
    }
    arr = array;
    size = (size < 100) ? size : 100;
    for(i=0; i<size; i++){
        printf("0x%02x, ", arr[i]);
    }
    printf("\n");
}
#else
void print_hex_array(void* array, size_t size){
	IGNORE_PARAMETER(array);
	IGNORE_PARAMETER(size);
}
#endif

struct pico_dhcp6_client_cookie cookie; /* TODO: use a pico tree to store cookies */

#define PICO_DHCP6_BUFF_SIZE 200
uint8_t buff[PICO_DHCP6_BUFF_SIZE];


static void send_renew_msg(struct pico_ip6 dst);
static void pico_dhcp6_send_sol(void);

/* Generate DUID Based on Link-Layer Address [DUID-LL] */
static void generate_cid(struct pico_device *dev, struct pico_dhcp6_opt_cid ** cid)
{
    struct pico_dhcp6_duid_ll * duid;
    (*cid) = PICO_ZALLOC(sizeof(struct pico_dhcp6_opt_cid) + sizeof(struct pico_dhcp6_duid_ll) + PICO_SIZE_ETH);
    (*cid)->base_opts.option_len = short_be(sizeof(struct pico_dhcp6_duid_ll) + PICO_SIZE_ETH);
    (*cid)->base_opts.option_code = short_be(PICO_DHCP6_OPT_CLIENTID);
    duid = (struct pico_dhcp6_duid_ll *)&(*cid)->duid;
    duid->type = short_be(PICO_DHCP6_DUID_LL);
    duid->hw_type = short_be(PICO_DHCP6_HW_TYPE_ETHERNET);
    /* TODO Convert MAC to network repr */
    memcpy(&duid->link_layer_address, &dev->eth->mac.addr, PICO_SIZE_ETH); /* Copy MAC from device */
}

static inline int check_duid_rec(void)
{
    return (memcmp(&cookie.cid_rec->duid, (struct pico_dhcp6_duid_ll *) &cookie.cid_rec->duid, sizeof(cookie.cid_client->duid)) != 0); /* TODO: other DUID typed */
}

/* Generate random transaction ID. The transaction ID is stored in the cookie so it can later be used to
 * compare it with the transaction ID that will be in the response from the server. */
void generate_transaction_id(void)
{
    uint32_t t = pico_rand();
    cookie.transaction_id[0] = (uint8_t)t;
    cookie.transaction_id[1] = (uint8_t)(t >> 8);
    cookie.transaction_id[2] = (uint8_t)(t >> 16);
}

static inline void allocate_and_copy(void **dst, void **ptr, size_t size){
    *dst = PICO_ZALLOC(size);
    memcpy(*dst, *ptr, size);
}

void process_status_code(struct pico_dhcp6_opt_status_code** status_code_field, size_t size)
{
    /* TODO */
    allocate_and_copy((void **)&cookie.status_code_field, (void **)status_code_field, size);
    cookie.status_code_field->status_code = short_be(cookie.status_code_field->status_code); //TODO: check
    switch(short_be((*status_code_field)->status_code))
    {
    case PICO_DHCP6_SUCCESS:
        break;
    case PICO_DHCP6_UNSPEC_FAIL:
        break;
    case PICO_DHCP6_NO_ADDRS_AVAIL:
        break;
    case PICO_DHCP6_NO_BINDING:
        break;
    case PICO_DHCP6_NOT_ON_LINK:
        break;
    case PICO_DHCP6_USE_MULTICAST:
        pico_string_to_ipv6(ALL_DHCP_RELAY_AGENTS_AND_SERVERS, (uint8_t *)&cookie.msg_dst);
        break;
    default:
        dbg("DHCP6 client: received invalid status code %u",(*status_code_field)->status_code);
        break;
    }
}

static inline void pico_dhcp6_client_clear_options_in_cookie(void){
    if(cookie.cid_rec !=NULL)
        PICO_FREE(cookie.cid_rec);
    if(cookie.sid !=NULL)
        PICO_FREE(cookie.sid);
    if(cookie.iana !=NULL)
        PICO_FREE(cookie.iana);
    if(cookie.ia_ta !=NULL)
        PICO_FREE(cookie.ia_ta);
    if(cookie.iaddr !=NULL)
        PICO_FREE(cookie.iaddr);
    if(cookie.oro !=NULL)
        PICO_FREE(cookie.oro);
    if(cookie.pref !=NULL)
        PICO_FREE(cookie.pref);
    if(cookie.elapsed_time !=NULL)
        PICO_FREE(cookie.elapsed_time);
    if(cookie.status_code_field !=NULL)
        PICO_FREE(cookie.status_code_field);
    if(cookie.relay_msg !=NULL)
        PICO_FREE(cookie.relay_msg);
    if(cookie.auth !=NULL)
        PICO_FREE(cookie.auth);
    cookie.rapid_commit = 0;
    if(cookie.user_class !=NULL)
        PICO_FREE(cookie.user_class);
    if(cookie.vendor_class !=NULL)
        PICO_FREE(cookie.vendor_class);
    if(cookie.vendor_opts !=NULL)
        PICO_FREE(cookie.vendor_opts);
    if(cookie.interface_id !=NULL)
        PICO_FREE(cookie.interface_id);
    cookie.reconf_msg_type = 0;
    cookie.reconf_accept = 0;

    cookie.cid_rec = NULL;
    cookie.sid = NULL;
    cookie.iana = NULL;
    cookie.ia_ta = NULL;
    cookie.iaddr = NULL;
    cookie.oro = NULL;
    cookie.pref = NULL;
    cookie.elapsed_time = NULL;
    cookie.status_code_field = NULL;
    cookie.relay_msg = NULL;
    cookie.auth = NULL;
    cookie.user_class = NULL;
    cookie.vendor_class = NULL;
    cookie.vendor_opts = NULL;
    cookie.interface_id = NULL;
}

/* Parse all the options from a message and store them in the cookie */
static void pico_dhcp6_parse_options(struct pico_dhcp6_opt *options, size_t len)
{

    /* section A for allowed options per type  */

    size_t delta = 0;

    pico_dhcp6_client_clear_options_in_cookie();
    while(len > 0)
    {
        /* TODO: each option may appear only in the options
           area of a DHCP message and may appear only once.  If an option does
           appear multiple times, each instance is considered separate and the
           data areas of the options MUST NOT be concatenated or otherwise
           combined. --- but A DHCP message may contain multiple IA_NA options */
        delta = short_be(((struct pico_dhcp6_opt *)(options))->option_len) + sizeof(struct pico_dhcp6_opt);
//        convert_to_short_be( (((struct pico_dhcp6_opt *)(options))->option_len) ); //TODO does not work?
        switch(short_be(options->option_code))
        {
            case PICO_DHCP6_OPT_CLIENTID:
                dhcp6_dbg("DHCP6 client: parse_options: Received CID option\n"); /* TODO: remove option_code from options before storing ptr */
                allocate_and_copy((void **)&cookie.cid_rec, (void **)&options, delta);
                /* TODO: check if it matches the one that was sent out */
                break;
            case PICO_DHCP6_OPT_SERVERID:
                dhcp6_dbg("DHCP6 client: parse_options: Received SID option\n");
                allocate_and_copy((void **)&cookie.sid, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_IA_NA:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_IA_NA option\n");
                allocate_and_copy((void **)&cookie.iana, (void **)&options, delta);
                /* TODO: In a message sent by a server to a client, the client MUST use the
                   values in the T1 and T2 fields for the T1 and T2 parameters, unless
                   those values in those fields are 0.  The values in the T1 and T2
                   fields are the number of seconds until T1 and T2. */
                break;
            case PICO_DHCP6_OPT_IA_TA:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_IA_TA option\n");
                allocate_and_copy((void **)&cookie.ia_ta, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_IADDR:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_IADDR option\n");
                allocate_and_copy((void **)&cookie.iaddr, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_ORO:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_ORO option\n");
                allocate_and_copy((void **)&cookie.oro, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_PREFERENCE:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_PREFERENCE option\n");
                allocate_and_copy((void **)&cookie.pref, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_ELAPSED_TIME:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_PREFERENCE option\n");
                allocate_and_copy((void **)&cookie.elapsed_time, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_RELAY_MSG:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_RELAY_MSG option\n");
                allocate_and_copy((void **)&cookie.relay_msg, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_AUTH:
                if(cookie.auth) /* Any DHCP message that includes more than one authentication option MUST be discarded */
                {
                    dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_AUTH option more than once, discard\n");
                    /* TODO: discard message */
                }
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_AUTH option\n");
                allocate_and_copy((void **)&cookie.auth, (void **)&options, delta);

                break;
            case PICO_DHCP6_OPT_UNICAST: /* TODO: check if server_address valid */
                dhcp6_dbg("DHCP6 client: parse_options: Received UNICAST option\n");
                memcpy(&cookie.msg_dst, &((struct pico_dhcp6_opt_unicast *) options)->server_address, sizeof(struct pico_ip6));
                break;
            case PICO_DHCP6_OPT_STATUS_CODE: /* TODO */
                process_status_code(((struct pico_dhcp6_opt_status_code **) &options), delta);
                dhcp6_dbg("DHCP6 client: parse_options: Received STATUS_CODE option\n");
                break;
            case PICO_DHCP6_OPT_RAPID_COMMIT:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_RAPID_COMMIT option\n");
                cookie.rapid_commit = 1;
                break;
            case PICO_DHCP6_OPT_USER_CLASS:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_USER_CLASS option\n");
                allocate_and_copy((void **)&cookie.user_class, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_VENDOR_CLASS:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_VENDOR_CLASS option\n");
                allocate_and_copy((void **)&cookie.vendor_class, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_VENDOR_OPTS:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_VENDOR_OPTS option\n");
                allocate_and_copy((void **)&cookie.vendor_opts, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_INTERFACE_ID:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_INTERFACE_ID option\n");
                allocate_and_copy((void **)&cookie.interface_id, (void **)&options, delta);
                break;
            case PICO_DHCP6_OPT_RECONF_MSG:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_RECONF_MSG option\n");
                cookie.reconf_msg_type = *(((uint8_t *)options) + 4);
                //TODO: assert delta == 1
                break;
            case PICO_DHCP6_OPT_RECONF_ACCEPT:
                dhcp6_dbg("DHCP6 client: parse_options: Received PICO_DHCP6_OPT_RECONF_ACCEPT option\n");
                cookie.reconf_accept = 1;
                break;
            default:
                dhcp6_dbg("DHCP6 client: parse_options: ERROR Received unknown option: %u\n", short_be(options->option_code));
                break;
        }

        len -= delta;
        options = (struct pico_dhcp6_opt *) (  ( (uint8_t *)(options) ) + delta  );
        /* TODO: parse to short_be for e.g. length */
    }
}

/* Get the proposed address from the DHCP server and add it to the device */
static void pico_dhcp6_add_addr()
{
    struct pico_dhcp6_opt_ia_addr *ia_addr;
    struct pico_ip6 nm;

    /* TODO: add server address to cookie.server_addr */

    if(cookie.iana!= NULL && (cookie.iana->base_opts.option_len > PICO_DHCP6_OPT_SIZE_IA_NA))
    {
        ia_addr = (struct pico_dhcp6_opt_ia_addr *)(cookie.iana->options);
        if(short_be(ia_addr->base_opts.option_code) == PICO_DHCP6_OPT_IADDR)
        {
            /* Don't insert link if it already exists, TODO: also send DECLINE message to server */
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
//    pico_string_to_ipv6(ALL_DHCP_RELAY_AGENTS_AND_SERVERS, dst.addr);
    memcpy(&dst.addr, &cookie.msg_dst, sizeof(cookie.msg_dst)); /* unicast when option received*/
    if(pico_socket_sendto_extended(cookie.sock, (void *)msg, (int)len, (void *)&dst, short_be(PICO_DHCP6_SERVER_PORT), &info) < 0)
        dhcp6_dbg("pico_socket_sendto_extended failed!!");
}

static void pico_dhcp6_fill_msg_with_options(struct pico_dhcp6_hdr *msg)
{
    size_t cid_len, sid_len, iana_len;
    cid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.cid_client->base_opts.option_len);
    sid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.sid->base_opts.option_len);
    iana_len = (cookie.iana != NULL) ? (sizeof(struct pico_dhcp6_opt) + short_be(cookie.iana->base_opts.option_len)) : 0;

    /* First option is CID. Copy the CID from cookie to msg */
    memcpy(&msg->options, cookie.cid_client, cid_len);
    
    /* Copy SID from cookie to msg */
    memcpy(((uint8_t*)msg->options) + cid_len, cookie.sid, sid_len);

    /* Copy IANA from cookie to msg TODO: this option is not mandatory, check other options present as well */
    memcpy(((uint8_t*)msg->options) + cid_len + sid_len, cookie.iana, iana_len);
}

static void pico_dhcp6_send_req()
{
    /* MUST include CID and SID */
    size_t len, cid_len, sid_len, iana_len;
    struct pico_dhcp6_hdr *msg;
    dhcp6_dbg("Begin pico_dhcp6_send_req");
    cid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.cid_client->base_opts.option_len);
    sid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.sid->base_opts.option_len);
    iana_len = (cookie.iana != NULL) ? (sizeof(struct pico_dhcp6_opt) + short_be(cookie.iana->base_opts.option_len)) : 0;
    len = sizeof(struct pico_dhcp6_hdr) + cid_len + sid_len + iana_len;

    msg = (struct pico_dhcp6_hdr *)PICO_ZALLOC(len);
    msg->type = PICO_DHCP6_REQUEST;
    generate_transaction_id();
    memcpy(msg->transaction_id, cookie.transaction_id, 3);

    pico_dhcp6_fill_msg_with_options(msg);
    
    /* Send out request msg */
    cookie.state = DHCP6_CLIENT_STATE_REQUESTING;
    pico_dhcp6_send_msg(msg, len);

#ifdef DEBUG_PICO_DHCP6
    dhcp6_dbg("Sending request message:");
#endif

    PICO_FREE(msg);
}

static void pico_dhcp6_renew_timeout(pico_time t, void * arg)
{
    size_t len, cid_len, sid_len, iana_len;
    struct pico_dhcp6_hdr *msg;
    (void)(arg);
    (void)(t);

    dhcp6_dbg("SEND OUT RENEW MSG NOW!!!");
    cid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.cid_client->base_opts.option_len);
    sid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.sid->base_opts.option_len);
    iana_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.iana->base_opts.option_len);
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

#define PICO_DHCP6_ADV_OK (1)
#define PICO_DHCP6_ADV_NOK (0)

static int check_adv_message(struct pico_dhcp6_hdr *msg){
    /* 15.3 */
    /* TODO: The client MUST ignore any Advertise message that includes a Status
   Code option containing the value NoAddrsAvail, with the exception
   that the client MAY display the associated status message to the
   user.
   Check section 18.1.8. */
    if(cookie.sid == NULL)
    {
        dhcp6_dbg("DHCP6 client: check_adv_message: Received no SID\n");
        return PICO_DHCP6_ADV_NOK;
    }
    if(cookie.cid_rec == NULL)
    {
        dhcp6_dbg("DHCP6 client: check_adv_message: Received no CID\n");
        return PICO_DHCP6_ADV_NOK;
    }
    if(check_duid_rec())
    {
        dhcp6_dbg("DHCP6 client: check_adv_message: Received CID incorrect\n");
        return PICO_DHCP6_ADV_NOK;
    }
    if(memcmp(cookie.transaction_id, DHCP6_TRANSACTION_ID(msg), sizeof(cookie.transaction_id))!=0)
    {
        dhcp6_dbg("DHCP6 client: check_adv_message: Transaction IDs not correct\n");
        return PICO_DHCP6_ADV_NOK;
    }
    if(cookie.status_code_field != NULL && cookie.status_code_field->status_code == PICO_DHCP6_NO_ADDRS_AVAIL)
    {
        dhcp6_dbg("DHCP6 client: check_adv_message: Status code indicating NO_ADDRS_AVAIL\n");
        return PICO_DHCP6_ADV_NOK;
    }
    return PICO_DHCP6_ADV_OK;
}

static void recv_adv(struct pico_dhcp6_hdr *msg, size_t len)
{
    pico_dhcp6_parse_options((struct pico_dhcp6_opt *)msg->options, len-sizeof(struct pico_dhcp6_hdr));
    if(check_adv_message(msg) == PICO_DHCP6_ADV_NOK)
    {
        dhcp6_dbg("After check advertise message: invalid\n");
        return;
    }
    dhcp6_dbg("After check advertise message: valid\n");
    pico_timer_cancel(cookie.rto_timer);

    /* TODO: According to client policy, the client MAY
       choose to respond to an Advertise message that has not been
       authenticated. */

    /* TODO:
       Upon receipt of one or more valid Advertise messages, the client
       selects one or more Advertise messages based upon the following
       criteria... 17.1.3 */

    /* Skip waiting for other advertisements and immediately sent a request to the server */
    dhcp6_dbg("Before send req\n");
    pico_dhcp6_send_req();
    dhcp6_dbg("After send req\n");

    /* TODO:    If the message exchange fails, the client takes an action based on
   the client's local policy.  Examples of actions the client might take
   include:

   -  Select another server from a list of servers known to the client;
      for example, servers that responded with an Advertise message.

   -  Initiate the server discovery process described in section 17.

   -  Terminate the configuration process and report failure. */
}

static void extend_lifetime_dedicated_server(pico_time t, void* arg){
    /* TODO */
    IGNORE_PARAMETER(t);
    IGNORE_PARAMETER(arg);
    send_renew_msg(cookie.server_addr);
}

static void extend_lifetime_any_server(pico_time t, void* arg){
    /* TODO */
    struct pico_ip6 dst_addr;
    IGNORE_PARAMETER(t);
    IGNORE_PARAMETER(arg);
    pico_string_to_ipv6(ALL_DHCP_SERVERS, (uint8_t *)&dst_addr);
    send_renew_msg(dst_addr);
}

static void record_t1_t2(void)
{
    /* TODO */
    if(cookie.iana != NULL)
    {
        /* TODO: check if relative time (duration not time point) for pico_timer_add */
        pico_timer_add((pico_time)(cookie.iana->t1 * 1000), &extend_lifetime_dedicated_server, 0);
        pico_timer_add((pico_time)(cookie.iana->t2 * 1000), &extend_lifetime_any_server, 0); /* TODO: check or maybe ALL_DHCP_RELAY_AGENTS_AND_SERVERS */
    }
    else
    {
        dhcp6_dbg("No T1 or T2 to be recorded");
    }
}

static void update_lifetimes(void)
{
    /* TODO */
}

static void check_trans_id(void)
{
    /* TODO */
}

static void recv_reply(struct pico_dhcp6_hdr *msg, size_t len)
{
    uint32_t renew_timer;

    /* TODO: If the client includes a Rapid Commit option in the Solicit message,
   it will expect a Reply message that includes a Rapid Commit option in
   response.  The client discards any Reply messages it receives that do
   not include a Rapid Commit option. */

    /*
   The client SHOULD perform duplicate address detection [17] on each of
   the addresses in any IAs it receives in the Reply message before
   using that address for traffic.  If any of the addresses are found to
   be in use on the link, the client sends a Decline message to the
   server as described in section 18.1.7.

   If the Reply was received in response to a Solicit (with a Rapid
   Commit option), Request, Renew or Rebind message, the client updates
   the information it has recorded about IAs from the IA options
   contained in the Reply message:

   -  Record T1 and T2 times.

   -  Add any new addresses in the IA option to the IA as recorded by
      the client.

   -  Update lifetimes for any addresses in the IA option that the
      client already has recorded in the IA.

   -  Discard any addresses from the IA, as recorded by the client, that
      have a valid lifetime of 0 in the IA Address option.

   -  Leave unchanged any information about addresses the client has
      recorded in the IA but that were not included in the IA from the
      server.

     */
    pico_dhcp6_parse_options((struct pico_dhcp6_opt *)msg->options, len-sizeof(struct pico_dhcp6_hdr));
    if(cookie.rapid_commit_option_enabled == 1 && cookie.rapid_commit != 1)
    {
        /* TODO: Discard message */
    }
    record_t1_t2();
    pico_dhcp6_add_addr();
    update_lifetimes();
    check_trans_id();
    if(cookie.iana != NULL)
    {
        renew_timer = long_be( ((struct pico_dhcp6_opt_ia_addr *) cookie.iana->options)->preferred_lt );
        dhcp6_dbg("After renew_timer");
        //valid_timer = long_be(((struct pico_dhcp6_opt_ia_addr *)cookie.iana->options)->valid_lt);
        pico_timer_add((pico_time)(renew_timer * 1000), &pico_dhcp6_renew_timeout, 0);
        dhcp6_dbg("After pico_timer_add");
    }
    //pico_timer_add((pico_time)(valid_timer * 1000), &pico_dhcp6_valid_timeout, 0);
    cookie.state = DHCP6_CLIENT_STATE_BOUND;
    dhcp6_dbg("Leaving recv_reply");
}

static inline int is_valid_reconf_option(uint8_t msg_type){
    /* @return 1 if valid else 0 */
    return (msg_type == PICO_DHCP6_OPT_RECONF_MSG_RENEW || msg_type == PICO_DHCP6_OPT_RECONF_MSG_INFO_REQ);
}

static int passes_validation_test(struct pico_dhcp6_hdr *msg, size_t len){
    /*TODO: */
    IGNORE_PARAMETER(msg);
    IGNORE_PARAMETER(len);
    return 0;
}

#define PICO_DHCP6_RECONF_OK (1)
#define PICO_DHCP6_RECONF_NOK (0)

static int check_reconfigure_message(struct pico_dhcp6_hdr *msg, size_t len){
    if(cookie.cid_rec == NULL)
    {
        dbg("DHCP6 client: discarding reconfigure w/o CID\n");
        return PICO_DHCP6_RECONF_NOK;
    } /* TODO: check if cookie.sid/cid NULL after processed */
    if(cookie.sid == NULL)
    {
        dbg("DHCP6 client: discarding reconfigure w/o SID\n");
        return PICO_DHCP6_RECONF_NOK;
    }
    if(check_duid_rec())
    {
        dbg("DHCP6 client: discarding reconfigure with wrong CID\n");
        return PICO_DHCP6_RECONF_NOK;
    }
    if(cookie.reconf_msg_type == 0)
    {
        dbg("DHCP6 client: discarding reconfigure that does not contain reconfigure option\n");
        return PICO_DHCP6_RECONF_NOK;
    }
    if(!is_valid_reconf_option(cookie.reconf_msg_type))
    {
        dbg("DHCP6 client: discarding reconfigure that has invalid msg type\n");
        return PICO_DHCP6_RECONF_NOK;
    }
    if(cookie.iana != NULL && cookie.reconf_msg_type == PICO_DHCP6_OPT_RECONF_MSG_INFO_REQ)
    {
        dbg("DHCP6 client: discarding reconfigure that contains IA options\n");
        return PICO_DHCP6_RECONF_NOK;
    }
    if(cookie.status_code_field == NULL || cookie.status_code_field->base_opts.option_code != PICO_DHCP6_OPT_AUTH)
    {
        dbg("DHCP6 client: discarding reconfigure w/o authentication\n");
        return PICO_DHCP6_RECONF_NOK;
    }
    if(!passes_validation_test(msg, len))
    {
        dbg("DHCP6 client: discarding reconfigure with failed validation test\n");
        return PICO_DHCP6_RECONF_NOK;
    }
    return PICO_DHCP6_RECONF_OK;
}

static void send_info_req()
{
    /* TODO */
}

static void send_renew_msg(struct pico_ip6 dst)
{
    /* TODO */
    IGNORE_PARAMETER(dst);
}

static void pico_dhcp6_check_if_unicast_received()
{
    /* TODO */
}

static int respond_to_reconfigure_message()
{
    /* TODO: */
    struct pico_ip6 dst; //TODO: dst to be determined
    if(cookie.reconf_msg_type == PICO_DHCP6_OPT_RECONF_MSG_INFO_REQ)
        send_info_req();
    else if(cookie.reconf_msg_type == PICO_DHCP6_OPT_RECONF_MSG_RENEW)
        send_renew_msg(dst);
    return 0;
}

static int recv_reconfigure(struct pico_dhcp6_hdr *msg, size_t len)
{
    pico_dhcp6_check_if_unicast_received();
    pico_dhcp6_parse_options(DHCP6_OPT(msg, 0), len);
    if(check_reconfigure_message(msg, len) == PICO_DHCP6_RECONF_NOK){
        /* discard message */
        return 0;
    }
    respond_to_reconfigure_message();
    cookie.state = DHCP6_CLIENT_STATE_RECONFIGURING;

    return 1;;

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

/* When a solicit message times out, increase the retransmission timeout with an upper
 * boundary of PICO_DHCP6_SOL_MAX_RT 
 */
static void pico_dhcp6_sol_timeout(pico_time t, void * arg)
{
    dhcp6_dbg("SOL timeout. Retransmit SOL\n");
    (void)(t);
    (void)(arg);

    cookie.rtc++;
    cookie.rto = (uint8_t)(cookie.rto << 1); /* TODO: add random factor. See rfc3315 section 14 */
    if(cookie.rto > PICO_DHCP6_SOL_MAX_RT)
        cookie.rto = PICO_DHCP6_SOL_MAX_RT;

    pico_dhcp6_send_sol();
}


static void pico_dhcp6_send_sol(void)
{
    /* TODO: also other DUID types */
    struct pico_dhcp6_hdr *dhcp6_hdr;
    struct pico_dhcp6_opt_cid *dhcp6_cid;
    struct pico_dhcp6_opt_oro *oro_opt;
    struct pico_dhcp6_opt_elapsed_time *elt_opt;
    struct pico_dhcp6_opt_ia_na *iana_opt;
    size_t len, cid_len, oro_len, elt_len, iana_len; 

    /* Don't create a new transaction ID & CID if this is a retransmission */
    if(cookie.rtc == 0)
    {
        generate_transaction_id();
        generate_cid(cookie.dev, &cookie.cid_client);
    }

    cid_len = sizeof(struct pico_dhcp6_opt) + short_be(cookie.cid_client->base_opts.option_len);
    oro_len = sizeof(struct pico_dhcp6_opt_oro);
    elt_len = sizeof(struct pico_dhcp6_opt_elapsed_time);
    iana_len = sizeof(struct pico_dhcp6_opt_ia_na);
    len = sizeof(struct pico_dhcp6_hdr) + cid_len + oro_len + elt_len + iana_len;

    /* TODO: if rapid commit: set
    cookie.rapid_commit_option_enabled = 1; */

    dhcp6_hdr = (struct pico_dhcp6_hdr*)PICO_ZALLOC(len);
    dhcp6_hdr->type = PICO_DHCP6_SOLICIT;

    dhcp6_cid = (struct pico_dhcp6_opt_cid *)(dhcp6_hdr->options);
    memcpy(dhcp6_hdr->transaction_id, cookie.transaction_id, PICO_DHCP6_TRANSACTION_ID_SIZE);
    memcpy(dhcp6_cid, cookie.cid_client, cid_len); /* copy DUID into current packet */

    oro_opt = (struct pico_dhcp6_opt_oro*)((uint8_t *)dhcp6_cid + cid_len);
    oro_opt->base_opts.option_code = short_be(PICO_DHCP6_OPT_ORO);
    oro_opt->base_opts.option_len = short_be(PICO_DHCP6_OPT_SIZE_ORO); /* No additional options requested for now */

    elt_opt = (struct pico_dhcp6_opt_elapsed_time*)((uint8_t *)oro_opt + oro_len);
    elt_opt->base_opts.option_code = short_be(PICO_DHCP6_OPT_ELAPSED_TIME);
    elt_opt->base_opts.option_len = short_be(PICO_DHCP6_OPT_SIZE_ELAPSED_TIME);
    elt_opt->elapsed_time = short_be(0);

    iana_opt = (struct pico_dhcp6_opt_ia_na*)((uint8_t *)elt_opt + elt_len);
    iana_opt->base_opts.option_code = short_be(PICO_DHCP6_OPT_IA_NA);
    iana_opt->base_opts.option_len = short_be(PICO_DHCP6_OPT_SIZE_IA_NA); /* We don't include IA addr option in IA_NA from solicit msgs */
    memcpy(&iana_opt->iaid,((uint8_t *) &cookie.dev->eth->mac.addr) + (PICO_SIZE_ETH - sizeof(iana_opt->iaid)), sizeof(iana_opt->iaid)); /* Use lower 4 bytes of MAC as IAID */
    iana_opt->t1 = long_be(0); /* No preferred time when we will contact the server from whom address was obtained */
    iana_opt->t2 = long_be(0); /* No preferred time when we will contact any server again */

    dhcp6_dbg("Sending DHCP solicit");
    cookie.state = DHCP6_CLIENT_STATE_SOLICITING;
    /* TODO: The first Solicit message from the client on the interface MUST be
   delayed by a random amount of time between 0 and SOL_MAX_DELAY. */
    pico_dhcp6_send_msg(dhcp6_hdr, len);

    cookie.rto_timer = pico_timer_add((pico_time)(cookie.rto * 1000), &pico_dhcp6_sol_timeout, 0);
    PICO_FREE(dhcp6_hdr);
}

static void init_cookie_values(void)
{
    cookie.rapid_commit = 0;
    cookie.reconf_msg_type = 0;
    cookie.reconf_accept = 0;
    cookie.cid_rec = NULL;
    cookie.sid = NULL;
    cookie.iana = NULL;
    cookie.ia_ta = NULL;
    cookie.iaddr = NULL;
    cookie.oro = NULL;
    cookie.pref = NULL;
    cookie.elapsed_time = NULL;
    cookie.status_code_field = NULL;
    cookie.relay_msg = NULL;
    cookie.auth = NULL;
    cookie.user_class = NULL;
    cookie.vendor_class = NULL;
    cookie.vendor_opts = NULL;
    cookie.interface_id = NULL;
    cookie.rapid_commit_option_enabled = 0;
}

static inline void init_cookie(void)
{
    init_cookie_values();
    pico_dhcp6_client_clear_options_in_cookie();
}

/* Initiate the request of an IP address via DHCPv6. 
 *
 * NOTE: only call this function if there is already a link-local address assigned to the device!!
 */
int pico_dhcp6_initiate_negotiation(struct pico_device *device, void (*callback)(void*cli, int code), uint32_t *xid)
{
    uint16_t local_port;
    (void)(xid);

    init_cookie();

    cookie.sock = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, &dhcp6c_cb);
    cookie.dev = device;
    cookie.cb = callback;
    cookie.rtc = 0;
    cookie.rto = PICO_DHCP6_SOL_TIMEOUT;
    pico_string_to_ipv6(ALL_DHCP_RELAY_AGENTS_AND_SERVERS, (uint8_t *)&cookie.msg_dst);

    local_port = short_be(PICO_DHCP6_CLIENT_PORT);
    pico_socket_bind(cookie.sock, &pico_ipv6_linklocal_get(cookie.dev)->address, &local_port);
    pico_dhcp6_send_sol();

    return 0;
}

struct dhcp6_action_entry {
    int (*sol)(void);
    void (*adv)(struct pico_dhcp6_hdr *msg, size_t len);
    int (*req)(void);
    int (*confirm)(void);
    int (*renew)(void);
    int (*rebind)(void);
    void (*reply)(struct pico_dhcp6_hdr *msg, size_t len); /* TODO: or use int for status code? */
    int (*release)(void);
    int (*decline)(void);
    int (*reconfigure)(struct pico_dhcp6_hdr *msg, size_t len);
    int (*info_request)(void);
};

static struct dhcp6_action_entry dhcp6_fsm[] =
{   /* event                    |sol       |adv     |req   |confirm      |renew    |rebind    |reply        |release     |decline     |reconfigure         |info_request */
    /* state SOLICITING      */ { NULL,    recv_adv, NULL,   NULL,         NULL,     NULL,/*(1)*/recv_reply, NULL,         NULL,        recv_reconfigure,    NULL },
    /* state REQUESTING      */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    recv_reply,    NULL,         NULL,        recv_reconfigure,    NULL },
    /* state CONFIRMING      */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    recv_reply,    NULL,         NULL,        recv_reconfigure,    NULL },
    /* state BOUND           */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    NULL,          NULL,         NULL,        recv_reconfigure,    NULL },
    /* state RENEWING        */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    recv_reply,    NULL,         NULL,        recv_reconfigure,    NULL },
    /* state REBINDING       */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    recv_reply,    NULL,         NULL,        recv_reconfigure,    NULL },
    /* state RELEASING       */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    recv_reply,    NULL,         NULL,        recv_reconfigure,    NULL },
    /* state DECLINING       */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    recv_reply,    NULL,         NULL,        recv_reconfigure,    NULL },
    /* state INFO_REQUESTING */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    recv_reply,    NULL,         NULL,        recv_reconfigure,    NULL },
    /* state RECONFIGURING   */ { NULL,    NULL,     NULL,   NULL,         NULL,     NULL,    NULL,          NULL,         NULL,        NULL,                NULL }
    /* (1) only with rapid commit option 18.1.8 */
};

static void sm_process_msg(struct pico_dhcp6_hdr *msg, size_t len)
{
    /* TODO:
   A client MUST be configurable to discard unauthenticated messages,
   and SHOULD be configured by default to discard unauthenticated
   messages if the client has been configured with an authentication key
   or other authentication information. */
    /* the client MUST generate authentication
   information for subsequent Request, Confirm, Renew, Rebind or Release
   messages sent to the server, as described in section 21.4. */
    switch(msg->type)
    {
        case PICO_DHCP6_SOLICIT:
            dhcp6_dbg("DHCP6 client: Solicit message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_ADVERTISE:
            dhcp6_dbg("DHCP6 client: Advertise message received\n");
            if(dhcp6_fsm[cookie.state].adv != NULL)
                dhcp6_fsm[cookie.state].adv(msg, len);
            break;
        case PICO_DHCP6_REQUEST:
            dhcp6_dbg("DHCP6 client: Request message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_CONFIRM:
            dhcp6_dbg("DHCP6 client: Confirm message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_RENEW:
            dhcp6_dbg("DHCP6 client: Renew message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_REBIND:
            dhcp6_dbg("DHCP6 client: Rebind message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_REPLY:
            dhcp6_dbg("DHCP6 client: Reply message received\n");
            /*  The client SHOULD perform duplicate address detection [17] on each of
           the addresses in any IAs it receives in the Reply message before
           using that address for traffic.  If any of the addresses are found to
           be in use on the link, the client sends a Decline message to the
           server as described in section 18.1.7. */
            if(dhcp6_fsm[cookie.state].reply != NULL)
                dhcp6_fsm[cookie.state].reply(msg, len);
            break;
        case PICO_DHCP6_RELEASE:
            dhcp6_dbg("DHCP6 client: Release message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_DECLINE:
            dhcp6_dbg("DHCP6 client: Decline message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_RECONFIGURE: /* May be sent at any time, SHOULD log these events, and MAY notify L7 programs */
            dhcp6_dbg("DHCP6 client: Reconfigure message received\n");
            if(dhcp6_fsm[cookie.state].reconfigure != NULL)
                dhcp6_fsm[cookie.state].reconfigure(msg, len);
            break;
        case PICO_DHCP6_INFORMATION_REQUEST:
            dhcp6_dbg("DHCP6 client: Information request message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_RELAY_FORW:
            dhcp6_dbg("DHCP6 client: Relay forward message received\n");
            /* do nothing */
            break;
        case PICO_DHCP6_RELAY_REPL:
            dhcp6_dbg("DHCP6 client: Relay reply message received\n");
            /* do nothing */
            break;
        default:
            dhcp6_dbg("Unrecognized message received at client: %u\n", msg->type); /* TODO: handle this? */
            break;
    }
}
#endif
