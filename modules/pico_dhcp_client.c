/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Frederik Van Slycken, Kristof Roelants
*********************************************************************/

#include "pico_dhcp_client.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

#ifdef PICO_SUPPORT_DHCPC

/***********
 * structs *
 ***********/

static uint8_t dhcp_client_mutex = 1; /* to serialize client negotations if multiple devices */

struct dhcp_timer_param{
  uint16_t type;
  struct pico_dhcp_client_cookie* cli;
  int valid;
};

struct pico_dhcp_client_cookie
{
  uint32_t xid;
  uint32_t *xid_user;
  struct pico_ip4 address;
  struct pico_ip4 netmask;
  struct pico_ip4 gateway;
  struct pico_ip4 nameserver;
  struct pico_ip4 server_id;
  uint32_t lease_time;
  uint32_t T1;
  uint32_t T2;
  struct pico_socket* socket;
  int connected;
  struct pico_device* device;
  unsigned long start_time;
  int attempt;
  enum dhcp_negotiation_state state;
  void (*cb)(void* cli, int code);
  struct dhcp_timer_param* timer_param_1;
  struct dhcp_timer_param* timer_param_2;
  struct dhcp_timer_param* timer_param_lease;
  struct dhcp_timer_param* timer_param_retransmit;
  int link_added;
};

static int dhcp_cookies_cmp(void *ka, void *kb)
{
  struct pico_dhcp_client_cookie *a = ka, *b = kb;
  if (a->xid < b->xid)
    return -1; 
  else if (a->xid > b->xid)
    return 1;
  else
    return 0;
} 
PICO_TREE_DECLARE(DHCPCookies, dhcp_cookies_cmp);

/*************************
 * function declarations *
 *************************/
static void pico_dhcp_state_machine(int type, struct pico_dhcp_client_cookie* cli, uint8_t* data, int len);
static void pico_dhcp_reinitiate_negotiation(unsigned long now, void *arg);

//cb
static void pico_dhcp_wakeup(uint16_t ev, struct pico_socket *s);
static void dhcp_timer_cb(unsigned long tick, void* param);

//util
static void pico_dhcp_retry(struct pico_dhcp_client_cookie *client);
static int dhclient_send(struct pico_dhcp_client_cookie *cli, uint8_t msg_type);
static int pico_dhcp_verify_and_identify_type(uint8_t* data, int len, struct pico_dhcp_client_cookie *cli);
static int init_cookie(struct pico_dhcp_client_cookie* cli);
static struct pico_dhcp_client_cookie* get_cookie_by_xid(uint32_t xid);
static uint32_t get_xid(uint8_t* data);

//fsm functions
static int recv_offer(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
static int recv_ack(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
static int renew(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
static int reset(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
static int retransmit(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);

//fsm implementation
static void pico_dhcp_state_machine(int type, struct pico_dhcp_client_cookie* cli, uint8_t* data, int len);

/***************
 * entry point *
 ***************/

static uint32_t pico_dhcp_execute_init(struct pico_dhcp_client_cookie *cli)
{
  if (!dhcp_client_mutex) {
    pico_timer_add(3000, pico_dhcp_reinitiate_negotiation, cli);
    return 0;
  }
  dhcp_client_mutex--;

  if (init_cookie(cli) < 0)
    return -1;

  dbg("DHCPC: cookie with xid %u\n", cli->xid);
  
  if (pico_tree_insert(&DHCPCookies, cli)) {
    pico_err = PICO_ERR_EAGAIN;
    if(cli->cb != NULL) {
      cli->cb(cli, PICO_DHCP_ERROR);
    }
    pico_free(cli);
    return -1; /* Element key already exists */
  }

  if (dhclient_send(cli, PICO_DHCP_MSG_DISCOVER) < 0)
    return -1;

  return 0;
}

/* returns a pointer to the client cookie. The user should pass this pointer every time he calls a dhcp-function. This is so that we can (one day) support dhcp on multiple interfaces */
int pico_dhcp_initiate_negotiation(struct pico_device *device, void (*callback)(void *cli, int code), uint32_t *xid)
{
  struct pico_dhcp_client_cookie *cli;
  
  if(!device || !callback || !xid){
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }
  cli = pico_zalloc(sizeof(struct pico_dhcp_client_cookie));
  if(!cli){
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }

  cli->device = device;
  cli->cb = callback;
  cli->xid_user = xid;
  *(cli->xid_user) = 0;

  return pico_dhcp_execute_init(cli);
}

static void pico_dhcp_reinitiate_negotiation(unsigned long now, void *arg)
{
  struct pico_dhcp_client_cookie *cli = (struct pico_dhcp_client_cookie *) arg;

  pico_dhcp_execute_init(cli);

  return;
}

/********************
 * access functions *
 ********************/

struct pico_ip4 pico_dhcp_get_address(void* cli)
{
  return ((struct pico_dhcp_client_cookie*)cli)->address;
}

struct pico_ip4 pico_dhcp_get_gateway(void* cli)
{
  return ((struct pico_dhcp_client_cookie*)cli)->gateway;
}

struct pico_ip4 pico_dhcp_get_nameserver(void* cli)
{
  return ((struct pico_dhcp_client_cookie*)cli)->nameserver;
}

/*************
 * callbacks *
 *************/

static void pico_dhcp_wakeup(uint16_t ev, struct pico_socket *s)
{
  uint8_t buf[DHCPC_DATAGRAM_SIZE];
  int r=0;
  uint32_t peer;
  uint16_t port;
  int type;

  struct pico_dhcp_client_cookie *cli;
  dbg("DHCPC: called dhcp_wakeup\n");
  if (ev == PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_recvfrom(s, buf, DHCPC_DATAGRAM_SIZE, &peer, &port);
      cli = get_cookie_by_xid(get_xid(buf));
      if(cli == NULL)
        return;
      if (r > 0 && port == PICO_DHCPD_PORT) {
        type = pico_dhcp_verify_and_identify_type(buf, r, cli);
        pico_dhcp_state_machine(type, cli, buf, r);
      }
    } while(r>0);
  }
}

static void dhcp_timer_cb(unsigned long tick, void* param)
{
  struct dhcp_timer_param* param2 = (struct dhcp_timer_param*) param;
  if(param2->valid == 1){
    //dbg("called timer cb on active timer type %d\n",param2->type);
    pico_dhcp_state_machine(param2->type, param2->cli, NULL, 0);
  }
  if(param2->cli->timer_param_1 == param){
    param2->cli->timer_param_1 = NULL;
  }
  if(param2->cli->timer_param_2 == param){
    param2->cli->timer_param_2 = NULL;
  }
  if(param2->cli->timer_param_lease == param){
    param2->cli->timer_param_lease = NULL;
  }
  if(param2->cli->timer_param_retransmit == param){
    param2->cli->timer_param_retransmit = NULL;
  }

  pico_free(param);

}
/*****************
 * fsm functions *
 *****************/

static int recv_offer(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len)
{
  struct pico_dhcphdr *dhdr = (struct pico_dhcphdr *) data;
  uint8_t *nextopt, opt_data[20], opt_type;
  int opt_len = 20;
  uint8_t msg_type = 0xFF;
  int T1_set = 0;
  int T2_set = 0;

  cli->address.addr = dhdr->yiaddr;

  opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
  while (opt_type != PICO_DHCPOPT_END) {
    if (opt_type == PICO_DHCPOPT_MSGTYPE)
      msg_type = opt_data[0];
    if ((opt_type == PICO_DHCPOPT_LEASETIME) && (opt_len == 4)){
      memcpy(&cli->lease_time, opt_data, 4);
      cli->lease_time = long_be(cli->lease_time);
    }
    if ((opt_type == PICO_DHCPOPT_RENEWALTIME) && (opt_len == 4)){
      memcpy(&cli->T1, opt_data, 4);
      cli->T1 = long_be(cli->T1);
      T1_set =1;
    }
    if ((opt_type == PICO_DHCPOPT_REBINDINGTIME) && (opt_len == 4)){
      memcpy(&cli->T2, opt_data, 4);
      cli->T2 = long_be(cli->T2);
      T2_set =1;
    }
    if ((opt_type == PICO_DHCPOPT_ROUTER) && (opt_len == 4)) //XXX assuming only one router will be advertised...
      memcpy(&cli->gateway.addr, opt_data, 4);
    if ((opt_type == PICO_DHCPOPT_DNS) && (opt_len == 4))
      memcpy(&cli->nameserver.addr, opt_data, 4);
    if ((opt_type == PICO_DHCPOPT_NETMASK) && (opt_len == 4))
      memcpy(&cli->netmask.addr, opt_data, 4);
    if ((opt_type == PICO_DHCPOPT_SERVERID) && (opt_len == 4))
      memcpy(&cli->server_id.addr, opt_data, 4);
    if (opt_type == PICO_DHCPOPT_OPTIONOVERLOAD)
      dbg("DHCPC: WARNING: option overload present (not processed)");

    opt_len = 20;
    opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
  }

  /* default values for T1 and T2 if necessary */
  if(T1_set != 1)
    cli->T1 = cli->lease_time >> 1;
  if(T2_set != 1)
    cli->T2 = (cli->lease_time * 875) / 1000;



  if ((msg_type != PICO_DHCP_MSG_OFFER) || !cli->lease_time || !cli->netmask.addr || !cli->server_id.addr )
    return 0;


  dhclient_send(cli, PICO_DHCP_MSG_REQUEST);
  cli->state = DHCPSTATE_REQUEST;
  return 1;
}

static int recv_ack(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len)
{
  struct pico_ip4 address = {0};

  if(cli->link_added == 0){
    /* close the socket bound on address 0.0.0.0 */
    pico_socket_close(cli->socket);
    cli->socket = NULL;
    pico_ipv4_link_del(cli->device, address);
    pico_ipv4_link_add(cli->device, cli->address, cli->netmask);
    cli->link_added = 1;
  }
  cli->state = DHCPSTATE_BOUND;

  dbg("DHCPC: T1: %d\n",cli->T1);
  dbg("DHCPC: T2: %d\n",cli->T2);
  dbg("DHCPC: lease time: %d\n",cli->lease_time);

  if(cli->timer_param_1)
    cli->timer_param_1->valid = 0;
  if(cli->timer_param_2)
    cli->timer_param_2->valid = 0;
  if(cli->timer_param_lease)
    cli->timer_param_lease->valid = 0;
  if(cli->timer_param_retransmit)
    cli->timer_param_retransmit->valid = 0;


  cli->timer_param_1 = pico_zalloc(sizeof(struct dhcp_timer_param));
  if(!cli->timer_param_1){
    if(cli->cb != NULL){
      pico_err = PICO_ERR_ENOMEM;
      cli->cb(cli, PICO_DHCP_ERROR);
    }
    return 0;
  }
  cli->timer_param_2 = pico_zalloc(sizeof(struct dhcp_timer_param));
  if(!cli->timer_param_2){
    if(cli->cb != NULL){
      pico_err = PICO_ERR_ENOMEM;
      cli->cb(cli, PICO_DHCP_ERROR);
    }
    return 0;
  }
  cli->timer_param_lease = pico_zalloc(sizeof(struct dhcp_timer_param));
  if(!cli->timer_param_lease){
    if(cli->cb != NULL){
      pico_err = PICO_ERR_ENOMEM;
      cli->cb(cli, PICO_DHCP_ERROR);
    }
    return 0;
  }
  cli->timer_param_1->valid = 1;
  cli->timer_param_2->valid = 1;
  cli->timer_param_lease->valid = 1;

  cli->timer_param_1->cli = cli;
  cli->timer_param_2->cli = cli;
  cli->timer_param_lease->cli = cli;

  cli->timer_param_1->type = PICO_DHCP_EVENT_T1;
  cli->timer_param_2->type = PICO_DHCP_EVENT_T2;
  cli->timer_param_lease->type = PICO_DHCP_EVENT_LEASE;
  //add timer
  pico_timer_add(cli->T1*1000, dhcp_timer_cb, cli->timer_param_1);
  pico_timer_add(cli->T2*1000, dhcp_timer_cb, cli->timer_param_2);
  pico_timer_add(cli->lease_time*1000, dhcp_timer_cb, cli->timer_param_lease);

  *(cli->xid_user) = cli->xid;
  if(cli->cb != NULL)
    cli->cb(cli, PICO_DHCP_SUCCESS);
  else
    dbg("DHCPC: no callback\n");

  dhcp_client_mutex++;
  cli->state = DHCPSTATE_BOUND;
  return 0;
}

static int renew(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len)
{
  uint16_t port = PICO_DHCP_CLIENT_PORT;

  /* open and bind to currently acquired address */
  if (!cli->socket){
    cli->socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dhcp_wakeup);
    if (!cli->socket) {
      dbg("DHCPC: error opening socket on renew: %s\n", strerror(pico_err));
      if(cli->cb != NULL)
        cli->cb(cli, PICO_DHCP_ERROR);
      return -1;
    }
    if (pico_socket_bind(cli->socket, &cli->address, &port) != 0){
      dbg("DHCPC: error binding socket on renew: %s\n", strerror(pico_err));
      pico_socket_close(cli->socket);
      if(cli->cb != NULL)
        cli->cb(cli, PICO_DHCP_ERROR);
      return -1;
    }
  }
  cli->state = DHCPSTATE_RENEWING;
  dhclient_send(cli, PICO_DHCP_MSG_REQUEST);

  return 0;
}

static int reset(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len)
{
  if(cli->cb != NULL)
    cli->cb(cli, PICO_DHCP_RESET);
  //reset pretty much everything

  if(cli->timer_param_1)
    cli->timer_param_1->valid = 0;
  if(cli->timer_param_2)
    cli->timer_param_2->valid = 0;
  if(cli->timer_param_lease)
    cli->timer_param_lease->valid = 0;
  if(cli->timer_param_retransmit)
    cli->timer_param_retransmit->valid = 0;

  pico_socket_close(cli->socket);
  pico_ipv4_link_del(cli->device, cli->address);

  //initiate negotiations again
  init_cookie(cli);
  pico_dhcp_retry(cli);
  dhclient_send(cli, PICO_DHCP_MSG_DISCOVER);

  return 0;

}

static int retransmit(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len)
{
  pico_dhcp_retry(cli);

  if(cli->state == DHCPSTATE_DISCOVER)
    dhclient_send(cli, PICO_DHCP_MSG_DISCOVER);
  else if(cli->state == DHCPSTATE_RENEWING)
    dhclient_send(cli, PICO_DHCP_MSG_REQUEST);
  else
    dbg("DHCPC: WARNING: should not get here in state %d!\n", cli->state);

  return 0;

}

/**********************
 * fsm implementation *
 **********************/

struct dhcp_action_entry {
  uint16_t tcpstate;
  int (*offer)(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
  int (*ack)(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
  int (*nak)(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
  int (*timer1)(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
  int (*timer_lease)(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
  int (*timer_retransmit)(struct pico_dhcp_client_cookie *cli, uint8_t *data, int len);
};

static struct dhcp_action_entry dhcp_fsm[] = {
    /* State             offer       ack       nak     timer1  timer_lease timer_retransmit*/
  { DHCPSTATE_DISCOVER,  recv_offer, NULL,     NULL,   NULL,   reset,      retransmit},
  { DHCPSTATE_OFFER,     NULL,       NULL,     NULL,   NULL,   reset,      NULL},
  { DHCPSTATE_REQUEST,   NULL,       recv_ack, reset,  NULL,   reset,      retransmit},
  { DHCPSTATE_BOUND,     NULL,       NULL,     reset,  renew,  reset,      NULL},
  { DHCPSTATE_RENEWING,  NULL,       recv_ack, reset,  NULL,   reset,      retransmit},
};


static void pico_dhcp_state_machine(int type, struct pico_dhcp_client_cookie* cli, uint8_t* data, int len)
{
  dbg("DHCPC: received incoming event of type %d\n", type);
  switch(type){
    case PICO_DHCP_MSG_OFFER:
      if(dhcp_fsm[cli->state].offer != NULL)
        dhcp_fsm[cli->state].offer(cli, data, len);
      break;
    case PICO_DHCP_MSG_ACK:
      if(dhcp_fsm[cli->state].ack != NULL){
        dhcp_fsm[cli->state].ack(cli, data, len);
      }
      break;
    case PICO_DHCP_MSG_NAK:
      if(dhcp_fsm[cli->state].nak!= NULL){
        dhcp_fsm[cli->state].nak(cli, data, len);
      }
      break;
    case PICO_DHCP_EVENT_T1:
      if(dhcp_fsm[cli->state].timer1!= NULL){
        dhcp_fsm[cli->state].timer1(cli, NULL, 0);
      }
      break;
    case PICO_DHCP_EVENT_LEASE:
      if(dhcp_fsm[cli->state].timer_lease!= NULL){
        dhcp_fsm[cli->state].timer_lease(cli, NULL, 0);
      }
      break;
    case PICO_DHCP_EVENT_RETRANSMIT:
      if(dhcp_fsm[cli->state].timer_retransmit!= NULL){
        dhcp_fsm[cli->state].timer_retransmit(cli, NULL, 0);
      }
      break;
    default:
      dbg("DHCPC: event not supported yet!!\n");
      break;
  }
}


/*********************
 * utility functions *
 *********************/

static void pico_dhcp_retry(struct pico_dhcp_client_cookie *cli)
{
  const int MAX_RETRY = 3;
  uint32_t new_xid;
  if (++cli->attempt > MAX_RETRY) {
    cli->start_time = pico_tick;
    cli->attempt = 0;
     new_xid = pico_rand();
    while(get_cookie_by_xid(new_xid) != NULL){
      new_xid = pico_rand();
    }
    cli->xid = new_xid;
    cli->state = DHCPSTATE_DISCOVER;
  }
}

static int dhclient_send(struct pico_dhcp_client_cookie *cli, uint8_t msg_type)
{
  uint8_t buf_out[DHCPC_DATAGRAM_SIZE] = {0};
  struct pico_dhcphdr *dh_out = (struct pico_dhcphdr *) buf_out;
  int sent = 0;
  int i = 0;
  struct pico_ip4 destination;
  uint16_t port = PICO_DHCPD_PORT;
  if(cli->state == DHCPSTATE_BOUND || cli->state == DHCPSTATE_RENEWING){
    destination.addr = cli->server_id.addr;
  }else{
    destination.addr = long_be(0xFFFFFFFF);
  }

  if(cli->device->eth == NULL){
    pico_err = PICO_ERR_EOPNOTSUPP;
    if(cli->cb != NULL){
      cli->cb(cli, PICO_DHCP_ERROR);
    }
    return -1;
  }
  memcpy(dh_out->hwaddr, &cli->device->eth->mac, PICO_HLEN_ETHER);
  dh_out->op = PICO_DHCP_OP_REQUEST;
  dh_out->htype = PICO_HTYPE_ETHER;
  dh_out->hlen = PICO_HLEN_ETHER;
  dh_out->xid = cli->xid;
  dh_out->secs = (msg_type == PICO_DHCP_MSG_REQUEST)?0:short_be((pico_tick - cli->start_time)/1000);
  dh_out->dhcp_magic = PICO_DHCPD_MAGIC_COOKIE;
  if (cli->state == DHCPSTATE_RENEWING)
    dh_out->ciaddr = cli->address.addr;

  /* Option: msg type, len 1 */
  dh_out->options[i++] = PICO_DHCPOPT_MSGTYPE;
  dh_out->options[i++] = 1;
  dh_out->options[i++] = msg_type;

  if (( msg_type == PICO_DHCP_MSG_REQUEST) && ( cli->state != DHCPSTATE_RENEWING )) {
    dh_out->options[i++] = PICO_DHCPOPT_REQIP;
    dh_out->options[i++] = 4;
    dh_out->options[i++] = (long_be(cli->address.addr) & 0xFF000000) >> 24;
    dh_out->options[i++] = (long_be(cli->address.addr) & 0xFF0000) >> 16;
    dh_out->options[i++] = (long_be(cli->address.addr) & 0xFF00) >> 8;
    dh_out->options[i++] = (long_be(cli->address.addr) & 0xFF);
    dh_out->options[i++] = PICO_DHCPOPT_SERVERID;
    dh_out->options[i++] = 4;
    dh_out->options[i++] = (long_be(cli->server_id.addr) & 0xFF000000) >> 24;
    dh_out->options[i++] = (long_be(cli->server_id.addr) & 0xFF0000) >> 16;
    dh_out->options[i++] = (long_be(cli->server_id.addr) & 0xFF00) >> 8;
    dh_out->options[i++] = (long_be(cli->server_id.addr) & 0xFF);
  }

  /* Option: req list, len 4 */
  dh_out->options[i++] = PICO_DHCPOPT_PARMLIST;
  dh_out->options[i++] = 7;
  dh_out->options[i++] = PICO_DHCPOPT_NETMASK;
  dh_out->options[i++] = PICO_DHCPOPT_BCAST;
  dh_out->options[i++] = PICO_DHCPOPT_TIME;
  dh_out->options[i++] = PICO_DHCPOPT_ROUTER;
  dh_out->options[i++] = PICO_DHCPOPT_HOSTNAME;
  dh_out->options[i++] = PICO_DHCPOPT_RENEWALTIME;
  dh_out->options[i++] = PICO_DHCPOPT_REBINDINGTIME;

  /* Option : max message size */
  if( msg_type == PICO_DHCP_MSG_REQUEST || msg_type == PICO_DHCP_MSG_DISCOVER){
    uint16_t dds = DHCPC_DATAGRAM_SIZE;
    dh_out->options[i++] = PICO_DHCPOPT_MAXMSGSIZE;
    dh_out->options[i++] = 2;
    dh_out->options[i++] = (dds & 0xFF00) >> 8;
    dh_out->options[i++] = (dds & 0xFF);
  }



  dh_out->options[i] = PICO_DHCPOPT_END;
  sent = pico_socket_sendto(cli->socket, buf_out, DHCPC_DATAGRAM_SIZE, &destination, port);
  if (sent < 0) {
    dbg("DHCPC: sendto failed: %s\n", strerror(pico_err));
    if(cli->cb != NULL)
      cli->cb(cli, PICO_DHCP_ERROR);
  }


  //resend-timer :
  if(cli->timer_param_retransmit != NULL)
    cli->timer_param_retransmit->valid=0;

  cli->timer_param_retransmit = pico_zalloc(sizeof(struct dhcp_timer_param));
  if(!cli->timer_param_retransmit){
    if(cli->cb != NULL)
      pico_err = PICO_ERR_ENOMEM;
      cli->cb(cli, PICO_DHCP_ERROR);
    return -1;
  }
  cli->timer_param_retransmit->valid = 1;
  cli->timer_param_retransmit->cli = cli;
  cli->timer_param_retransmit->type = PICO_DHCP_EVENT_RETRANSMIT;
  pico_timer_add(4000, dhcp_timer_cb, cli->timer_param_retransmit);

  return 0;
}

//identifies type & does some preprocessing : checking if everything is valid
static int pico_dhcp_verify_and_identify_type(uint8_t* data, int len, struct pico_dhcp_client_cookie *cli)
{
  struct pico_dhcphdr *dhdr = (struct pico_dhcphdr *) data;
  uint8_t *nextopt, opt_data[20], opt_type;
  int opt_len = 20;

  if (dhdr->xid != cli->xid)
    return 0;

  if (!is_options_valid(dhdr->options, len - sizeof(struct pico_dhcphdr)))
    return 0;

  if( dhdr->dhcp_magic != PICO_DHCPD_MAGIC_COOKIE)
    return 0;

  opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
  while (opt_type != PICO_DHCPOPT_END) {
    /* parse interesting options here */
    if (opt_type == PICO_DHCPOPT_MSGTYPE) {
      return *opt_data;
    }
    opt_len = 20;
    opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
  }
  return 0;

}

static int init_cookie(struct pico_dhcp_client_cookie* cli)
{
  uint8_t n = 3;
  uint16_t port = PICO_DHCP_CLIENT_PORT;
  struct pico_ip4 address, netmask;

  address.addr = long_be(0x00000000);
  netmask.addr = long_be(0x00000000);

  cli->state = DHCPSTATE_DISCOVER;
  cli->start_time = pico_tick;
  cli->attempt = 0;

  cli->socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dhcp_wakeup);
  if (!cli->socket) {
    dbg("DHCPC: error opening socket: %s\n", strerror(pico_err));
    if(cli->cb != NULL)
      cli->cb(cli, PICO_DHCP_ERROR);
    return -1;
  }
  if (pico_socket_bind(cli->socket, &address, &port) != 0){
    dbg("DHCPC: error binding socket: %s\n", strerror(pico_err));
    pico_socket_close(cli->socket);
    if(cli->cb != NULL)
      cli->cb(cli, PICO_DHCP_ERROR);
    return -1;
  }
  cli->socket->dev = cli->device;

  if(pico_ipv4_link_add(cli->device, address, netmask) != 0){
    dbg("DHCPC: error adding link: %s\n", strerror(pico_err));
    if(cli->cb != NULL)
      cli->cb(cli, PICO_DHCP_ERROR);
    return -1;
  }

  /* attempt to generate a correct xid 3 times, then fail */
  do {
    cli->xid = pico_rand();
  } while (!cli->xid && --n);
  if (!cli->xid) {
    if(cli->cb != NULL)
      cli->cb(cli, PICO_DHCP_ERROR);
    return -1;
  }

  return 0;
}

static struct pico_dhcp_client_cookie *get_cookie_by_xid(uint32_t xid)
{
  struct pico_dhcp_client_cookie test = { }, *cookie = NULL;

  if (!xid)
    return NULL;

  test.xid = xid;
  cookie = pico_tree_findKey(&DHCPCookies, &test);
  if (!cookie)
    return NULL;
  else
    return cookie;
}

void *pico_dhcp_get_identifier(uint32_t xid)
{
  return (void *) get_cookie_by_xid(xid);
}

static uint32_t get_xid(uint8_t* data)
{
  struct pico_dhcphdr *dhdr = (struct pico_dhcphdr *) data;
  return dhdr->xid;
}

#endif
