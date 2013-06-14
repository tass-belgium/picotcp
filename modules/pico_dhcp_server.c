/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.


Authors: Frederik Van Slycken, Kristof Roelants
*********************************************************************/

#ifdef PICO_SUPPORT_DHCPD

#include "pico_dhcp_server.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_arp.h"
#include <stdlib.h>

# define dhcpd_dbg(...) do{}while(0)
//# define dhcpd_dbg dbg

#define dhcpd_make_offer(x) dhcpd_make_reply(x, PICO_DHCP_MSG_OFFER)
#define dhcpd_make_ack(x) dhcpd_make_reply(x, PICO_DHCP_MSG_ACK)
#define ip_inrange(x) ((long_be(x) >= long_be(dn->settings->pool_start)) && (long_be(x) <= long_be(dn->settings->pool_end)))

static int dhcp_settings_cmp(void *ka, void *kb)
{
  struct pico_dhcpd_settings *a = ka, *b = kb;
  if (a->dev < b->dev)
    return -1; 
  else if (a->dev > b->dev)
    return 1;
  else
    return 0;
} 
PICO_TREE_DECLARE(DHCPSettings, dhcp_settings_cmp);

static int dhcp_negotiations_cmp(void *ka, void *kb)
{
  struct pico_dhcp_negotiation *a = ka, *b = kb;
  if (a->xid < b->xid)
    return -1; 
  else if (a->xid > b->xid)
    return 1;
  else
    return 0;
} 
PICO_TREE_DECLARE(DHCPNegotiations, dhcp_negotiations_cmp);

static struct pico_dhcp_negotiation *get_negotiation_by_xid(uint32_t xid)
{
  struct pico_dhcp_negotiation test = { }, *neg = NULL;

  test.xid = xid;
  neg = pico_tree_findKey(&DHCPNegotiations, &test);
  if (!neg)
    return NULL;
  else
    return neg;
}

static void dhcpd_make_reply(struct pico_dhcp_negotiation *dn, uint8_t reply_type)
{
  uint8_t buf_out[DHCPD_DATAGRAM_SIZE] = {0};
  struct pico_dhcphdr *dh_out = (struct pico_dhcphdr *) buf_out;
  struct pico_ip4 destination = { };
  uint32_t bcast = dn->settings->my_ip.addr | ~(dn->settings->netmask.addr);
  uint32_t dns_server = OPENDNS;
  uint16_t port = PICO_DHCP_CLIENT_PORT;
  int sent = 0;

  memcpy(dh_out->hwaddr, dn->eth.addr, PICO_HLEN_ETHER);
  dh_out->op = PICO_DHCP_OP_REPLY;
  dh_out->htype = PICO_HTYPE_ETHER;
  dh_out->hlen = PICO_HLEN_ETHER;
  dh_out->xid = dn->xid;
  dh_out->yiaddr = dn->ipv4.addr;
  dh_out->siaddr = dn->settings->my_ip.addr;
  dh_out->dhcp_magic = PICO_DHCPD_MAGIC_COOKIE;

  /* Option: msg type, len 1 */
  dh_out->options[0] = PICO_DHCPOPT_MSGTYPE;
  dh_out->options[1] = 1;
  dh_out->options[2] = reply_type;

  /* Option: server id, len 4 */
  dh_out->options[3] = PICO_DHCPOPT_SERVERID;
  dh_out->options[4] = 4;
  memcpy(dh_out->options + 5, &dn->settings->my_ip.addr, 4);

  /* Option: Lease time, len 4 */
  dh_out->options[9] = PICO_DHCPOPT_LEASETIME;
  dh_out->options[10] = 4;
  memcpy(dh_out->options + 11, &dn->settings->lease_time, 4);

  /* Option: Netmask, len 4 */
  dh_out->options[15] = PICO_DHCPOPT_NETMASK;
  dh_out->options[16] = 4;
  memcpy(dh_out->options + 17, &dn->settings->netmask.addr, 4);

  /* Option: Router, len 4 */
  dh_out->options[21] = PICO_DHCPOPT_ROUTER;
  dh_out->options[22] = 4;
  memcpy(dh_out->options + 23, &dn->settings->my_ip.addr, 4);

  /* Option: Broadcast, len 4 */
  dh_out->options[27] = PICO_DHCPOPT_BCAST;
  dh_out->options[28] = 4;
  memcpy(dh_out->options + 29, &bcast, 4);

  /* Option: DNS, len 4 */
  dh_out->options[33] = PICO_DHCPOPT_DNS;
  dh_out->options[34] = 4;
  memcpy(dh_out->options + 35, &dns_server, 4);

  dh_out->options[40] = PICO_DHCPOPT_END;

  destination.addr = dh_out->yiaddr;

  sent = pico_socket_sendto(dn->settings->s, buf_out, DHCPD_DATAGRAM_SIZE, &destination, port);
  if (sent < 0) {
    dhcpd_dbg("DHCPD: sendto failed with code %d!\n", pico_err);
  }
}

static void dhcp_recv(struct pico_socket *s, uint8_t *buffer, int len)
{
  struct pico_dhcphdr *dhdr = (struct pico_dhcphdr *) buffer;
  struct pico_dhcp_negotiation *dn = get_negotiation_by_xid(dhdr->xid);
  struct pico_ip4* ipv4 = NULL;
  struct pico_dhcpd_settings test, *settings = NULL;
  uint8_t *nextopt, opt_data[20], opt_type;
  int opt_len = 20;
  uint8_t msg_type;
  uint32_t msg_reqIP = 0;
  uint32_t msg_servID = 0;

  if (!is_options_valid(dhdr->options, len - sizeof(struct pico_dhcphdr))) {
    dhcpd_dbg("DHCPD WARNING: invalid options in dhcp message\n");
    return;
  }

  if (!dn) {
    dn = pico_zalloc(sizeof(struct pico_dhcp_negotiation));
    if (!dn) {
      pico_err = PICO_ERR_ENOMEM;
      return;
    }
    dn->xid = dhdr->xid;
    dn->state = DHCPSTATE_DISCOVER;
    memcpy(dn->eth.addr, dhdr->hwaddr, PICO_HLEN_ETHER);

    test.dev = pico_ipv4_link_find(&s->local_addr.ip4);
    settings = pico_tree_findKey(&DHCPSettings, &test);
    if (settings) {
      dn->settings = settings;
    } else {
      dhcpd_dbg("DHCPD WARNING: received DHCP message on unconfigured link %s\n", test.dev->name);
      pico_free(dn);
      return;
    }

    ipv4 = pico_arp_reverse_lookup(&dn->eth);
    if (!ipv4) {
      dn->ipv4.addr = settings->pool_next;
      pico_arp_create_entry(dn->eth.addr, dn->ipv4, settings->dev);
      settings->pool_next = long_be(long_be(settings->pool_next) + 1);
    } else {
      dn->ipv4.addr = ipv4->addr;
    }

    if (pico_tree_insert(&DHCPNegotiations, dn)) {
      dhcpd_dbg("DHCPD WARNING: tried creating new negotation for existing xid %u\n", dn->xid);
      pico_free(dn);
      return; /* Element key already exists */
    }
  }
 
  if (!ip_inrange(dn->ipv4.addr))
    return;

  opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
  while (opt_type != PICO_DHCPOPT_END) {
    /* parse interesting options here */
      //dhcpd_dbg("DHCPD sever: opt_type %x,  opt_data[0]%d\n", opt_type, opt_data[0]);
    switch(opt_type){
      case PICO_DHCPOPT_MSGTYPE:
        msg_type = opt_data[0];
        break;
      case PICO_DHCPOPT_REQIP:
        //dhcpd_dbg("DHCPD sever: opt_type %x,  opt_len%d\n", opt_type, opt_len);
        if( opt_len == 4)
        {
          msg_reqIP =  ( opt_data[0] << 24 );
          msg_reqIP |= ( opt_data[1] << 16 );
          msg_reqIP |= ( opt_data[2] << 8  );
          msg_reqIP |= ( opt_data[3]       );
         //dhcpd_dbg("DHCPD sever: msg_reqIP %x, opt_data[0] %x,[1] %x,[2] %x,[3] %x\n", msg_reqIP, opt_data[0],opt_data[1],opt_data[2],opt_data[3]);
        };
        break;
      case PICO_DHCPOPT_SERVERID:
        //dhcpd_dbg("DHCPD sever: opt_type %x,  opt_len%d\n", opt_type, opt_len);
        if( opt_len == 4)
        {
          msg_servID =  ( opt_data[0] << 24 );
          msg_servID |= ( opt_data[1] << 16 );
          msg_servID |= ( opt_data[2] << 8  );
          msg_servID |= ( opt_data[3]       );
          //dhcpd_dbg("DHCPD sever: msg_servID %x, opt_data[0] %x,[1] %x,[2] %x,[3] %x\n", msg_servID, opt_data[0],opt_data[1],opt_data[2],opt_data[3]);
        };
        break;        
      default:
        break;
    }
        
    opt_len = 20;
    opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
  }
    
  //dhcpd_dbg("DHCPD sever: msg_type %d, dn->state %d\n", msg_type, dn->state);
  //dhcpd_dbg("DHCPD sever: msg_reqIP %x, dn->msg_servID %x\n", msg_reqIP, msg_servID);
  //dhcpd_dbg("DHCPD sever: dhdr->ciaddr %x, dhdr->yiaddr %x, dn->ipv4.addr %x\n", dhdr->ciaddr,dhdr->yiaddr,dn->ipv4.addr);

  if (msg_type == PICO_DHCP_MSG_DISCOVER)
  {
    dhcpd_make_offer(dn);
    dn->state = DHCPSTATE_OFFER;
    return;
  }
  else if ((msg_type == PICO_DHCP_MSG_REQUEST)&&( dn->state == DHCPSTATE_OFFER))
  {
    dhcpd_make_ack(dn);
    dn->state = DHCPSTATE_BOUND;
    return;
  }
  else if ((msg_type == PICO_DHCP_MSG_REQUEST)&&( dn->state == DHCPSTATE_BOUND))
  {
    if( ( msg_servID == 0 )
      &&( msg_reqIP == 0 )
      &&( dhdr->ciaddr == dn->ipv4.addr)
      )
    { 
      dhcpd_make_ack(dn);
      return;
    }
  }  
}

static void pico_dhcpd_wakeup(uint16_t ev, struct pico_socket *s)
{
  uint8_t buf[DHCPD_DATAGRAM_SIZE] = { };
  int r = 0;
  uint32_t peer = 0;
  uint16_t port = 0;

  dhcpd_dbg("DHCPD: called dhcpd_wakeup\n");
  if (ev == PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_recvfrom(s, buf, DHCPD_DATAGRAM_SIZE, &peer, &port);
      if (r > 0 && port == PICO_DHCP_CLIENT_PORT) {
        dhcp_recv(s, buf, r);
      }
    } while(r>0);
  }
}

int pico_dhcp_server_initiate(struct pico_dhcpd_settings *setting)
{
  struct pico_dhcpd_settings *settings = NULL;
  struct pico_ipv4_link *link = NULL;
  uint16_t port = PICO_DHCPD_PORT;

  if (!setting) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  if (!setting->my_ip.addr) {
    pico_err = PICO_ERR_EINVAL;
    dhcpd_dbg("DHCPD: IP address of interface was not supplied\n");
    return -1;
  }

  link = pico_ipv4_link_get(&setting->my_ip);
  if (!link) {
    pico_err = PICO_ERR_EINVAL;
    dhcpd_dbg("DHCPD: no link with IP %X found\n", setting->my_ip.addr);
    return -1;
  }

  settings = pico_zalloc(sizeof(struct pico_dhcpd_settings));
  if (!settings) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  memcpy(settings, setting, sizeof(struct pico_dhcpd_settings));

  settings->dev = link->dev;
  dhcpd_dbg("DHCPD: configuring DHCP server for link %s\n", link->dev->name);
  settings->my_ip.addr = link->address.addr;
  dhcpd_dbg("DHCPD: using server addr %X\n", long_be(settings->my_ip.addr));
  settings->netmask.addr = link->netmask.addr;
  dhcpd_dbg("DHCPD: using netmask %X\n", long_be(settings->netmask.addr));

  /* default values if not provided */
  if (settings->pool_start == 0)
    settings->pool_start = (settings->my_ip.addr & settings->netmask.addr) | POOL_START;
  dhcpd_dbg("DHCPD: using pool_start %X\n", long_be(settings->pool_start));
  if (settings->pool_end == 0)
    settings->pool_end = (settings->my_ip.addr & settings->netmask.addr) | POOL_END;
  dhcpd_dbg("DHCPD: using pool_end %x\n", long_be(settings->pool_end));
  if (settings->lease_time == 0)
    settings->lease_time = LEASE_TIME;
  dhcpd_dbg("DHCPD: using lease time %x\n", long_be(settings->lease_time));
  settings->pool_next = settings->pool_start;

  settings->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dhcpd_wakeup);
  if (!settings->s) {
    dhcpd_dbg("DHCP: could not open client socket\n");
    pico_free(settings);
    return -1;
  }
  if (pico_socket_bind(settings->s, &settings->my_ip, &port) != 0) {
    dhcpd_dbg("DHCP: could not bind server socket (%s)\n", strerror(pico_err));
    pico_free(settings);
    return -1;
  }
  
  if (pico_tree_insert(&DHCPSettings, settings)) {
    dhcpd_dbg("DHCPD ERROR: link %s already configured\n", link->dev->name);
    pico_err = PICO_ERR_EINVAL;
    pico_free(settings);
    return -1; /* Element key already exists */
  }
  dhcpd_dbg("DHCPD: configured DHCP server for link %s\n", link->dev->name);

  return 0;
}
#endif /* PICO_SUPPORT_DHCP */
