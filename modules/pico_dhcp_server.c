/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Frederik Van Slycken
*********************************************************************/

#ifdef PICO_SUPPORT_DHCPD

#include "pico_dhcp_server.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_arp.h"
#include <stdlib.h>

static struct pico_dhcp_negotiation *Negotiation_list;
static struct pico_socket *udpsock;
static struct pico_dhcpd_settings settings;

static void pico_dhcpd_wakeup(uint16_t ev, struct pico_socket *s);

//TODO could/should probably replace this with an rb-tree...
static struct pico_dhcp_negotiation * get_negotiation_by_xid(uint32_t xid)
{
	struct pico_dhcp_negotiation *cur = Negotiation_list;
	while (cur) {
		if (cur->xid == xid)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

static void dhcpd_make_reply(struct pico_dhcp_negotiation *dn, uint8_t reply_type)
{

	uint8_t buf_out[DHCPD_DATAGRAM_SIZE] = {0};
	struct pico_dhcphdr *dh_out = (struct pico_dhcphdr *) buf_out;
	uint32_t bcast = BROADCAST;
	uint32_t dns_server = OPENDNS;
	uint16_t port = PICO_DHCP_CLIENT_PORT;
	struct pico_ip4 destination;

	int sent = 0;

	memcpy(dh_out->hwaddr, dn->hwaddr, PICO_HLEN_ETHER);
	dh_out->op = PICO_DHCP_OP_REPLY;
	dh_out->htype = PICO_HTYPE_ETHER;
	dh_out->hlen = PICO_HLEN_ETHER;
	dh_out->xid = dn->xid;
	dh_out->yiaddr = dn->arp->ipv4.addr;
	dh_out->siaddr = settings.my_ip.addr;
	dh_out->dhcp_magic = PICO_DHCPD_MAGIC_COOKIE;

	/* Option: msg type, len 1 */
	dh_out->options[0] = PICO_DHCPOPT_MSGTYPE;
	dh_out->options[1] = 1;
	dh_out->options[2] = reply_type;

	/* Option: server id, len 4 */
	dh_out->options[3] = PICO_DHCPOPT_SERVERID;
	dh_out->options[4] = 4;
	memcpy(dh_out->options + 5, &settings.my_ip.addr, 4);

	/* Option: Lease time, len 4 */
	dh_out->options[9] = PICO_DHCPOPT_LEASETIME;
	dh_out->options[10] = 4;
	memcpy(dh_out->options + 11, &settings.lease_time, 4);

	/* Option: Netmask, len 4 */
	dh_out->options[15] = PICO_DHCPOPT_NETMASK;
	dh_out->options[16] = 4;
	memcpy(dh_out->options + 17, &settings.netmask.addr, 4);

	/* Option: Router, len 4 */
	dh_out->options[21] = PICO_DHCPOPT_ROUTER;
	dh_out->options[22] = 4;
	memcpy(dh_out->options + 23, &settings.my_ip.addr, 4);

	/* Option: Broadcast, len 4 */
	dh_out->options[27] = PICO_DHCPOPT_BCAST;
	dh_out->options[28] = 4;
	memcpy(dh_out->options + 29, &bcast, 4);

	/* Option: DNS, len 4 */
	dh_out->options[33] = PICO_DHCPOPT_DNS;
	dh_out->options[34] = 4;
	memcpy(dh_out->options + 35, &dns_server, 4);

	dh_out->options[40] = PICO_DHCPOPT_END;

	//TODO find out where we checked if yiaddr is OK...
	destination.addr = dh_out->yiaddr;
	sent = pico_socket_sendto(udpsock, buf_out, DHCPD_DATAGRAM_SIZE, &destination, port);
	if (sent < 0) {
		dbg("DHCPD>sendto failed with code %d!\n", pico_err);
	}
}

#define dhcpd_make_offer(x) dhcpd_make_reply(x, PICO_DHCP_MSG_OFFER)
#define dhcpd_make_ack(x) dhcpd_make_reply(x, PICO_DHCP_MSG_ACK)

#define ip_inrange(x) ((long_be(x) >= long_be(settings.pool_start)) && (long_be(x) <= long_be(settings.pool_end)))

static void dhcp_recv(uint8_t *buffer, int len)
{
	struct pico_dhcphdr *dhdr = (struct pico_dhcphdr *) buffer;
	//TODO does this mean we only give out the same ip if the xid was the same? shouldn't we be looking at the MAC address? 
	struct pico_dhcp_negotiation *dn = get_negotiation_by_xid(dhdr->xid);
	uint8_t *nextopt, opt_data[20], opt_type;
	int opt_len = 20;


	if (!is_options_valid(dhdr->options, len - sizeof(struct pico_dhcphdr)))
		return;


	if (!dn) {
		dn = malloc(sizeof(struct pico_dhcp_negotiation));
		memset(dn, 0, sizeof(struct pico_dhcp_negotiation));
		dn->xid = dhdr->xid;
		dn->state = DHCPSTATE_DISCOVER;
		memcpy(dn->hwaddr, dhdr->hwaddr, PICO_HLEN_ETHER);
		dn->next = Negotiation_list;
		Negotiation_list = dn;
		dn->arp = pico_arp_get_entry_by_mac(dn->hwaddr);
		if (!dn->arp) {
			//allocate memory for arp entry
			dn->arp = pico_zalloc(sizeof(struct pico_arp));
			if (!dn->arp)
				return;
			//fill in arp entry, add it to the tree
			memcpy(dn->arp->eth.addr, dn->hwaddr, PICO_HLEN_ETHER);
			//TODO this means we completely ignore it if there was an option requesting a specific address...
			dn->arp->ipv4.addr = settings.pool_next;
			dn->arp->dev = settings.dev;
			pico_arp_add_entry(dn->arp);

			settings.pool_next = long_be(long_be(settings.pool_next) + 1);
		}
	}

	if (!ip_inrange(dn->arp->ipv4.addr))
		return;


	opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
	while (opt_type != PICO_DHCPOPT_END) {
		/* parse interesting options here */
		if (opt_type == PICO_DHCPOPT_MSGTYPE) {

			/* server simple state machine */
			uint8_t msg_type = opt_data[0];
			if (msg_type == PICO_DHCP_MSG_DISCOVER) {
				dhcpd_make_offer(dn);
				dn->state = DHCPSTATE_OFFER;
				return;
			} else if (msg_type == PICO_DHCP_MSG_REQUEST) {
				//TODO does this mean that we can simply send a REQUEST right away and have it acked without any debate? 
				dhcpd_make_ack(dn);
				return;
			}
		}
		opt_len = 20;
		opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
	}
}


//TODO should we return something when things go wrong? or a callback (like in the client?)
//This function gets a pico_dhcpd_settings-struct. 
void pico_dhcp_server_initiate(struct pico_dhcpd_settings* setting)
{
	uint16_t port = PICO_DHCPD_PORT;

	if(!setting->dev)
		return;

	memcpy(&settings,setting,sizeof(struct pico_dhcpd_settings));
	dbg("DHCPD>initiating server\n");

	//default values if not filled in!
	if(settings.my_ip.addr == 0){
		settings.my_ip.addr = SERVER_ADDR;
		dbg("DHCPD>  using default server addr\n");
	}else{
		dbg("DHCPD> using server addr %x\n",settings.my_ip.addr);
	}
	if(settings.netmask.addr == 0){
		settings.netmask.addr = NETMASK;
		dbg("DHCPD>  using default netmask\n");
	}else{
		dbg("DHCPD> using netmask %x\n",settings.netmask.addr);
	}

	if(settings.pool_start == 0){
		settings.pool_start = POOL_START;
		dbg("DHCPD>  using default pool_start\n");
	}else{
		dbg("DHCPD> using pool_start %x\n",settings.pool_start);
	}
	if(settings.pool_end == 0){
		settings.pool_end = POOL_END;
		dbg("DHCPD>  using default pool_end\n");
	}else{
		dbg("DHCPD> using pool_end %x\n",settings.pool_end);
	}
	if(settings.lease_time == 0){
		settings.lease_time = LEASE_TIME;
		dbg("DHCPD>  using default lease time\n");
	}else{
		dbg("DHCPD> using lease time %x\n",settings.lease_time);
	}

	settings.pool_next = settings.pool_start;

	udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dhcpd_wakeup);
	if (!udpsock) {
		dbg("DHCP>could not open client socket\n");
		//if(cli->cb != NULL)
			//cli->cb(cli, PICO_DHCP_ERROR);
		return;
	}
	if (pico_socket_bind(udpsock, &settings.my_ip, &port) != 0){
		dbg("DHCP>could not bind client socket\n");
		//if(cli->cb != NULL)
			//cli->cb(cli, PICO_DHCP_ERROR);
		return;
	}
}

static void pico_dhcpd_wakeup(uint16_t ev, struct pico_socket *s)
{
	uint8_t buf[DHCPD_DATAGRAM_SIZE];
	int r=0;
	uint32_t peer;
	uint16_t port;
	//int type;

	//struct pico_dhcp_client_cookie *cli = &dhcp_client;
	dbg("DHCP>Called dhcpd_wakeup\n");
	if (ev == PICO_SOCK_EV_RD) {
		do {
			r = pico_socket_recvfrom(s, buf, DHCPD_DATAGRAM_SIZE, &peer, &port);
			if (r > 0 && port == PICO_DHCP_CLIENT_PORT) {
				dhcp_recv(buf, r);
			}
		} while(r>0);
	}
}

/*
 * TODO's, ideas, remarks,...
 *
 * getting the hwaddr of the other end could prove somewhat difficult... but we don't need it...wtf?
 *
 * We're going to get into the same kind of funky stuff : it will only work on one interface at a time...
 *
 * it seems that DHCP relies on info from ARP for assigning IPs... Not sure if this can't cause any problems...
 *
 *
 * longer term :
 *
 * obey the Broadcast-flag!
 */

#endif
