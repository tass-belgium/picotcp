#include "pico_dhcp_server.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_arp.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

static struct pico_dhcp_negotiation *Negotiation_list;
static struct pico_socket *udpsock;
static struct pico_dhcpd_settings settings;

/* should check out OK */
static void pico_dhcpd_wakeup(uint16_t ev, struct pico_socket *s);

//TODO could probably replace this with an rb-tree...
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

static uint8_t dhcp_get_next_option(uint8_t *begin, uint8_t *data, int *len, uint8_t **nextopt)
{
	uint8_t *p;
	uint8_t type;
	uint8_t opt_len;

	if (!begin)
		p = *nextopt;
	else
		p = begin;

	type = *p;
	*nextopt = ++p;
	if ((type == PICO_DHCPOPT_END) || (type == PICO_DHCPOPT_PAD)) {
		memset(data, 0, *len);
		len = 0;
		return type;
	}
	opt_len = *p;
	p++;
	if (*len > opt_len)
		*len = opt_len;
	memcpy(data, p, *len);
	*nextopt = p + opt_len;
	return type;
}

static int is_options_valid(uint8_t *opt_buffer, int len)
{
	uint8_t *p = opt_buffer;
	while (len > 0) {
		if (*p == PICO_DHCPOPT_END)
			return 1;
		else if (*p == PICO_DHCPOPT_PAD) {
			p++;
			len--;
		} else {
			uint8_t opt_len;
			p++;
			len--;
			opt_len = *p;
			p += opt_len + 1;
			len -= opt_len;
		}
	}
	return 0;
}

#define DHCPD_DATAGRAM_SIZE 300

/* TODO change this around...*/ 

static void dhcpd_make_reply(struct pico_dhcp_negotiation *dn, uint8_t reply_type)
{

	uint8_t buf_out[DHCPD_DATAGRAM_SIZE] = {0};
	struct pico_dhcphdr *dh_out = (struct pico_dhcphdr *) buf_out;
	uint32_t server_address = SERVER_ADDR;
	uint32_t netmask = NETMASK;
	uint32_t bcast = BROADCAST;
	uint32_t dns_server = OPENDNS;
	uint16_t port = PICO_DHCP_CLIENT_PORT;
	struct pico_ip4 destination;

	int sent = 0;
	dbg("getting ready for a reply\n");


	memcpy(dh_out->hwaddr, dn->hwaddr, PICO_HLEN_ETHER);
	dh_out->op = PICO_DHCP_OP_REPLY;
	dh_out->htype = PICO_HTYPE_ETHER;
	dh_out->hlen = PICO_HLEN_ETHER;
	dh_out->xid = dn->xid;
	dh_out->yiaddr = dn->arp->ipv4.addr;
	dh_out->siaddr = server_address;
	dh_out->dhcp_magic = PICO_DHCPD_MAGIC_COOKIE;

	/* Option: msg type, len 1 */
	dh_out->options[0] = PICO_DHCPOPT_MSGTYPE;
	dh_out->options[1] = 1;
	dh_out->options[2] = reply_type;

	/* Option: server id, len 4 */
	dh_out->options[3] = PICO_DHCPOPT_SERVERID;
	dh_out->options[4] = 4;
	memcpy(dh_out->options + 5, &server_address, 4);

	/* Option: Lease time, len 4 */
	dh_out->options[9] = PICO_DHCPOPT_LEASETIME;
	dh_out->options[10] = 4;
	memcpy(dh_out->options + 11, &settings.lease_time, 4);

	/* Option: Netmask, len 4 */
	dh_out->options[15] = PICO_DHCPOPT_NETMASK;
	dh_out->options[16] = 4;
	memcpy(dh_out->options + 17, &netmask, 4);

	/* Option: Router, len 4 */
	dh_out->options[21] = PICO_DHCPOPT_ROUTER;
	dh_out->options[22] = 4;
	memcpy(dh_out->options + 23, &server_address, 4);

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
	dbg("just before sending!\n");
	sent = pico_socket_sendto(udpsock, buf_out, DHCP_DATAGRAM_SIZE, &destination, port);
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
			dn->arp->ipv4.addr = settings.pool_next;
			dn->arp->dev = settings.dev;
			pico_arp_add_entry(dn->arp);

			settings.pool_next = long_be(long_be(settings.pool_next) + 1);
		}
	}

	printf("foobarxyzzy\n");
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
				dhcpd_make_ack(dn);
				return;
			}
		}
		opt_len = 20;
		opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
	}
}


void pico_dhcp_server_loop(struct pico_device* device)
{
	uint16_t port = PICO_DHCPD_PORT;
	struct pico_ip4 address;

	if(!device)
		return;

	address.addr = SERVER_ADDR;


	settings.dev = device;
	settings.pool_start = POOL_START;
	settings.pool_end = POOL_END;
	settings.lease_time = LEASE_TIME;

	settings.pool_next = settings.pool_start;

	udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dhcpd_wakeup);
	if (!udpsock) {
		dbg("DHCP>could not open client socket\n");
		//if(cli->cb != NULL)
			//cli->cb(cli, PICO_DHCP_ERROR);
		return;
	}
	if (pico_socket_bind(udpsock, &address, &port) != 0){
		dbg("DHCP>could not bind client socket\n");
		//if(cli->cb != NULL)
			//cli->cb(cli, PICO_DHCP_ERROR);
		return;
	}
}

static void pico_dhcpd_wakeup(uint16_t ev, struct pico_socket *s)
{
	uint8_t buf[DHCP_DATAGRAM_SIZE];
	int r=0;
	uint32_t peer;
	uint16_t port;
	//int type;

	//struct pico_dhcp_client_cookie *cli = &dhcp_client;
	dbg("DHCP>Called dhcpd_wakeup\n");
	if (ev == PICO_SOCK_EV_RD) {
		do {
			r = pico_socket_recvfrom(s, buf, DHCP_DATAGRAM_SIZE, &peer, &port);
			if (r > 0 && port == PICO_DHCP_CLIENT_PORT) {
				//type = pico_dhcp_verify_and_identify_type(buf, r, cli);//TODO make this work...or should we? dhcp_recv doesn't need it....
				//pico_dhcp_state_machine(type, cli, buf, r);
				dbg("bar\n");
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
 *
 * longer term :
 *
 * obey the Broadcast-flag!
 */
