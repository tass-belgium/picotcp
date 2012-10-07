#include "vder_udp.h"
#include "vder_arp.h"
#include "vder_dhcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

static struct vder_dhcp_negotiation *Negotiation_list;
static struct vder_udp_socket *udpsock;
static struct vder_dhcpd_settings Settings;

static struct vder_dhcp_negotiation *
get_negotiation_by_xid(uint32_t xid)
{
	struct vder_dhcp_negotiation *cur = Negotiation_list;
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
	if ((type == DHCPOPT_END) || (type == DHCPOPT_PAD)) {
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
		if (*p == DHCPOPT_END)
			return 1;
		else if (*p == DHCPOPT_PAD) {
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

#define DHCP_DATAGRAM_SIZE 300
#define OPENDNS (htonl(0xd043dede))

static void dhcpd_make_reply(struct vder_dhcp_negotiation *dn, uint8_t reply_type)
{

	uint8_t buf_out[DHCP_DATAGRAM_SIZE] = {0};
	struct dhcphdr *dh_out = (struct dhcphdr *) buf_out;
	uint32_t server_address = vder_get_right_localip(Settings.iface, Settings.pool_next);
	uint32_t netmask = vder_get_netmask(Settings.iface, server_address);
	uint32_t bcast = vder_get_broadcast(server_address, netmask);
	uint32_t dns_server = OPENDNS;

	int sent = 0;


	memcpy(dh_out->hwaddr, dn->hwaddr, HLEN_ETHER);
	dh_out->op = DHCP_OP_REPLY;
	dh_out->htype = HTYPE_ETHER;
	dh_out->hlen = HLEN_ETHER;
	dh_out->xid = dn->xid;
	dh_out->yiaddr = dn->arp->ipaddr;
	dh_out->siaddr = server_address;
	dh_out->dhcp_magic = DHCPD_MAGIC_COOKIE;

	/* Option: msg type, len 1 */
	dh_out->options[0] = DHCPOPT_MSGTYPE;
	dh_out->options[1] = 1;
	dh_out->options[2] = reply_type;

	/* Option: server id, len 4 */
	dh_out->options[3] = DHCPOPT_SERVERID;
	dh_out->options[4] = 4;
	memcpy(dh_out->options + 5, &server_address, 4);

	/* Option: Lease time, len 4 */
	dh_out->options[9] = DHCPOPT_LEASETIME;
	dh_out->options[10] = 4;
	memcpy(dh_out->options + 11, &Settings.lease_time, 4);

	/* Option: Netmask, len 4 */
	dh_out->options[15] = DHCPOPT_NETMASK;
	dh_out->options[16] = 4;
	memcpy(dh_out->options + 17, &netmask, 4);

	/* Option: Router, len 4 */
	dh_out->options[21] = DHCPOPT_ROUTER;
	dh_out->options[22] = 4;
	memcpy(dh_out->options + 23, &server_address, 4);

	/* Option: Broadcast, len 4 */
	dh_out->options[27] = DHCPOPT_BCAST;
	dh_out->options[28] = 4;
	memcpy(dh_out->options + 29, &bcast, 4);

	/* Option: DNS, len 4 */
	dh_out->options[33] = DHCPOPT_DNS;
	dh_out->options[34] = 4;
	memcpy(dh_out->options + 35, &dns_server, 4);

	dh_out->options[40] = DHCPOPT_END;

	sent = vder_udpsocket_sendto(udpsock, buf_out, DHCP_DATAGRAM_SIZE, dh_out->yiaddr, DHCP_CLIENT_PORT);
	if (sent < 0) {
		perror("udp sendto");
	}
}

#define dhcpd_make_offer(x) dhcpd_make_reply(x, DHCP_MSG_OFFER)
#define dhcpd_make_ack(x) dhcpd_make_reply(x, DHCP_MSG_ACK)

#define ip_inrange(x) ((ntohl(x) >= ntohl(Settings.pool_start)) && (ntohl(x) <= ntohl(Settings.pool_end)))

static void dhcp_recv(uint8_t *buffer, int len)
{
	struct dhcphdr *dhdr = (struct dhcphdr *) buffer;
	struct vder_dhcp_negotiation *dn = get_negotiation_by_xid(dhdr->xid);
	uint8_t *nextopt, opt_data[20], opt_type;
	int opt_len = 20;


	if (!is_options_valid(dhdr->options, len - sizeof(struct dhcphdr)))
		return;



	if (!dn) {
		dn = malloc(sizeof(struct vder_dhcp_negotiation));
		memset(dn, 0, sizeof(struct vder_dhcp_negotiation));
		dn->xid = dhdr->xid;
		dn->state = DHCPSTATE_DISCOVER;
		memcpy(dn->hwaddr, dhdr->hwaddr, HLEN_ETHER);
		dn->next = Negotiation_list;
		Negotiation_list = dn;
		dn->arp = vder_arp_get_record_by_macaddr(Settings.iface, dn->hwaddr);
		if (!dn->arp) {
			dn->arp = malloc(sizeof(struct vder_arp_entry));
			if (!dn->arp)
				return;
			memcpy(dn->arp->macaddr, dn->hwaddr, HLEN_ETHER);
			dn->arp->ipaddr = Settings.pool_next;
			Settings.pool_next = htonl(ntohl(Settings.pool_next) + 1);
			vder_add_arp_entry(Settings.iface, dn->arp);
		}
	}

	if (!ip_inrange(dn->arp->ipaddr))
		return;


	opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
	while (opt_type != DHCPOPT_END) {
		/* parse interesting options here */
		if (opt_type == DHCPOPT_MSGTYPE) {

			/* server simple state machine */
			uint8_t msg_type = opt_data[0];
			if (msg_type == DHCP_MSG_DISCOVER) {
				dhcpd_make_offer(dn);
				dn->state = DHCPSTATE_OFFER;
				return;
			} else if (msg_type == DHCP_MSG_REQUEST) {
				dhcpd_make_ack(dn);
				return;
			}
		}
		opt_len = 20;
		opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
	}
}


void *dhcp_server_loop(void *ptr_settings)
{
	uint32_t from_ip;
	uint16_t from_port;

	unsigned char buffer[2000];
	int len;

	memcpy(&Settings, ptr_settings, sizeof(struct vder_dhcpd_settings));
	Settings.pool_next = Settings.pool_start;
	free(ptr_settings);


	if(!Settings.iface)
		return NULL;
	if (!udpsock)
		udpsock = vder_udpsocket_open(DHCPD_PORT);
	if (!udpsock)
		return NULL;


	while(1) {
		len = vder_udpsocket_recvfrom(udpsock, buffer, 2000, &from_ip, &from_port, -1);
		if (len < 0) {
			perror("udp recv");
			return NULL;
		}
		if ((from_ip == 0) && (from_port == DHCP_CLIENT_PORT)) {
			dhcp_recv(buffer, len);
		}
	}
}



struct dhcp_client_cookie
{
	uint32_t xid;
	uint32_t address;
	uint32_t netmask;
	uint32_t gateway;
	uint32_t server_id;
	uint32_t lease_time;
	struct vder_udp_socket *socket;
	struct vder_iface *iface;
	struct timeval start_time;
	int attempt;
	enum dhcp_negotiation_state state;
};

static int dhclient_recv_offer(struct dhcp_client_cookie *cli, uint8_t *data, int len)
{
	struct dhcphdr *dhdr = (struct dhcphdr *) data;
	uint8_t *nextopt, opt_data[20], opt_type;
	int opt_len = 20;
	uint8_t msg_type = 0xFF;


	if (dhdr->xid != cli->xid) {
		printf("bad xid\n");
		return 0;
	}

	if (!is_options_valid(dhdr->options, len - sizeof(struct dhcphdr))) {
		printf("bad options\n");
		return 0;
	}

	cli->address = dhdr->yiaddr;

	opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
	while (opt_type != DHCPOPT_END) {
		if (opt_type == DHCPOPT_MSGTYPE)
			msg_type = opt_data[0];
		if ((opt_type == DHCPOPT_LEASETIME) && (opt_len == 4))
			memcpy(&cli->lease_time, opt_data, 4);
		if ((opt_type == DHCPOPT_ROUTER) && (opt_len == 4))
			memcpy(&cli->gateway, opt_data, 4);
		if ((opt_type == DHCPOPT_NETMASK) && (opt_len == 4))
			memcpy(&cli->netmask, opt_data, 4);
		if ((opt_type == DHCPOPT_SERVERID) && (opt_len == 4))
			memcpy(&cli->server_id, opt_data, 4);

		opt_len = 20;
		opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
	}
	if ((msg_type != DHCP_MSG_OFFER) || !cli->lease_time || !cli->netmask || !cli->server_id )
		return 0;
	return 1;
}

static int dhclient_recv_ack(struct dhcp_client_cookie *cli, uint8_t *data, int len)
{
	struct dhcphdr *dhdr = (struct dhcphdr *) data;
	uint8_t *nextopt, opt_data[20], opt_type;
	int opt_len = 20;
	uint8_t msg_type = 0xFF;

	if (dhdr->xid != cli->xid)
		return 0;

	if (!is_options_valid(dhdr->options, len - sizeof(struct dhcphdr)))
		return 0;


	opt_type = dhcp_get_next_option(dhdr->options, opt_data, &opt_len, &nextopt);
	while (opt_type != DHCPOPT_END) {
		if (opt_type == DHCPOPT_MSGTYPE)
			msg_type = opt_data[0];

		opt_len = 20;
		opt_type = dhcp_get_next_option(NULL, opt_data, &opt_len, &nextopt);
	}
	if (msg_type != DHCP_MSG_ACK)
		return 0;
	return 1;
}


static void dhclient_send(struct dhcp_client_cookie *cli, uint8_t msg_type)
{

	uint8_t buf_out[DHCP_DATAGRAM_SIZE] = {0};
	struct dhcphdr *dh_out = (struct dhcphdr *) buf_out;
	int sent = 0;
	struct timeval now;
	int i = 0;
	gettimeofday(&now, NULL);

	memcpy(dh_out->hwaddr, cli->iface->macaddr, HLEN_ETHER);
	dh_out->op = DHCP_OP_REQUEST;
	dh_out->htype = HTYPE_ETHER;
	dh_out->hlen = HLEN_ETHER;
	dh_out->xid = cli->xid;
	dh_out->secs = (msg_type == DHCP_MSG_REQUEST)?0:htons(now.tv_sec - cli->start_time.tv_sec);
	dh_out->dhcp_magic = DHCPD_MAGIC_COOKIE;


	/* Option: msg type, len 1 */
	dh_out->options[i++] = DHCPOPT_MSGTYPE;
	dh_out->options[i++] = 1;
	dh_out->options[i++] = msg_type;

	if (msg_type == DHCP_MSG_REQUEST) {
		dh_out->options[i++] = DHCPOPT_REQIP;
		dh_out->options[i++] = 4;
		dh_out->options[i++] = (ntohl(cli->address) & 0xFF000000) >> 24;
		dh_out->options[i++] = (ntohl(cli->address) & 0xFF0000) >> 16;
		dh_out->options[i++] = (ntohl(cli->address) & 0xFF00) >> 8;
		dh_out->options[i++] = (ntohl(cli->address) & 0xFF);
		dh_out->options[i++] = DHCPOPT_SERVERID;
		dh_out->options[i++] = 4;
		dh_out->options[i++] = (ntohl(cli->server_id) & 0xFF000000) >> 24;
		dh_out->options[i++] = (ntohl(cli->server_id) & 0xFF0000) >> 16;
		dh_out->options[i++] = (ntohl(cli->server_id) & 0xFF00) >> 8;
		dh_out->options[i++] = (ntohl(cli->server_id) & 0xFF);
	}

	/* Option: req list, len 4 */
	dh_out->options[i++] = DHCPOPT_PARMLIST;
	dh_out->options[i++] = 5;
	dh_out->options[i++] = DHCPOPT_NETMASK;
	dh_out->options[i++] = DHCPOPT_BCAST;
	dh_out->options[i++] = DHCPOPT_TIME;
	dh_out->options[i++] = DHCPOPT_ROUTER;
	dh_out->options[i++] = DHCPOPT_HOSTNAME;

	dh_out->options[i] = DHCPOPT_END;

	sent = vder_udpsocket_sendto_broadcast(cli->socket, buf_out, DHCP_DATAGRAM_SIZE, cli->iface, (uint32_t)(-1), DHCPD_PORT);
	if (sent < 0) {
		perror("udp sendto");
	}
}

void dhcp_retry(struct dhcp_client_cookie *client)
{
	const int MAX_RETRY = 5;
	if (++client->attempt > MAX_RETRY) {
		gettimeofday(&client->start_time, NULL);
		client->attempt = 0;
		client->xid ^= client->start_time.tv_usec ^ client->start_time.tv_sec;
	}
}

void *dhcp_client_loop(void *iface)
{
	unsigned char buffer[2000];
	int len;
	struct dhcp_client_cookie client;
	uint16_t from_port;
	uint32_t from_ip;

	memset(&client, 0, sizeof(client));

	client.iface = (struct vder_iface *) iface;
	client.state = DHCPSTATE_DISCOVER;
	client.socket = vder_udpsocket_open(DHCP_CLIENT_PORT);
	if (!client.socket) {
		perror("dhcp client socket");
		return NULL;
	}

	gettimeofday(&client.start_time, NULL);
	client.attempt = 0;
	client.xid = client.start_time.tv_usec ^ client.start_time.tv_sec;


	if (!client.socket) {
		return NULL;
	}

	while(1) {
		switch (client.state) {
			case DHCPSTATE_DISCOVER:
				dhcp_retry(&client);
				dhclient_send(&client, DHCP_MSG_DISCOVER);
				len = vder_udpsocket_recvfrom(client.socket, buffer, 2000, &from_ip, &from_port, 5000);
				if (len < 0) {
					perror("udp recv");
					return NULL;
				}
				if (len > 0) {
					if (dhclient_recv_offer(&client, buffer, len)) {
						client.state = DHCPSTATE_REQUEST;
					}
				}
				break;
			case DHCPSTATE_REQUEST:
				dhclient_send(&client, DHCP_MSG_REQUEST);
				len = vder_udpsocket_recvfrom(client.socket, buffer, 2000, &from_ip, &from_port, 10000);
				if (len < 0) {
					perror("udp recv");
					return NULL;
				}
				if (len == 0)
					break;
				if (dhclient_recv_ack(&client, buffer, len))
					client.state = DHCPSTATE_ACK;
				else {
					if (client.address)
						vder_iface_address_del(client.iface, client.address);
					client.state = DHCPSTATE_DISCOVER;
					client.address = 0;
					client.netmask = 0;
					client.gateway = 0;
				}
				break;
			case DHCPSTATE_ACK:
				vder_iface_address_del(client.iface, (uint32_t)-1);
				vder_iface_address_add(client.iface, client.address, client.netmask);
				if ((client.gateway != 0) && ((client.gateway & client.netmask) == (client.address & client.netmask)))
					vder_route_add(0, 0, client.gateway, 1, client.iface);
				sleep(ntohl(client.lease_time));
				client.state = DHCPSTATE_REQUEST;
				break;
			default:
				client.address = 0;
				client.netmask = 0;
				client.gateway = 0;
				client.state = DHCPSTATE_DISCOVER;
		}
	}
}
