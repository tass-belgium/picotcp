#ifndef __VDER_DHCPD
#define __VDER_DHCPD

#include "vder_arp.h"

#define DHCPD_PORT (htons(67))
#define DHCP_CLIENT_PORT (htons(68))


#define DHCP_GATEWAY 0x01
#define DHCP_DNS 0x02

struct vder_dhcpd_settings
{
	struct vder_iface *iface;
	uint32_t my_ip;
	uint32_t netmask;
	uint32_t pool_start;
	uint32_t pool_next;
	uint32_t pool_end;
	unsigned long lease_time;
	uint8_t flags;
};

#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY   2

#define HTYPE_ETHER 1
#define HLEN_ETHER 6

#define FLAG_BROADCAST (htons(0xF000))

#define DHCPD_MAGIC_COOKIE (htonl(0x63825363))

/* DHCP OPTIONS, RFC2132 */
#define DHCPOPT_PAD 			0x00
#define DHCPOPT_NETMASK 		0x01
#define DHCPOPT_TIME			0x02
#define DHCPOPT_ROUTER 			0x03
#define DHCPOPT_DNS				0x06
#define DHCPOPT_HOSTNAME		0x0c
#define DHCPOPT_DOMAINNAME		0x0f
#define DHCPOPT_MTU 			0x1a
#define DHCPOPT_BCAST 			0x1c
#define DHCPOPT_NETBIOSNS	 	0x2c
#define DHCPOPT_NETBIOSSCOPE 	0x2f

#define DHCPOPT_REQIP			0x32
#define DHCPOPT_LEASETIME 		0x33
#define DHCPOPT_MSGTYPE			0x35
#define DHCPOPT_SERVERID 		0x36
#define DHCPOPT_PARMLIST 		0x37
#define DHCPOPT_RENEWALTIME 	0x3a
#define DHCPOPT_REBINDINGTIME	0x3b
#define DHCPOPT_DOMAINSEARCH	0x77
#define DHCPOPT_STATICROUTE		0x79
#define DHCPOPT_END 			0xFF

/* DHCP MESSAGE TYPE */
#define DHCP_MSG_DISCOVER 		1
#define DHCP_MSG_OFFER 			2
#define DHCP_MSG_REQUEST		3
#define DHCP_MSG_DECLINE		4
#define DHCP_MSG_ACK			5
#define DHCP_MSG_NAK			6
#define DHCP_MSG_RELEASE		7
#define DHCP_MSG_INFORM			8


struct __attribute__((packed)) dhcphdr
{
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops; //zero
	uint32_t xid; //store this in the request
	uint16_t secs; // ignore
	uint16_t flags;
	uint32_t ciaddr; // client address - if asking for renewal
	uint32_t yiaddr; // your address (client)
	uint32_t siaddr; // dhcp offered address
	uint32_t giaddr; // relay agent, bootp.
	uint8_t hwaddr[6];
	uint8_t hwaddr_padding[10];
	char 	hostname[64];
	char	bootp_filename[128]; 
	uint32_t dhcp_magic;
	uint8_t options[0];
};

enum dhcp_negotiation_state {
	DHCPSTATE_DISCOVER = 0,
	DHCPSTATE_OFFER,
	DHCPSTATE_REQUEST,
	DHCPSTATE_ACK
};

struct vder_dhcp_negotiation {
	struct vder_dhcp_negotiation *next;
	uint32_t xid;
	uint8_t hwaddr[6];
	uint32_t assigned_address;
	enum dhcp_negotiation_state state;
	struct vder_arp_entry *arp;
};

void *dhcp_server_loop(void *ptr_iface);
void *dhcp_client_loop(void *ptr_iface);

#endif
