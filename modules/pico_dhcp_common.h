/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

*********************************************************************/
#ifndef _INCLUDE_PICO_DHCP_COMMON
#define _INCLUDE_PICO_DHCP_COMMON

#if defined (PICO_SUPPORT_DHCPC) || defined (PICO_SUPPORT_DHCPD)

#include <stdint.h>

//minimum size is 576, cfr RFC
#define DHCPC_DATAGRAM_SIZE 576
#define DHCPD_DATAGRAM_SIZE 576


#define PICO_DHCPD_PORT (short_be(67))
#define PICO_DHCP_CLIENT_PORT (short_be(68))

#define PICO_DHCP_OP_REQUEST 1
#define PICO_DHCP_OP_REPLY   2

#define PICO_HTYPE_ETHER 1
#define PICO_HLEN_ETHER  6

#define PICO_DHCPD_MAGIC_COOKIE (long_be(0x63825363))

/* DHCP OPTIONS, RFC2132 */
#define PICO_DHCPOPT_PAD                     0x00
#define PICO_DHCPOPT_NETMASK                 0x01
#define PICO_DHCPOPT_TIME                    0x02
#define PICO_DHCPOPT_ROUTER                  0x03
#define PICO_DHCPOPT_DNS                     0x06
#define PICO_DHCPOPT_HOSTNAME                0x0c
#define PICO_DHCPOPT_DOMAINNAME              0x0f
#define PICO_DHCPOPT_MTU                     0x1a
#define PICO_DHCPOPT_BCAST                   0x1c
#define PICO_DHCPOPT_NETBIOSNS               0x2c
#define PICO_DHCPOPT_NETBIOSSCOPE            0x2f

#define PICO_DHCPOPT_REQIP                   0x32
#define PICO_DHCPOPT_LEASETIME               0x33
#define PICO_DHCPOPT_OPTIONOVERLOAD          0x34
#define PICO_DHCPOPT_MSGTYPE                 0x35
#define PICO_DHCPOPT_SERVERID                0x36
#define PICO_DHCPOPT_PARMLIST                0x37
#define PICO_DHCPOPT_MAXMSGSIZE              0x39
#define PICO_DHCPOPT_RENEWALTIME             0x3a
#define PICO_DHCPOPT_REBINDINGTIME           0x3b
#define PICO_DHCPOPT_DOMAINSEARCH            0x77
#define PICO_DHCPOPT_STATICROUTE             0x79
#define PICO_DHCPOPT_END                     0xFF

/* DHCP MESSAGE TYPE */
#define PICO_DHCP_MSG_DISCOVER               1
#define PICO_DHCP_MSG_OFFER                  2
#define PICO_DHCP_MSG_REQUEST                3
#define PICO_DHCP_MSG_DECLINE                4
#define PICO_DHCP_MSG_ACK                    5
#define PICO_DHCP_MSG_NAK                    6
#define PICO_DHCP_MSG_RELEASE                7
#define PICO_DHCP_MSG_INFORM                 8


enum dhcp_negotiation_state {
        DHCPSTATE_DISCOVER = 0,
        DHCPSTATE_OFFER,
        DHCPSTATE_REQUEST,
        DHCPSTATE_BOUND,
        DHCPSTATE_RENEWING
};


struct __attribute__((packed)) pico_dhcphdr
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
	char    hostname[64];
	char    bootp_filename[128];
	uint32_t dhcp_magic;
	uint8_t options[0];
};


//common functions for client and server

uint8_t dhcp_get_next_option(uint8_t *begin, uint8_t *data, int *len, uint8_t **nextopt);
int is_options_valid(uint8_t *opt_buffer, int len); 
#endif
#endif
