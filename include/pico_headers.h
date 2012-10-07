/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */

#ifndef __PICO_HEADER_H
#define __PICO_HEADER_H
#include <stdint.h>


/* Include this if supported by your C library. */
#include <endian.h>


#if __BYTE_ORDER == __BIG_ENDIAN
# define to_be16(x) (x)
# define from_be16(x) (x)
# define to_be32(x) (x)
# define from_be32(x) (x)
#else
  static inline uint16_t to_be16(uint16_t x) {
    uint8_t *c = (uint8_t *)(&x);
    uint16_t res = (c[0] << 8) + c[1];
    return res;
  }

# define from_be16(x) (to_be16(x))
  static inline uint32_t to_be32(uint32_t x) {
    uint8_t *c = (uint8_t *)(&x);
    uint32_t res = (c[0] << 24) + (c[1] << 16) + (c[2] << 8) + c[3];
    return res;
  }
# define from_be32(x) (to_be32(x))
#endif
uint16_t net_checksum(void *inbuf, int len);


/* Macaddr, Frame */
#define PTYPE_IP 0x0800U
#define PTYPE_ARP 0x0806U
struct __attribute__((__packed__)) pico_MACaddr {
  uint8_t B[6];
};

struct __attribute__((__packed__)) pico_ethhdr {
  struct pico_MACaddr dst;
  struct pico_MACaddr src;
  uint16_t proto;
  uint8_t content[0];
};

union pico_IP4addr {
  uint32_t  s_addr;
  uint8_t   octet[4];
};

struct pico_IP6addr {
  uint8_t octet[16];
};

/* IPaddr, packet */
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
struct __attribute__((__packed__)) pico_ip4hdr {
  uint8_t  iv;
  uint8_t   tos;
  uint16_t  len;
  uint16_t  id;
  uint16_t  frag_offset;
  uint8_t   ttl;
  uint8_t   proto;
  uint16_t  crc;
  struct    pico_IP4addr  src;
  struct    pico_IP4addr  dst;
  uint8_t   payload[0];
};

struct __attribute__((__packed__)) pico_ip6hdr {
  uint32_t  version:4;
  uint32_t  tc:8;
  uint32_t  flow:20;
  uint16_t  len;
  uint8_t   nexth;
  uint8_t   hop;
  struct    pico_IP6addr  src;
  struct    pico_IP6addr  dst;
};


/* Arp */
#define ARP_REQUEST 1
#define ARP_REPLY 2

#define ETHERNET_ADDRESS_SIZE 6
#define IP_ADDRESS_SIZE 4

#define ETH_BCAST (unsigned char *)"\xFF\xFF\xFF\xFF\xFF\xFF" 
#define HTYPE_ETH 1

struct
__attribute__ ((__packed__)) 
pico_arphdr
{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hsize;
	uint8_t	psize;
	uint16_t opcode;
	uint8_t s_mac[6];
	uint32_t s_addr;
	uint8_t d_mac[6];
	uint32_t d_addr;
};

/* UDP header, Datagram rfc 768 */
struct __attribute__((packed)) pico_udphdr {
	uint16_t sport, dport, len, crc;
};

/* ICMP header, message */
#define ICMP_ECHO_REPLY		  0
#define ICMP_DEST_UNREACH	  3
#define ICMP_SQUENCH	      4
#define ICMP_REDIRECT		    5
#define ICMP_ECHO_REQ       8
#define ICMP_TIME_EXCEEDED	11
#define ICMP_PARAMETERPROB	12
#define ICMP_TIMESTAMP		  13
#define ICMP_TIMESTAMPREPLY	14
#define ICMP_INFO_REQUEST	  15
#define ICMP_INFO_REPLY		  16
#define ICMP_ADDRESS		    17
#define ICMP_ADDRESSREPLY	  18
#define NR_ICMP_TYPES		    18



#define ICMP_NET_UNREACH	    0
#define ICMP_HOST_UNREACH	    1
#define ICMP_PROT_UNREACH	    2
#define ICMP_PORT_UNREACH	    3
#define ICMP_FRAG_NEEDED	    4
#define ICMP_SR_FAILED		    5
#define ICMP_NET_UNKNOWN	    6
#define ICMP_HOST_UNKNOWN	    7
#define ICMP_HOST_ISOLATED	  8
#define ICMP_NET_ANO		      9
#define ICMP_HOST_ANO		      10
#define ICMP_NET_UNR_TOS	    11
#define ICMP_HOST_UNR_TOS	    12
#define ICMP_PKT_FILTERED	    13
#define ICMP_PREC_VIOLATION	  14
#define ICMP_PREC_CUTOFF	    15


#define ICMP_REDIRECT_NET		  0
#define ICMP_REDIRECT_HOST		1
#define ICMP_REDIRECT_NETTOS	2
#define ICMP_REDIRECT_HOSTTOS	3


#define ICMP_EXCEEDED_TTL		    0
#define ICMP_EXCEEDED_FRAGTIME	1


struct __attribute__((__packed__)) pico_icmphdr {
  uint8_t		type;
  uint8_t		code;
  uint16_t	checksum;
  union __icmp_content {
	    struct {
		    __be16	id;
		    __be16	sequence;
	    } echo;
	    uint32_t	gw;
	    struct {
		    uint16_t	zero;
		    uint16_t  mtu;
	    } frag;
  } content;
};

/* XXX define : TCP Options  */

struct __attribute__((__packed__)) pico_tcpopt
{
  uint8_t kind;
  uint8_t len;
  uint8_t content[0];
};

/* XXX define : TCP Flags  */
struct __attribute__((__packed__)) pico_tcphdr
{
  uint16_t  sport;
  uint16_t  dport;
  uint32_t  seq;
  uint32_t  ack;
  uint8_t   offset;
  uint8_t   flags;
  uint16_t  rwnd;
  uint16_t  crc;
  uint16_t  urg;
  pico_tcpopt options[0];
};









#if REMOVE_ME
#define ethhead(vb) ((struct vde_ethernet_header *)(vb->data))
#define is_arp(vb) ( ((ethhead(vb))->buftype) == PTYPE_ARP )
#define is_ip(vb) ( ((ethhead(vb))->buftype) == PTYPE_IP )
#define is_bcast(vb) ( strncmp((ethhead(vb))->dst, ETH_BCAST) == 0)
#define check_destination(vb,mac) ( strncmp((ethhead(vb))->dst, mac) == 0)

#define iphead(vb) ((struct iphdr *)(vb->data + 14))
#define udp_pseudohead(vb) ((uint8_t *)(vb->data + 14 + sizeof(struct iphdr) - (2 * sizeof(uint32_t))))
#define footprint(vb) ((uint8_t *)(vb->data + 14))
#define arphead(vb) ((struct vde_arp_header *)(vb->data + 14))
#define payload(vb) ((uint8_t *)(vb->data + 14 + sizeof(struct iphdr)))
#endif

#endif
