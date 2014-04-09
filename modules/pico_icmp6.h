/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

 *********************************************************************/
#ifndef _INCLUDE_PICO_ICMP6
#define _INCLUDE_PICO_ICMP6
#include "pico_addressing.h"
#include "pico_protocol.h"

/* ICMP header sizes */
#define PICO_ICMP6HDR_DRY_SIZE          4
#define PICO_ICMP6HDR_ECHO_REQUEST_SIZE 8
#define PICO_ICMP6HDR_DEST_UNREACH_SIZE 8
#define PICO_ICMP6HDR_TIME_XCEEDED_SIZE 8
#define PICO_ICMP6HDR_NEIGH_SOL_SIZE    24
#define PICO_ICMP6HDR_NEIGH_ADV_SIZE    24
#define PICO_ICMP6HDR_ROUTER_SOL_SIZE   8
#define PICO_ICMP6HDR_ROUTER_ADV_SIZE   16
#define PICO_ICMP6HDR_REDIRECT_SIZE     40

/* ICMP types */
#define PICO_ICMP6_DEST_UNREACH        1
#define PICO_ICMP6_PKT_TOO_BIG         2
#define PICO_ICMP6_TIME_EXCEEDED       3
#define PICO_ICMP6_PARAM_PROBLEM       4
#define PICO_ICMP6_ECHO_REQUEST        128
#define PICO_ICMP6_ECHO_REPLY          129
#define PICO_ICMP6_ROUTER_SOL          133
#define PICO_ICMP6_ROUTER_ADV          134
#define PICO_ICMP6_NEIGH_SOL           135
#define PICO_ICMP6_NEIGH_ADV           136
#define PICO_ICMP6_REDIRECT            137

/* destination unreachable codes */
#define PICO_ICMP6_UNREACH_NOROUTE     0
#define PICO_ICMP6_UNREACH_ADMIN       1
#define PICO_ICMP6_UNREACH_SRCSCOPE    2
#define PICO_ICMP6_UNREACH_ADDR        3
#define PICO_ICMP6_UNREACH_PORT        4
#define PICO_ICMP6_UNREACH_SRCFILTER   5
#define PICO_ICMP6_UNREACH_REJROUTE    6

/* time exceeded codes */
#define PICO_ICMP6_TIMXCEED_INTRANS    0
#define PICO_ICMP6_TIMXCEED_REASS      1

/* parameter problem codes */
#define PICO_ICMP6_PARAMPROB_HDRFIELD  0
#define PICO_ICMP6_PARAMPROB_NXTHDR    1
#define PICO_ICMP6_PARAMPROB_IPV6OPT   2

/* ping error codes */
#define PICO_PING6_ERR_REPLIED         0
#define PICO_PING6_ERR_TIMEOUT         1
#define PICO_PING6_ERR_UNREACH         2
#define PICO_PING6_ERR_PENDING         0xFFFF

/* custom defines */
#define PICO_ICMP6_ND_UNICAST          0
#define PICO_ICMP6_ND_ANYCAST          1
#define PICO_ICMP6_ND_SOLICITED        2
#define PICO_ICMP6_ND_DAD              3

#define PICO_ICMP6_MAX_RTR_SOL_DELAY   1000

#define PICO_SIZE_ICMP6HDR ((sizeof(struct pico_icmp6_hdr)))

extern struct pico_protocol pico_proto_icmp6;

PACKED_STRUCT_DEF pico_icmp6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t crc;

    PACKED_UNION_DEF icmp6_msg_u {
        /* error messages */
        PACKED_UNION_DEF icmp6_err_u {
            PEDANTIC_STRUCT_DEF  dest_unreach_s {
                uint32_t unused;
                uint8_t data[0];
            } dest_unreach;
            PEDANTIC_STRUCT_DEF  pkt_too_big_s {
                uint32_t mtu;
                uint8_t data[0];
            } pkt_too_big;
            PEDANTIC_STRUCT_DEF  time_exceeded_s {
                uint32_t unused;
                uint8_t data[0];
            } time_exceeded;
            PEDANTIC_STRUCT_DEF  param_problem_s {
                uint32_t ptr;
                uint8_t data[0];
            } param_problem;
        } err;

        /* informational messages */
        PACKED_UNION_DEF icmp6_info_u {
            PEDANTIC_STRUCT_DEF  echo_request_s {
                uint16_t id;
                uint16_t seq;
                uint8_t data[0];
            } echo_request;
            PEDANTIC_STRUCT_DEF  echo_reply_s {
                uint16_t id;
                uint16_t seq;
                uint8_t data[0];
            } echo_reply;
            PEDANTIC_STRUCT_DEF  router_sol_s {
                uint32_t unused;
                uint8_t options[0];
            } router_sol;
            PEDANTIC_STRUCT_DEF  router_adv_s {
                uint8_t hop;
                uint8_t mor;
                uint16_t life_time;
                uint32_t reachable_time;
                uint32_t retrans_time;
                uint8_t options[0];
            } router_adv;
            PEDANTIC_STRUCT_DEF  neigh_sol_s {
                uint32_t unused;
                struct pico_ip6 target;
                uint8_t options[0];
            } neigh_sol;
            PEDANTIC_STRUCT_DEF  neigh_adv_s {
                uint32_t rsor;
                struct pico_ip6 target;
                uint8_t options[0];
            } neigh_adv;
            PEDANTIC_STRUCT_DEF  redirect_s {
                uint32_t reserved;
                struct pico_ip6 target;
                struct pico_ip6 dest;
                uint8_t options[0];
            } redirect;
        } info;
    } msg;
};

PACKED_STRUCT_DEF pico_icmp6_opt_lladdr
{
    uint8_t type;
    uint8_t len;
    PACKED_UNION_DEF icmp6_opt_hw_addr_u {
        struct pico_eth mac;
    } addr;
};

PACKED_STRUCT_DEF pico_icmp6_opt_prefix
{
    uint8_t type;
    uint8_t len;
    uint8_t prefix_len;
    uint8_t res : 6;
    uint8_t aac : 1;
    uint8_t onlink : 1;
    uint32_t val_lifetime;
    uint32_t pref_lifetime;
    uint32_t reserved;
    struct pico_ip6 prefix;
};

PACKED_STRUCT_DEF pico_icmp6_opt_mtu
{
    uint8_t type;
    uint8_t len;
    uint16_t res;
    uint32_t mtu;
};

PACKED_STRUCT_DEF pico_icmp6_opt_redirect
{
    uint8_t type;
    uint8_t len;
    uint16_t res0;
    uint32_t res1;
    uint8_t data[0];
};

PACKED_STRUCT_DEF pico_icmp6_opt_na
{
    uint8_t type;
    uint8_t len;
    uint8_t options[0];
};

struct pico_icmp6_stats
{
    unsigned long size;
    unsigned long seq;
    pico_time time;
    unsigned long ttl;
    int err;
    struct pico_ip6 dst;
};

int pico_icmp6_ping(char *dst, int count, int interval, int timeout, int size, void (*cb)(struct pico_icmp6_stats *));

int pico_icmp6_neighbor_solicitation(struct pico_device *dev, struct pico_ip6 *dst, uint8_t type);
int pico_icmp6_neighbor_advertisement(struct pico_frame *f, struct pico_ip6 *target);
int pico_icmp6_router_solicitation(struct pico_device *dev, struct pico_ip6 *src);

int pico_icmp6_port_unreachable(struct pico_frame *f);
int pico_icmp6_proto_unreachable(struct pico_frame *f);
int pico_icmp6_dest_unreachable(struct pico_frame *f);
int pico_icmp6_ttl_expired(struct pico_frame *f);
int pico_icmp6_packet_filtered(struct pico_frame *f);

uint16_t pico_icmp6_checksum(struct pico_frame *f);

#endif
