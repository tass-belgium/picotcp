/*********************************************************************
   PicoTCP. Copyright (c) 2015 Altran. Some rights reserved.
   See LICENSE and COPYING for usage.

   Author: Sam Van Den Berge

 *********************************************************************/
#ifndef _INCLUDE_PICO_DHCP6_CLIENT
#define _INCLUDE_PICO_DHCP6_CLIENT
#include "pico_defines.h"
#if defined(PICO_SUPPORT_UDP) && defined(PICO_SUPPORT_IPV6)
#include "pico_addressing.h"
#include "pico_protocol.h"

/* DHCP6 Multicast Address */
#define ALL_DHCP_RELAY_AGENTS_AND_SERVERS   "ff02::1:2"
#define PICO_DHCP6_CLIENT_PORT         546
#define PICO_DHCP6_SERVER_PORT         547

/* DHCP6 Message types */
#define PICO_DHCP6_SOLICIT             1
#define PICO_DHCP6_ADVERTISE           2
#define PICO_DHCP6_REQUEST             3
#define PICO_DHCP6_CONFIRM             4
#define PICO_DHCP6_RENEW               5
#define PICO_DHCP6_REBIND              6
#define PICO_DHCP6_REPLY               7
#define PICO_DHCP6_RELEASE             8
#define PICO_DHCP6_DECLINE             9
#define PICO_DHCP6_RECONFIGURE         10
#define PICO_DHCP6_INFORMATION_REQUEST 11
#define PICO_DHCP6_RELAY_FORW          12
#define PICO_DHCP6_RELAY_REPL          13

/* DHCP6 Options */
#define PICO_DHCP6_OPT_CLIENTID        1
#define PICO_DHCP6_OPT_SERVERID        2 
#define PICO_DHCP6_OPT_IA_NA           3
#define PICO_DHCP6_OPT_IA_TA           4
#define PICO_DHCP6_OPT_IADDR           5
#define PICO_DHCP6_OPT_ORO             6
#define PICO_DHCP6_OPT_PREFERENCE      7
#define PICO_DHCP6_OPT_ELAPSED_TIME    8
#define PICO_DHCP6_OPT_RELAY_MSG       9
#define PICO_DHCP6_OPT_AUTH            11
#define PICO_DHCP6_OPT_UNICAST         12
#define PICO_DHCP6_OPT_STATUS_CODE     13
#define PICO_DHCP6_OPT_RAPID_COMMIT    14
#define PICO_DHCP6_OPT_USER_CLASS      15
#define PICO_DHCP6_OPT_VENDOR_CLASS    16
#define PICO_DHCP6_OPT_VENDOR_OPTS     17
#define PICO_DHCP6_OPT_INTERFACE_ID    18
#define PICO_DHCP6_OPT_RECONF_MSG      19
#define PICO_DHCP6_OPT_RECONF_ACCEPT   20

/* DHCP6 Options Sizes */
#define PICO_DHCP6_OPT_SIZE_CLIENTID        0
#define PICO_DHCP6_OPT_SIZE_SERVERID        0 
#define PICO_DHCP6_OPT_SIZE_IA_NA           12
#define PICO_DHCP6_OPT_SIZE_IA_TA           4
#define PICO_DHCP6_OPT_SIZE_IADDR           24
#define PICO_DHCP6_OPT_SIZE_ORO             0
#define PICO_DHCP6_OPT_SIZE_PREFERENCE      1
#define PICO_DHCP6_OPT_SIZE_ELAPSED_TIME    2
#define PICO_DHCP6_OPT_SIZE_RELAY_MSG       0
#define PICO_DHCP6_OPT_SIZE_AUTH            11
#define PICO_DHCP6_OPT_SIZE_UNICAST         16
#define PICO_DHCP6_OPT_SIZE_STATUS_CODE     2
#define PICO_DHCP6_OPT_SIZE_RAPID_COMMIT    0
#define PICO_DHCP6_OPT_SIZE_USER_CLASS      0
#define PICO_DHCP6_OPT_SIZE_VENDOR_CLASS    4
#define PICO_DHCP6_OPT_SIZE_VENDOR_OPTS     4
#define PICO_DHCP6_OPT_SIZE_INTERFACE_ID    0
#define PICO_DHCP6_OPT_SIZE_RECONF_MSG      1
#define PICO_DHCP6_OPT_SIZE_RECONF_ACCEPT   0

/* Transmission and Retransmission Parameters */
#define PICO_DHCP6_SOL_MAX_DELAY       1
#define PICO_DHCP6_SOL_TIMEOUT         1
#define PICO_DHCP6_SOL_MAX_RT          120
#define PICO_DHCP6_REQ_TIMEOUT         1
#define PICO_DHCP6_REQ_MAX_RT          30
#define PICO_DHCP6_REQ_MAX_RC          10
#define PICO_DHCP6_CNF_MAX_DELAY       1
#define PICO_DHCP6_CNF_TIMEOUT         1
#define PICO_DHCP6_CNF_MAX_RT          4
#define PICO_DHCP6_CNF_MAX_RD          10
#define PICO_DHCP6_REN_TIMEOUT         10
#define PICO_DHCP6_REN_MAX_RT          600
#define PICO_DHCP6_REB_TIMEOUT         10
#define PICO_DHCP6_REB_MAX_RT          600
#define PICO_DHCP6_INF_MAX_DELAY       1
#define PICO_DHCP6_INF_TIMEOUT         1
#define PICO_DHCP6_INF_MAX_RT          120
#define PICO_DHCP6_REL_TIMEOUT         1
#define PICO_DHCP6_REL_MAX_RC          5
#define PICO_DHCP6_DEC_TIMEOUT         1
#define PICO_DHCP6_DEC_MAX_RC          5
#define PICO_DHCP6_REC_TIMEOUT         2
#define PICO_DHCP6_REC_MAX_RC          8
#define PICO_DHCP6_HOP_COUNT_LIMIT     32

/* DHCP6 DUID types */
#define PICO_DHCP6_DUID_LLT            1
#define PICO_DHCP6_DUID_EN             2
#define PICO_DHCP6_DUID_LL             3

#define PICO_DHCP6_TRANSACTION_ID_SIZE 3
#define PICO_DHCP6_HW_TYPE_ETHERNET    1

#define PICO_DHCP6_SUCCESS             0
#define PICO_DHCP6_UNSPEC_FAIL         1
#define PICO_DHCP6_NO_ADDRS_AVAIL      2
#define PICO_DHCP6_NO_BINDING          3
#define PICO_DHCP6_NOT_ON_LINK         4
#define PICO_DHCP6_USE_MULTICAST       5

PACKED_STRUCT_DEF pico_dhcp6_hdr {
    uint8_t type;
    uint8_t transaction_id[3];
    uint8_t options[0];
};

/* Client Identifier Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_cid {
    uint16_t type; /* Client Identifier Option has type = 1 */
    uint16_t len;
    uint8_t duid[0];
};

/* Server Identifier Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_sid {
    uint16_t type;
    uint16_t len;
    uint8_t data[0];
};

PACKED_STRUCT_DEF pico_dhcp6_duid_ll {
    uint16_t type;
    uint16_t hw_type; /* Hardware type by IANA. */
    PACKED_UNION_DEF dhcp6_opt_hw_addr_u {
        struct pico_eth mac;
    } addr;
};

/* Generic option type */
PACKED_STRUCT_DEF pico_dhcp6_opt {
    uint16_t type;
    uint16_t len;
    uint8_t data[0];
};

/* Option Request Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_oro {
    uint16_t type;
    uint16_t len;
    uint8_t data[0];
};

PACKED_STRUCT_DEF pico_dhcp6_opt_elapsed_time {
    uint16_t type;
    uint16_t len;
    uint16_t elapsed_time; /* Expressed in hundredths of a second (10^-2 seconds) */
};

/* Identity Association for Non-Temporary Address Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_ia_na {
    uint16_t type;
    uint16_t len;
    uint32_t iaid;
    uint32_t t1; /* Time in seconds when client will contact server from whom address was obtained */
    uint32_t t2; /* Time in seconds when client will contact any server */
    uint8_t options[0];
};

PACKED_STRUCT_DEF pico_dhcp6_opt_ia_addr {
    uint16_t type;
    uint16_t len;
    struct pico_ip6 addr;
    uint32_t preferred_lt;  /* Preferred lifetime for the IPv6 address in the option, in seconds*/
    uint32_t valid_lt;      /* Valid lifetime for the IPv6 address in the option, in seconds */
    uint8_t options[0];
};

struct pico_dhcp6_client_cookie
{
    struct pico_socket *sock;
    struct pico_device *dev;
    struct pico_dhcp6_opt_cid *cid;    /* Client Identifier */
    struct pico_dhcp6_opt_sid *sid;    /* Server Identifier */
    struct pico_dhcp6_opt_ia_na *iana; /* Identity Association for Non-Temporary Address */
    void (*cb)(void* cli, int code);   /* Callback to the user */
    struct pico_timer *rto_timer;
    uint8_t state;                     /* State of State Machine */
    uint8_t transaction_id[3];
    uint8_t rtc;                       /* current retransmission count */
    uint8_t rto;                       /* current retransmission timeout */
};

/* possible codes for the callback */
#define PICO_DHCP_SUCCESS 0
#define PICO_DHCP_ERROR   1
#define PICO_DHCP_RESET   2

int pico_dhcp6_initiate_negotiation(struct pico_device *device, void (*callback)(void*cli, int code), uint32_t *xid);

#endif
#endif
