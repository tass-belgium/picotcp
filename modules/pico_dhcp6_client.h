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
#define ALL_DHCP_SERVERS 					"ff05::1:3"
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

/* PICO_DHCP6_OPT_AUTH */
#define PICO_DHCP6_OPT_AUTH_DELAYED_AUTH_PROT 2
#define PICO_DHCP6_OPT_AUTH_RECONF_KEY_AUTH_PROT 3 /* TODO: + some other fields */

/* OPT_RECONF_MSG TYPE */
#define PICO_DHCP6_OPT_RECONF_MSG_RENEW 5
#define PICO_DHCP6_OPT_RECONF_MSG_INFO_REQ 11

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

/* Transmission and Retransmission Parameters (times in seconds) */
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

/* Representation of time values and "Infinity" as a time value */
#define PICO_DHCP_TIME_INFINITY 0xffffffff

/* DHCP6 DUID types */
#define PICO_DHCP6_DUID_LLT            1
#define PICO_DHCP6_DUID_EN             2
#define PICO_DHCP6_DUID_LL             3

#define PICO_DHCP6_TRANSACTION_ID_SIZE 3
#define PICO_DHCP6_HW_TYPE_ETHERNET    1

/* Status codes */
#define PICO_DHCP6_SUCCESS             0
#define PICO_DHCP6_UNSPEC_FAIL         1
#define PICO_DHCP6_NO_ADDRS_AVAIL      2
#define PICO_DHCP6_NO_BINDING          3
#define PICO_DHCP6_NOT_ON_LINK         4
#define PICO_DHCP6_USE_MULTICAST       5

enum dhcp6_client_state {
    DHCP6_CLIENT_STATE_SOLICITING = 0,
    DHCP6_CLIENT_STATE_REQUESTING,
	DHCP6_CLIENT_STATE_CONFIRMING,
    DHCP6_CLIENT_STATE_BOUND,
    DHCP6_CLIENT_STATE_RENEWING,
	DHCP6_CLIENT_STATE_REBINDING,
	DHCP6_CLIENT_STATE_RELEASING,
	DHCP6_CLIENT_STATE_DECLINING,
	DHCP6_CLIENT_STATE_INFO_REQUESTING,
	DHCP6_CLIENT_STATE_RECONFIGURING,
};

/* Client/Server Message Formats */
PACKED_STRUCT_DEF pico_dhcp6_hdr {
    uint8_t type;
    uint8_t transaction_id[3];
    uint8_t options[0]; /* variable length */
};


/* Macro to get DHCP6 option field */
#define DHCP6_OPT(hdr,off)              ((struct pico_dhcp6_opt *)(((uint8_t *)hdr)+sizeof(struct pico_dhcp6_hdr) + off)) /* TODO: check this */

/* Macro to get transaction_id out of pico_dhcp6_hdr */
#define DHCP6_TRANSACTION_ID(hdr)		(uint8_t *) (((uint8_t *)hdr)+1) /* 1 for pico_dhcp6_hdr.type */


/* Relay Agent/Server Message Formats */
/* TODO -- section 7 */

/* DUID Generic format */
PACKED_STRUCT_DEF pico_dhcp6_duid_generic {
    uint16_t type;
    uint8_t opt_spec_data[0];
};

/* DUID Based on Link-layer Address Plus Time [DUID-LLT] */
PACKED_STRUCT_DEF pico_dhcp6_duid_llt {
    uint16_t type; /* PICO_DHCP6_DUID_LLT */
    uint16_t hw_type;
    uint32_t time;
    uint8_t link_layer_address[0];
};

/* DUID Assigned by Vendor Based on Enterprise Number [DUID-EN] */
PACKED_STRUCT_DEF pico_dhcp6_duid_en {
    uint16_t type; /* PICO_DHCP6_DUID_EN */
    uint32_t enterprise_number;
    uint8_t identifier[0];
};

/* DUID Based on Link-layer Address */
PACKED_STRUCT_DEF pico_dhcp6_duid_ll {
    uint16_t type; /* PICO_DHCP6_DUID_LL */
    uint16_t hw_type; /* Hardware type by IANA. */
    uint8_t link_layer_address[0];
//    PACKED_UNION_DEF dhcp6_opt_hw_addr_u {
//        struct pico_eth mac;
//    } link_layer_address;
};


/* Generic option type */
PACKED_STRUCT_DEF pico_dhcp6_opt {
    uint16_t option_code;
    uint16_t option_len;
    /*uint8_t option_data[0];*/
};

/* Client Identifier Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_cid {
    /* PICO_DHCP6_OPT_CLIENTID */
    struct pico_dhcp6_opt base_opts;
//    uint8_t duid[0]; /* variable length */
    struct pico_dhcp6_duid_generic duid;
};

/* Server Identifier Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_sid {
    /* PICO_DHCP6_OPT_SERVERID */
    struct pico_dhcp6_opt base_opts;
//    uint8_t duid[0]; /* variable length */
    struct pico_dhcp6_duid_generic duid;
};

/* Identity Association for Non-Temporary Address Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_ia_na {
    /* PICO_DHCP6_OPT_IA_NA */
    struct pico_dhcp6_opt base_opts;
    uint32_t iaid;
    uint32_t t1; /* Time in seconds when client will contact server from whom address was obtained, recommended value: 0.5 x shortest preferred lifetime of the addresses in the IA that the
   server is willing to extend */
    uint32_t t2; /* Time in seconds when client will contact any server, recommended value: 0.8 x shortest preferred lifetime of the addresses in the IA that the
   server is willing to extend*/
    uint8_t options[0];
};

/* Identity Association for Temporary Addresses Option */
/* TODO? section 22.5 (IA_TA) */
PACKED_STRUCT_DEF pico_dhcp6_opt_ia_ta {
	/* PICO_DHCP6_OPT_IA_TA */
    struct pico_dhcp6_opt base_opts;
	uint32_t iaid;
	uint8_t options[0];
};

/* IA Address Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_ia_addr {
    /* OPTION_IAADDR */
    struct pico_dhcp6_opt base_opts;
    struct pico_ip6 addr;
    uint32_t preferred_lt;  /* Preferred lifetime for the IPv6 address in the option, in seconds */
    uint32_t valid_lt;      /* Valid lifetime for the IPv6 address in the option, in seconds */
    uint8_t options[0];
};

/* Option Request Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_oro {
    /* OPTION_ORO */
    struct pico_dhcp6_opt base_opts;
    uint16_t req_option_code_1;
    uint16_t req_option_code_2;
    uint8_t option_data[0];
};

/* Preference option */
PACKED_STRUCT_DEF pico_dhcp6_opt_pref {
    /* OPTION_PREFERENCE */
    struct pico_dhcp6_opt base_opts;
    uint8_t pref_value;
};

/* Elapsed time option */
PACKED_STRUCT_DEF pico_dhcp6_opt_elapsed_time {
    /* OPTION_ELAPSED_TIME */
    struct pico_dhcp6_opt base_opts;
    uint16_t elapsed_time; /* Expressed in hundredths of a second (10^-2 seconds) */
};

/* Relay message option */
PACKED_STRUCT_DEF pico_dhcp6_opt_relay_msg {
    /* OPTION_RELAY_MSG */
    struct pico_dhcp6_opt base_opts;
    uint8_t dhcp_relay_message[0];
};

/* Authentication option */
PACKED_STRUCT_DEF pico_dhcp6_opt_auth {
    /* OPTION_AUTH */
    struct pico_dhcp6_opt base_opts;
    uint8_t protocol;
    uint8_t algorithm;
    uint8_t rdm;
    uint64_t replay_detection;
    uint8_t auth_info[0];
};

/* Server unicast option */
PACKED_STRUCT_DEF pico_dhcp6_opt_unicast {
    /* OPTION_UNICAST */
    struct pico_dhcp6_opt base_opts;
    struct pico_ip6 server_address;
};

/* Status Code Option */
/* A Status Code option may appear in the options field of a DHCP
   message and/or in the options field of another option. */
PACKED_STRUCT_DEF pico_dhcp6_opt_status_code {
    /* OPTION_STATUS_CODE */
    struct pico_dhcp6_opt base_opts;
    uint16_t status_code;
    uint8_t status_message[0]; /* UTF-8 encoded text string, not NULL terminated */
};

/* Rapid Commit Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_rapid_commit {
    /* OPTION_RAPID_COMMIT */
    struct pico_dhcp6_opt base_opts;
};

/* User Class Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_user_class {
    /* OPTION_USER_CLASS */
    struct pico_dhcp6_opt base_opts;
    PACKED_STRUCT_DEF pico_dhcp6_user_class_data {
    	uint16_t user_class_len;
    	uint8_t opaque_data[0];
    } user_class_data[0]; /* The user class information carried in this option MUST be configurable on the client. */
};

/* Vendor Class Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_vendor_class {
	/* OPTION_VENDOR_CLASS  */
    struct pico_dhcp6_opt base_opts;
	uint32_t enterprise_number; /* registered Enterprise Number as registered with IANA */
    PACKED_STRUCT_DEF pico_dhcp6_vendor_class_data {
    	uint16_t vendor_class_len;
    	uint8_t opaque_data[0];
    } vendor_class_data[0];
};

/* Vendor-specific Information Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_vendor_opts {
    /* OPTION_VENDOR_OPTS */
    struct pico_dhcp6_opt base_opts;
	uint32_t enterprise_number; /* registered Enterprise Number as registered with IANA */
    PACKED_STRUCT_DEF pico_dhcp6_option_data_format {
    	uint16_t option_code;
    	uint16_t option_len;
    	uint16_t option_data[0];
    } option_data[0];
};

/* Interface-Id Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_interface_id {
	/* OPTION_INTERFACE_ID */
    struct pico_dhcp6_opt base_opts;
	uint8_t interface_id[0];
};

/* Reconfigure Message Option */
/* TODO: The Reconfigure Message option can only appear in a Reconfigure
   message. */
PACKED_STRUCT_DEF pico_dhcp6_opt_reconf_msg {
	/* OPTION_RECONF_MSG */
    struct pico_dhcp6_opt base_opts;
	uint8_t msg_type; /* 5 for Renew message, 11 for Information-request message. */
};

/* Reconfigure Accept Option */
PACKED_STRUCT_DEF pico_dhcp6_opt_reconf_accept {
	/* OPTION_RECONF_ACCEPT */
    struct pico_dhcp6_opt base_opts;
};


struct pico_dhcp6_client_cookie /* TODO: don't store entire message */
{
    struct pico_socket *sock;
    struct pico_device *dev;
    struct pico_ip6 msg_dst;		   /* Destination of messages: unicast or multicast addr */
    void (*cb)(void* cli, int code);   /* Callback to the user */
    struct pico_timer *rto_timer;
    enum dhcp6_client_state state;     /* State of State Machine */
    uint8_t transaction_id[3];
    uint8_t rtc;                       /* current retransmission count */
    uint8_t rto;                       /* current retransmission timeout */
//    struct pico_dhcp6_duid_generic *client_duid;    /* Client Identifier TODO: extend with other possibilities */
    struct pico_dhcp6_opt_cid *cid_client;    /* Client Identifier TODO: extend with other possibilities */
    struct pico_dhcp6_opt_cid *cid_rec;/* Client Identifier */
    struct pico_dhcp6_opt_sid *sid;    /* Server Identifier */
    struct pico_dhcp6_opt_ia_na *iana; /* Identity Association for Non-Temporary Address */ /* TODO: A DHCP message may contain multiple IA_NA options */
    struct pico_dhcp6_opt_ia_ta *ia_ta;
    struct pico_dhcp6_opt_iaddr *iaddr;
    struct pico_dhcp6_opt_oro *oro;
    struct pico_dhcp6_opt_pref *pref;
    struct pico_dhcp6_opt_elapsed_time *elapsed_time;
    struct pico_dhcp6_opt_status_code *status_code_field;
    struct pico_dhcp6_opt_relay_msg *relay_msg;
    struct pico_dhcp6_opt_auth *auth;
    uint8_t rapid_commit;
    struct pico_dhcp6_opt_user_class *user_class;
    struct pico_dhcp6_opt_vendor_class *vendor_class;
    struct pico_dhcp6_opt_vendor_opts *vendor_opts;
    struct pico_dhcp6_opt_interface_id *interface_id;
    uint8_t reconf_msg_type;
    uint8_t reconf_accept;
    uint8_t rapid_commit_option_enabled;
    struct pico_ip6 server_addr;
};

/* possible codes for the callback */
#define PICO_DHCP_SUCCESS (0)
#define PICO_DHCP_ERROR   (1)
#define PICO_DHCP_RESET   (2)

int pico_dhcp6_initiate_negotiation(struct pico_device *device, void (*callback)(void*cli, int code), uint32_t *xid);
void generate_transaction_id(void);
void process_status_code(struct pico_dhcp6_opt_status_code** status_code_field, size_t size);

#endif
#endif
