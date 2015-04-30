/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera, Maxime Vincent
 *********************************************************************/


#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pico_device.h"
#include "pico_dev_ppp.h"
#include "pico_stack.h"
#include "pico_md5.h"
#include "pico_dns_client.h"

/* We should define this in a global header. */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PICO_PPP_MRU 1514
#define PICO_PPP_MTU 1500
#define PPP_MAXPKT 2048
#define PPP_MAX_APN 134
#define PPP_MAX_USERNAME 134
#define PPP_MAX_PASSWORD 134
#define PPP_HDR_SIZE 3
#define PPP_PROTO_SLOT_SIZE 2
#define PPP_FCS_SIZE 2
#define PPP_PROTO_LCP short_be(0xc021)
#define PPP_PROTO_IP  short_be(0x0021)
#define PPP_PROTO_PAP short_be(0xc023)
#define PPP_PROTO_CHAP short_be(0xc223)
#define PPP_PROTO_IPCP short_be(0x8021)

#define PICO_CONF_REQ 1
#define PICO_CONF_ACK 2
#define PICO_CONF_NAK 3
#define PICO_CONF_REJ 4

#define LCPOPT_MRU 1
#define LCPOPT_AUTH 3
#define LCPOPT_QUALITY 4
#define LCPOPT_MAGIC 5
#define LCPOPT_PROTO_COMP 7
#define LCPOPT_ADDRCTL_COMP 8

#define CHAP_MD5_SIZE   16
#define CHAP_CHALLENGE  1
#define CHAP_RESPONSE   2
#define CHAP_SUCCESS    3
#define CHAP_FAILURE    4
#define CHALLENGE_SIZE(ppp, ch) (1 + strlen(ppp->password)+ short_be((ch)->len))

#define IPCP_ADDR_LEN 6
#define IPCP_VJ_LEN 6
#define IPCP_OPT_IP 0x03
#define IPCP_OPT_VJ 0x02
#define IPCP_OPT_DNS1 0x81
#define IPCP_OPT_NBNS1 0x82
#define IPCP_OPT_DNS2 0x83
#define IPCP_OPT_NBNS2 0x84

static uint8_t LCPOPT_LEN[9] = { 0, 4, 0, 4, 4, 6, 2, 2, 2 };

/* Protocol defines */
static const unsigned char  AT_S3          = 0x0du;
static const unsigned char  AT_S4          = 0x0au;
static const unsigned char  PPPF_FLAG_SEQ  = 0x7eu;
static const unsigned char  PPPF_CTRL_ESC  = 0x7du;
static const unsigned char  PPPF_ADDR      = 0xffu;
static const unsigned char  PPPF_CTRL      = 0x03u;
static const unsigned char  PPP_PROTO_IP_C = 0x21u;

static int ppp_devnum = 0;
static uint8_t ppp_recv_buf[PPP_MAXPKT];

PACKED_STRUCT_DEF pico_lcp_hdr {
   uint8_t code;
   uint8_t id;
   uint16_t len;
};

PACKED_STRUCT_DEF pico_chap_hdr {
   uint8_t code;
   uint8_t id;
   uint16_t len;
};

PACKED_STRUCT_DEF pico_ipcp_hdr {
   uint8_t code;
   uint8_t id;
   uint16_t len;
};

#ifdef DEBUG_PPP
static int fifo_fd = -1; 
#endif

enum ppp_modem_state {
    PPP_MODEM_STATE_INITIAL = 0,
    PPP_MODEM_STATE_RESET,
    PPP_MODEM_STATE_ECHO,
    PPP_MODEM_STATE_CREG,
    PPP_MODEM_STATE_CGREG,
    PPP_MODEM_STATE_CGDCONT,
    PPP_MODEM_STATE_CGATT,
    PPP_MODEM_STATE_DIAL,
    PPP_MODEM_STATE_CONNECTED,
    PPP_MODEM_STATE_MAX
};

enum ppp_modem_event {
    PPP_MODEM_EVENT_START = 0,
    PPP_MODEM_EVENT_STOP,
    PPP_MODEM_EVENT_OK,
    PPP_MODEM_EVENT_CONNECT,
    PPP_MODEM_EVENT_MAX
};

enum ppp_lcp_state {
    PPP_LCP_STATE_INITIAL = 0,
    PPP_LCP_STATE_STARTING,
    PPP_LCP_STATE_CLOSED,
    PPP_LCP_STATE_STOPPED,
    PPP_LCP_STATE_CLOSING,
    PPP_LCP_STATE_STOPPING,
    PPP_LCP_STATE_REQ_SENT,
    PPP_LCP_STATE_ACK_RCVD,
    PPP_LCP_STATE_ACK_SENT,
    PPP_LCP_STATE_OPENED,
    PPP_LCP_STATE_MAX
};

enum ppp_lcp_event {
    PPP_LCP_EVENT_UP = 0,
    PPP_LCP_EVENT_DOWN,
    PPP_LCP_EVENT_OPEN,
    PPP_LCP_EVENT_CLOSE,
    PPP_LCP_EVENT_TO_POS,
    PPP_LCP_EVENT_TO_NEG,
    PPP_LCP_EVENT_RCR_POS,
    PPP_LCP_EVENT_RCR_NEG,
    PPP_LCP_EVENT_RCA,
    PPP_LCP_EVENT_RCN,
    PPP_LCP_EVENT_RTR,
    PPP_LCP_EVENT_RTA,
    PPP_LCP_EVENT_RUC,
    PPP_LCP_EVENT_RXJ_POS,
    PPP_LCP_EVENT_RXJ_NEG,
    PPP_LCP_EVENT_RXR,
    PPP_LCP_EVENT_MAX
};

enum ppp_auth_state {
    PPP_AUTH_STATE_INITIAL = 0,
    PPP_AUTH_STATE_STARTING,
    PPP_AUTH_STATE_RSP_SENT,
    PPP_AUTH_STATE_REQ_SENT,
    PPP_AUTH_STATE_AUTHENTICATED,
    PPP_AUTH_STATE_MAX
};

enum ppp_auth_event {
    PPP_AUTH_EVENT_UP_NONE = 0,
    PPP_AUTH_EVENT_UP_PAP,
    PPP_AUTH_EVENT_UP_CHAP,
    PPP_AUTH_EVENT_DOWN,
    PPP_AUTH_EVENT_RAC,
    PPP_AUTH_EVENT_RAA,
    PPP_AUTH_EVENT_RAN,
    PPP_AUTH_EVENT_MAX
};

enum ppp_ipcp_state {
    PPP_IPCP_STATE_INITIAL = 0,
    PPP_IPCP_STATE_REQ_SENT,
    PPP_IPCP_STATE_ACK_RCVD,
    PPP_IPCP_STATE_ACK_SENT,
    PPP_IPCP_STATE_OPENED,
    PPP_IPCP_STATE_MAX
};

enum ppp_ipcp_event {
    PPP_IPCP_EVENT_UP = 0,
    PPP_IPCP_EVENT_DOWN,
    PPP_IPCP_EVENT_RCR_POS,
    PPP_IPCP_EVENT_RCR_NEG,
    PPP_IPCP_EVENT_RCA,
    PPP_IPCP_EVENT_RCN,
    PPP_IPCP_EVENT_MAX
};

enum pico_ppp_state {
    PPP_MODEM_RST = 0,
    PPP_MODEM_CREG,
    PPP_MODEM_CGREG,
    PPP_MODEM_CGDCONT,
    PPP_MODEM_CGATT,
    PPP_MODEM_CONNECT,
    /* From here on, PPP states */
    PPP_ESTABLISH,
    PPP_AUTH,
    PPP_NETCONFIG,
    PPP_NETWORK,
    PPP_TERMINATE,
    /* MAXSTATE is the last one */
    PPP_MODEM_MAXSTATE
};

struct pico_device_ppp {
    struct pico_device dev;
    int statistics_frames_out;
    enum ppp_modem_state modem_state;
    enum ppp_lcp_state lcp_state;
    enum ppp_auth_state auth_state;
    enum ppp_ipcp_state ipcp_state;
    enum pico_ppp_state state;
    uint8_t frame_id;
    char apn[PPP_MAX_APN];
    char password[PPP_MAX_PASSWORD];
    char username[PPP_MAX_USERNAME];
    uint16_t lcpopt_local;
    uint16_t lcpopt_peer;
    uint8_t *pkt;
    size_t len;
    uint16_t rej;
    uint16_t auth;
    int (*serial_recv)(struct pico_device *dev, void *buf, int len);
    int (*serial_send)(struct pico_device *dev, const void *buf, int len);
    int (*serial_set_speed)(struct pico_device *dev, uint32_t speed);
    uint32_t ipcp_ip;
    uint32_t ipcp_dns1;
    uint32_t ipcp_nbns1;
    uint32_t ipcp_dns2;
    uint32_t ipcp_nbns2;
};

struct pico_ppp_fsm {
    int next_state;
    void (*event_handler)(struct pico_device_ppp *);
};

#define LCPOPT_SET_LOCAL(ppp, opt) ppp->lcpopt_local |= (1 << opt)
#define LCPOPT_SET_PEER(ppp, opt) ppp->lcpopt_peer |= (1 << opt)
#define LCPOPT_UNSET_LOCAL(ppp, opt) ppp->lcpopt_local &= ~(1 << opt)
#define LCPOPT_UNSET_PEER(ppp, opt) ppp->lcpopt_peer &= ~(1 << opt)
#define LCPOPT_ISSET_LOCAL(ppp, opt) ((ppp->lcpopt_local & (1 << opt)) != 0)
#define LCPOPT_ISSET_PEER(ppp, opt) ((ppp->lcpopt_peer & (1 << opt)) != 0)

static void evaluate_modem_state(struct pico_device_ppp *ppp, enum ppp_modem_event event);
static void evaluate_lcp_state(struct pico_device_ppp *ppp, enum ppp_lcp_event event);
static void evaluate_auth_state(struct pico_device_ppp *ppp, enum ppp_auth_event event);
static void evaluate_ipcp_state(struct pico_device_ppp *ppp, enum ppp_ipcp_event event);


static int ppp_ctl_packet_size(struct pico_device_ppp *ppp, uint16_t proto, int *size)
{
    int prefix = 0;
    prefix += PPP_HDR_SIZE; /* 7e ff 03 ... */
    prefix += PPP_PROTO_SLOT_SIZE;
    *size  += prefix;
    *size  += PPP_FCS_SIZE;
    (*size)++; /* STOP byte 0x7e */
    return prefix;
}

/* CRC16 / FCS Calculation */
static uint16_t ppp_fcs_char(uint16_t old_crc, uint8_t data)
{
    uint16_t word = (old_crc ^ data) & 0xFF;
    word ^= (word << 4) & 0xFF;
    word = (word << 8) ^ (word << 3) ^ (word >> 4);
    return ((old_crc >> 8) ^ word);
}

static uint16_t ppp_fcs_continue(uint16_t fcs, uint8_t *buf, int len)
{
    uint8_t * pos = buf;
    for (pos = buf; pos < buf + len; pos++)
    {
        fcs = ppp_fcs_char(fcs, *pos);
    }
    return fcs;
}

static uint16_t ppp_fcs_finish(uint16_t fcs)
{
    return fcs ^ 0xFFFF;
}

static uint16_t ppp_fcs_start(uint8_t *buf, int len)
{
    uint8_t * pos = buf;
    uint16_t fcs = 0xFFFF;
    return ppp_fcs_continue(fcs, buf, len);
}

static int ppp_fcs_verify(uint8_t *buf, int len)
{
    uint16_t fcs = ppp_fcs_start(buf, len - 2);
    fcs = ppp_fcs_finish(fcs);
    if ( (((fcs & 0xFF00) >> 8) != buf[len -1]) || ((fcs & 0xFF) != buf[len -2]) ) {
        return -1;
    }
    return 0;
}

/* Serial send (DTE->DCE) functions */
static int pico_ppp_ctl_send(struct pico_device *dev, uint16_t code, uint8_t *pkt, int len, int prefix)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *) dev;
    uint16_t fcs;
    uint8_t *ptr = pkt;
    int i = 0;

    if (!ppp->serial_send)
        return len;
    
    /* PPP Header */
    ptr[i++] = PPPF_FLAG_SEQ;
    ptr[i++] = PPPF_ADDR;
    ptr[i++] = PPPF_CTRL;
    /* protocol */
    ptr[i++] = (code & 0xFF);
    ptr[i++] = ((code & 0xFF00) >> 8);

    /* payload is already in place. Calculate FCS. */
    fcs = ppp_fcs_start(pkt + 1, len - 4); /* FCS excludes: start (1), FCS(2), stop(1), total 4 bytes */
    fcs = ppp_fcs_finish(fcs);
    pkt[len - 3] = fcs & 0xFF;
    pkt[len - 2] = ((fcs & 0xFF00) >> 8);
    pkt[len - 1] = PPPF_FLAG_SEQ;

    ppp->serial_send(&ppp->dev, pkt, len);
    return len;
}

static uint8_t pico_ppp_data_buffer[PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + PICO_PPP_MTU + PPP_FCS_SIZE + 1];
static int pico_ppp_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *) dev;
    uint16_t fcs = 0;
    int fcs_start;
    int i = 0;
    if (ppp->ipcp_state != PPP_IPCP_STATE_OPENED)
        return len;

    if (!ppp->serial_send)
        return len;

    pico_ppp_data_buffer[i++] = PPPF_FLAG_SEQ;
    if (!LCPOPT_ISSET_PEER(ppp, LCPOPT_ADDRCTL_COMP)) 
    {
            pico_ppp_data_buffer[i++] = PPPF_ADDR;
            pico_ppp_data_buffer[i++] = PPPF_CTRL;
    }
    fcs_start = i;

    if (!LCPOPT_ISSET_PEER(ppp, LCPOPT_PROTO_COMP)) 
    {
        pico_ppp_data_buffer[i++] = 0x00;
    }

    pico_ppp_data_buffer[i++] = 0x21;
    memcpy(pico_ppp_data_buffer + i, buf, len);
    i += len;
    fcs = ppp_fcs_start(pico_ppp_data_buffer + fcs_start, i - fcs_start);
    fcs = ppp_fcs_finish(fcs);
    pico_ppp_data_buffer[i++] = fcs & 0xFF;
    pico_ppp_data_buffer[i++] = (fcs & 0xFF00) >> 8;
    pico_ppp_data_buffer[i++] = PPPF_FLAG_SEQ;
    ppp->serial_send(&ppp->dev, pico_ppp_data_buffer, i);
    return len;
}


/* FSM functions */

#define PPP_AT_CREG0 "ATZ\r\n"
static void ppp_modem_send_reset(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CREG0, strlen(PPP_AT_CREG0));
}

#define PPP_AT_CREG1 "ATE0\r\n"
static void ppp_modem_send_echo(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CREG1, strlen(PPP_AT_CREG1));
}

#define PPP_AT_CREG2 "AT+CREG=1\r\n"
static void ppp_modem_send_creg(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CREG2, strlen(PPP_AT_CREG2));
}

#define PPP_AT_CREG3 "AT+CREG?\r\n"
static void ppp_modem_send_creg_q(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CREG3, strlen(PPP_AT_CREG3));
}

#define PPP_AT_CGREG "AT+CGREG=1\r\n"
static void ppp_modem_send_cgreg(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CGREG, strlen(PPP_AT_CGREG));
}

#define PPP_AT_CGREG_Q "AT+CGREG?\r\n"
static void ppp_modem_send_cgreg_q(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CGREG_Q, strlen(PPP_AT_CGREG_Q));
}

#define PPP_AT_CGDCONT "AT+CGDCONT=1,\"IP\",\"%s\",,,\r\n"
static void ppp_modem_send_cgdcont(struct pico_device_ppp *ppp)
{
    char at_cgdcont[200];

    if (!ppp->serial_send)
        return;

    snprintf(at_cgdcont, 200, PPP_AT_CGDCONT, ppp->apn);
    ppp->serial_send(&ppp->dev, at_cgdcont, strlen(at_cgdcont));
}

#define PPP_AT_CGDCONT_Q "AT+CGDCONT?\r\n"
static void ppp_modem_send_cgdcont_q(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CGDCONT_Q, strlen(PPP_AT_CGDCONT_Q));
}

#define PPP_AT_CGATT "AT+CGATT=1\r\n"
static void ppp_modem_send_cgatt(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CGATT, strlen(PPP_AT_CGATT));
}

#define PPP_AT_CGATT_Q "AT+CGATT?\r\n"
static void ppp_modem_send_cgatt_q(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_CGATT_Q, strlen(PPP_AT_CGATT_Q));
}

#define PPP_AT_DIALIN "ATD*99#\r\n"
static void ppp_modem_send_dial(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;

    ppp->serial_send(&ppp->dev, PPP_AT_DIALIN, strlen(PPP_AT_DIALIN));
}

static void ppp_modem_connected(struct pico_device_ppp *ppp)
{
    dbg("PPP: Modem connected to peer.\n");

    evaluate_lcp_state(ppp, PPP_LCP_EVENT_UP);
}

static void ppp_modem_disconnected(struct pico_device_ppp *ppp)
{
    dbg("PPP: Modem disconnected from peer.\n");

    evaluate_lcp_state(ppp, PPP_LCP_EVENT_DOWN);
}

static const struct pico_ppp_fsm ppp_modem_fsm[PPP_MODEM_STATE_MAX][PPP_MODEM_EVENT_MAX] = {
    [PPP_MODEM_STATE_INITIAL] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_RESET, ppp_modem_send_reset },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_INITIAL, NULL }
    },
    [PPP_MODEM_STATE_RESET] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_RESET, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_ECHO, ppp_modem_send_echo },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_RESET, NULL }
    },
    [PPP_MODEM_STATE_ECHO] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_ECHO, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_CREG, ppp_modem_send_creg },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_ECHO, NULL }
    },
    [PPP_MODEM_STATE_CREG] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_CREG, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_CGREG, ppp_modem_send_cgreg },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_CREG, NULL }
    },
    [PPP_MODEM_STATE_CGREG] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_CGREG, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_CGDCONT, ppp_modem_send_cgdcont },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_CGREG, NULL }
    },
    [PPP_MODEM_STATE_CGDCONT] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_CGDCONT, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_CGATT, ppp_modem_send_cgatt },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_CGDCONT, NULL }
    },
    [PPP_MODEM_STATE_CGATT] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_CGATT, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_DIAL, ppp_modem_send_dial },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_CGATT, NULL }
    },
    [PPP_MODEM_STATE_DIAL] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_DIAL, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, NULL },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_DIAL, NULL },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_CONNECTED, ppp_modem_connected }
    },
    [PPP_MODEM_STATE_CONNECTED] = {
            [PPP_MODEM_EVENT_START]   = { PPP_MODEM_STATE_CONNECTED, NULL },
            [PPP_MODEM_EVENT_STOP]    = { PPP_MODEM_STATE_INITIAL, ppp_modem_disconnected },
            [PPP_MODEM_EVENT_OK]      = { PPP_MODEM_STATE_CONNECTED, NULL },
            [PPP_MODEM_EVENT_CONNECT] = { PPP_MODEM_STATE_CONNECTED, NULL }
    }
};

static void evaluate_modem_state(struct pico_device_ppp *ppp, enum ppp_modem_event event)
{
    const struct pico_ppp_fsm *fsm;

    fsm = &ppp_modem_fsm[ppp->modem_state][event];

    ppp->modem_state = fsm->next_state;

    if (fsm->event_handler)
        fsm->event_handler(ppp);
}

static void ppp_modem_recv(struct pico_device_ppp *ppp, void *data, size_t len)
{
    dbg("PPP: Recv: '%s'\n", data);

    if (strcmp(data, "OK") == 0) {
        evaluate_modem_state(ppp, PPP_MODEM_EVENT_OK);
    }
    if (strcmp(data, "ERROR") == 0) {
        evaluate_modem_state(ppp, PPP_MODEM_EVENT_STOP);
    }
    if (strncmp(data, "CONNECT", 7) == 0) {
        evaluate_modem_state(ppp, PPP_MODEM_EVENT_CONNECT);
    }
}

void ppp_lcp_req(struct pico_device_ppp *ppp)
{
#   define MY_LCP_REQ_SIZE 12 /* Max value. */
    struct pico_lcp_hdr *req; 
    uint8_t *lcpbuf, *opts;
    int size = MY_LCP_REQ_SIZE;
    int prefix;
    int optsize = 0;

    prefix = ppp_ctl_packet_size(ppp, PPP_PROTO_LCP, &size);
    lcpbuf = PICO_ZALLOC(size);
    if (!lcpbuf)
        return;
    req = (struct pico_lcp_hdr *)(lcpbuf + prefix);
        
    opts = lcpbuf + prefix + (sizeof(struct pico_lcp_hdr));
    //uint8_t my_pkt[] = { 0x7e, 0xff, 0x03, 0xc0, 0x21, 0x01, 0x00, 0x00, 0x06, 0x07, 0x02, 0x64, 0x7b, 0x7e };

    dbg("Sending LCP CONF REQ\n");
    req->code = PICO_CONF_REQ;
    req->id = ppp->frame_id++;

    if (LCPOPT_ISSET_LOCAL(ppp, LCPOPT_PROTO_COMP)) {
        opts[optsize++] = LCPOPT_PROTO_COMP;
        opts[optsize++] = LCPOPT_LEN[LCPOPT_PROTO_COMP];
    }

    if (LCPOPT_ISSET_LOCAL(ppp, LCPOPT_MRU)) {
        opts[optsize++] = LCPOPT_MRU;
        opts[optsize++] = LCPOPT_LEN[LCPOPT_MRU];
        opts[optsize++] = (uint8_t)((PICO_PPP_MRU >> 8) & 0xFF);
        opts[optsize++] = (uint8_t)(PICO_PPP_MRU & 0xFF);
    }

    if (LCPOPT_ISSET_LOCAL(ppp, LCPOPT_ADDRCTL_COMP)) {
        opts[optsize++] = LCPOPT_ADDRCTL_COMP;
        opts[optsize++] = LCPOPT_LEN[LCPOPT_ADDRCTL_COMP];
    }
    req->len = short_be(optsize + sizeof(struct pico_lcp_hdr));

    pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_LCP, 
            lcpbuf,                         /* Start of PPP packet */
            prefix +                        /* PPP Header, etc. */
            sizeof(struct pico_lcp_hdr) +   /* LCP HDR */
            optsize +                       /* Actual options size */
            PPP_FCS_SIZE +                  /* FCS at the end of the frame */
            1,                              /* STOP Byte */
            prefix);
    PICO_FREE(lcpbuf);
}

static uint16_t lcp_optflags(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    uint16_t flags = 0;
    uint8_t *p = pkt +  sizeof(struct pico_lcp_hdr);
    while(p < (pkt + len)) {
        flags |= 1 << p[0];
        if ((p[0] == 3) && ppp) {
            dbg("Setting AUTH to %02x%02x\n", p[2], p[3]);
            ppp->auth = (p[2] << 8) + p[3];
        }
        p += p[1];
    }
    return flags;
} 

static void lcp_ack(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    uint8_t ack[len + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_lcp_hdr) + PPP_FCS_SIZE + 1];
    struct pico_lcp_hdr *ack_hdr = (struct pico_lcp_hdr *) (ack + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
    struct pico_lcp_hdr *lcpreq = (struct pico_lcp_hdr *)pkt;
    memcpy(ack + PPP_HDR_SIZE +  PPP_PROTO_SLOT_SIZE, pkt, len);
    ack_hdr->code = PICO_CONF_ACK;
    ack_hdr->id = lcpreq->id;
    ack_hdr->len = lcpreq->len;
    dbg("Sending LCP CONF ACK\n");
    pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_LCP, ack, 
            PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE +            /* PPP Header, etc. */
            short_be(lcpreq->len) +                         /* Actual options size + hdr (whole lcp packet) */
            PPP_FCS_SIZE +                                  /* FCS at the end of the frame */
            1,                                              /* STOP Byte */
            PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
}

static void lcp_reject(struct pico_device_ppp *ppp, uint8_t *pkt, int len, uint16_t rejected)
{
    uint8_t reject[64];
    uint8_t *p = pkt +  sizeof(struct pico_lcp_hdr);
    struct pico_lcp_hdr *lcpreq = (struct pico_lcp_hdr *)pkt;
    struct pico_lcp_hdr *lcprej = (struct pico_lcp_hdr *)(reject + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
    uint8_t *dst_opts = reject + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_lcp_hdr);
    int dstopts_len = 0;
    while (p < (pkt + len)) {
        int i = 0;
        if ((1 << p[0]) & rejected || (p[0] > 8)) {
            dst_opts[dstopts_len++] = p[0];
            dst_opts[dstopts_len++] = p[1];
            for(i = 0; i < p[1]; i++) {
                dst_opts[dstopts_len++] = p[1 + i];
            }
        }  
        p += p[1];
    }
    lcprej->code = PICO_CONF_REJ;
    lcprej->id = lcpreq->id;
    lcprej->len = short_be(dstopts_len + sizeof(struct pico_lcp_hdr));
    dbg("Sending LCP CONF REJ\n");
    pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_LCP, reject, 
            PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE +            /* PPP Header, etc. */
            sizeof(struct pico_lcp_hdr) +                   /* LCP HDR */
            dstopts_len +                                   /* Actual options size */
            PPP_FCS_SIZE +                                  /* FCS at the end of the frame */
            1,                                              /* STOP Byte */
            PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
}

static void lcp_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    uint16_t optflags;
    if (pkt[0] == PICO_CONF_REQ) {
        uint16_t rejected = 0;
        dbg("Received LCP CONF REQ\n");
        optflags = lcp_optflags(ppp, pkt,len);
        rejected = optflags & (~ppp->lcpopt_local);
        ppp->pkt = pkt;
        ppp->len = len;
        ppp->rej = rejected;
        if (rejected) {
            evaluate_lcp_state(ppp, PPP_LCP_EVENT_RCR_NEG);
        } else {
            ppp->lcpopt_peer = optflags;
            evaluate_lcp_state(ppp, PPP_LCP_EVENT_RCR_POS);
        }
        return;
    }
    if (pkt[0] == PICO_CONF_ACK) {
        dbg("Received LCP CONF ACK\nOptflags: %04x\n", lcp_optflags(NULL, pkt, len));
        evaluate_lcp_state(ppp, PPP_LCP_EVENT_RCA);
        return;
    }
    if (pkt[0] == PICO_CONF_NAK) {
        dbg("Received LCP CONF NAK\n");
        evaluate_lcp_state(ppp, PPP_LCP_EVENT_RCN);
        return;
    }
    if (pkt[0] == PICO_CONF_REJ) {
        dbg("Received LCP CONF REJ\n");
        evaluate_lcp_state(ppp, PPP_LCP_EVENT_RCN);
        return;
    }
}

static void pap_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{

}


static void chap_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    struct pico_chap_hdr *ch = (struct pico_chap_hdr *)pkt;

    switch(ch->code) {
        case CHAP_CHALLENGE:
            dbg("Received CHAP CHALLENGE\n");
            ppp->pkt = pkt;
            ppp->len = len;
            evaluate_auth_state(ppp, PPP_AUTH_EVENT_RAC);
            break;
        case CHAP_SUCCESS:
            dbg("Received CHAP SUCCESS\n");
            evaluate_auth_state(ppp, PPP_AUTH_EVENT_RAA);
            break;
        case CHAP_FAILURE:
            dbg("Received CHAP FAILURE\n");
            evaluate_auth_state(ppp, PPP_AUTH_EVENT_RAN);
            break;
    }
}


static void ipcp_ack(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    uint8_t ack[len + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_lcp_hdr) + PPP_FCS_SIZE + 1];
    struct pico_ipcp_hdr *ack_hdr = (struct pico_ipcp_hdr *) (ack + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
    struct pico_ipcp_hdr *ipcpreq = (struct pico_ipcp_hdr *)pkt;
    memcpy(ack + PPP_HDR_SIZE +  PPP_PROTO_SLOT_SIZE, pkt, len);
    ack_hdr->code = PICO_CONF_ACK;
    ack_hdr->id = ipcpreq->id;
    ack_hdr->len = ipcpreq->len;
    dbg("Sending IPCP CONF ACK\n");
    pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_IPCP, ack, 
            PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE +            /* PPP Header, etc. */
            short_be(ipcpreq->len) +                         /* Actual options size + hdr (whole ipcp packet) */
            PPP_FCS_SIZE +                                  /* FCS at the end of the frame */
            1,                                              /* STOP Byte */
            PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
}

static inline int ipcp_request_options_size(struct pico_device_ppp *ppp)
{
    int size = IPCP_ADDR_LEN;
    if (ppp->ipcp_dns1) 
        size += IPCP_ADDR_LEN;
    if (ppp->ipcp_dns2) 
        size += IPCP_ADDR_LEN;
    if (ppp->ipcp_nbns1) 
        size += IPCP_ADDR_LEN;
    if (ppp->ipcp_nbns2) 
        size += IPCP_ADDR_LEN;
    return size;
}

static int ipcp_request_add_address(uint8_t *dst, uint8_t tag, uint32_t arg)
{
    uint32_t addr = long_be(arg);
    dst[0] = tag;
    dst[1] = IPCP_ADDR_LEN;
    dst[2] = (addr & 0xFF000000) >> 24;
    dst[3] = (addr & 0x00FF0000) >> 16;
    dst[4] = (addr & 0x0000FF00) >> 8;
    dst[5] = (addr & 0x000000FF);
    return IPCP_ADDR_LEN;
}

static void ipcp_request_fill(struct pico_device_ppp *ppp, uint8_t *opts)
{
    opts += ipcp_request_add_address(opts, IPCP_OPT_IP, ppp->ipcp_ip);
    if (ppp->ipcp_dns1)
        opts += ipcp_request_add_address(opts, IPCP_OPT_DNS1, ppp->ipcp_dns1);
    if (ppp->ipcp_nbns1)
        opts += ipcp_request_add_address(opts, IPCP_OPT_NBNS1, ppp->ipcp_nbns1);
    if (ppp->ipcp_dns2)
        opts += ipcp_request_add_address(opts, IPCP_OPT_DNS2, ppp->ipcp_dns2);
    if (ppp->ipcp_nbns2)
        opts += ipcp_request_add_address(opts, IPCP_OPT_NBNS2, ppp->ipcp_nbns2);
}

static void ipcp_request(struct pico_device_ppp *ppp)
{
    uint8_t ipcp_req[PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_ipcp_hdr) + ipcp_request_options_size(ppp) + PPP_FCS_SIZE + 1];
    int prefix = PPP_HDR_SIZE +  PPP_PROTO_SLOT_SIZE;
    struct pico_ipcp_hdr *ih = (struct pico_ipcp_hdr *) (ipcp_req + prefix);
    uint8_t *p = ipcp_req + prefix + sizeof(struct pico_ipcp_hdr);
    ih->id = ppp->frame_id++;
    ih->code = PICO_CONF_REQ;
    ih->len = short_be(IPCP_ADDR_LEN + sizeof(struct pico_ipcp_hdr));
    ipcp_request_fill(ppp, p);

    dbg("Sending IPCP CONF REQ\n");
    pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_IPCP, 
            ipcp_req,                       /* Start of PPP packet */
            prefix +                        /* PPP Header, etc. */
            sizeof(struct pico_ipcp_hdr) +  /* LCP HDR */
            ipcp_request_options_size(ppp) +/* Actual options size */
            PPP_FCS_SIZE +                  /* FCS at the end of the frame */
            1,                              /* STOP Byte */
            prefix);
}

static void ipcp_reject_vj(struct pico_device_ppp *ppp, uint8_t *comp_req, int len)
{
    uint8_t ipcp_req[PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_ipcp_hdr) + IPCP_VJ_LEN + PPP_FCS_SIZE + 1];
    int prefix = PPP_HDR_SIZE +  PPP_PROTO_SLOT_SIZE;
    struct pico_ipcp_hdr *ih = (struct pico_ipcp_hdr *) (ipcp_req + prefix);
    uint8_t *p = ipcp_req + prefix + sizeof(struct pico_ipcp_hdr);
    int i;

    ih->id = ppp->frame_id++;
    ih->code = PICO_CONF_REQ;
    ih->len = short_be(IPCP_VJ_LEN + sizeof(struct pico_ipcp_hdr));
    for(i = 0; i < IPCP_OPT_VJ; i++)
        p[i] = comp_req[i + sizeof(struct pico_ipcp_hdr)];
    

    dbg("Sending IPCP CONF REJ VJ\n");
    pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_IPCP, 
            ipcp_req,                       /* Start of PPP packet */
            prefix +                        /* PPP Header, etc. */
            sizeof(struct pico_ipcp_hdr) +  /* LCP HDR */
            IPCP_VJ_LEN +                 /* Actual options size */
            PPP_FCS_SIZE +                  /* FCS at the end of the frame */
            1,                              /* STOP Byte */
            prefix);
}

static void ppp_ipv4_conf(struct pico_device_ppp *ppp)
{
    struct pico_ip4 ip;
    struct pico_ip4 nm;
    struct pico_ip4 dns1;
    struct pico_ip4 dns2;
    struct pico_ip4 any = { };
    ip.addr = ppp->ipcp_ip;
    nm.addr = 0xFFFFFF00;
    pico_ipv4_link_add(&ppp->dev, ip, nm);
    pico_ipv4_route_add(any, any, any, 1, pico_ipv4_link_by_dev(&ppp->dev));

    dns1.addr = ppp->ipcp_dns1;
    dns2.addr = ppp->ipcp_dns2;
    pico_dns_client_nameserver(&dns1, PICO_DNS_NS_ADD);
    pico_dns_client_nameserver(&dns2, PICO_DNS_NS_ADD);
}


static void ipcp_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    struct pico_ipcp_hdr *ih = (struct pico_ipcp_hdr *)pkt;
    uint8_t *p = pkt + sizeof(struct pico_ipcp_hdr);
    int idx;
    int reject = 0;
    while (p < pkt + len) {
        if (p[0] == IPCP_OPT_VJ) {
            reject++;
        }
        if (p[0] == IPCP_OPT_IP) {
            ppp->ipcp_ip = long_be((p[2] << 24) + (p[3] << 16) + (p[4] << 8) + p[5]);
        }
        if (p[0] == IPCP_OPT_DNS1) {
            ppp->ipcp_dns1 = long_be((p[2] << 24) + (p[3] << 16) + (p[4] << 8) + p[5]);
        }
        if (p[0] == IPCP_OPT_NBNS1) {
            ppp->ipcp_nbns1 = long_be((p[2] << 24) + (p[3] << 16) + (p[4] << 8) + p[5]);
        }
        if (p[0] == IPCP_OPT_DNS2) {
            ppp->ipcp_dns2 = long_be((p[2] << 24) + (p[3] << 16) + (p[4] << 8) + p[5]);
        }
        if (p[0] == IPCP_OPT_NBNS2) {
            ppp->ipcp_nbns2 = long_be((p[2] << 24) + (p[3] << 16) + (p[4] << 8) + p[5]);
        }
        p += p[1];
    }
    if (reject) {
        ipcp_reject_vj(ppp, p, len);
        return;
    }

    ppp->pkt = pkt;
    ppp->len = len;

    switch(ih->code) {
        case PICO_CONF_ACK:
            dbg("Received IPCP CONF ACK\n");
            evaluate_ipcp_state(ppp, PPP_IPCP_EVENT_RCA);
            break;
        case PICO_CONF_REQ:
            dbg("Received IPCP CONF REQ\n");
            evaluate_ipcp_state(ppp, PPP_IPCP_EVENT_RCR_POS);
            break;
        case PICO_CONF_NAK:
            dbg("Received IPCP CONF NAK\n");
            evaluate_ipcp_state(ppp, PPP_IPCP_EVENT_RCN);
            break;
        case PICO_CONF_REJ:
            dbg("Received IPCP CONF REJ\n");
            evaluate_ipcp_state(ppp, PPP_IPCP_EVENT_RCN);
            break;
    }
}

static void ipcp6_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{

}

static void ppp_recv_ipv4(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    pico_stack_recv(&ppp->dev, pkt, len);

}

static void ppp_recv_ipv6(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{

}


static void ppp_netconf(struct pico_device_ppp *ppp) 
{
    ipcp_request(ppp);
}

static void ppp_process_packet_payload(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    if (pkt[0] == 0xc0) {
        /* Link control packet */
        if (pkt[1] == 0x21) {
            /* LCP */
            lcp_process_in(ppp, pkt + 2, len - 2);
        } 
        if (pkt[1] == 0x23) {
            /* PAP */
            pap_process_in(ppp, pkt + 2, len - 2);
        }
        return;
    }
    if ((pkt[0] == 0xc2) && (pkt[1] == 0x23)) {
        /*  CHAP */
        chap_process_in(ppp, pkt + 2, len -2);
        return;
    }

    if (pkt[0] == 0x80) {
        /* IP assignment (IPCP/IPCP6) */
        if (pkt[1] == 0x21) {
            /* IPCP */
            ipcp_process_in(ppp, pkt + 2, len - 2);
        }
        if (pkt[1] == 0x57) {
            /* IPCP6 */
            ipcp6_process_in(ppp, pkt + 2, len - 2);
        }
        return;
    }

    if (pkt[0] == 0x00) {
        /* Uncompressed protocol: leading zero. */
        pkt++;
        len--;
    }

    if (pkt[0] == 0x21) {
        /* IPv4 Data */
        ppp_recv_ipv4(ppp, pkt + 1, len - 1);
        return;
    }
    if (pkt[0] == 0x57) {
        ppp_recv_ipv6(ppp, pkt + 1, len - 1);
        return;
    }
    dbg("PPP: Unrecognized protocol %02x%02x\n", pkt[0], pkt[1]);
}

static void ppp_process_packet(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    int i;
    /* Verify incoming FCS */
    if (ppp_fcs_verify(pkt, len) != 0)
        return;

    /* Remove trailing FCS */
    len -= 2;

    /* Remove ADDR/CTRL, then process */
    if ((pkt[0] == PPPF_ADDR) && (pkt[1] == PPPF_CTRL)) {
        pkt+=2;
        len-=2;
    }
    ppp_process_packet_payload(ppp, pkt, len);
    
}



static void ppp_recv_data(struct pico_device_ppp *ppp, void *data, int len)
{
    size_t idx;
    uint8_t *pkt = (uint8_t *)data;

    if (len > 0) {
        dbg("PPP   <<<<< ");
        for(idx = 0; idx < len; idx++) {
            dbg(" %02x", ((uint8_t *)data)[idx]);
        }
        dbg("\n");
    }

    ppp_process_packet(ppp, pkt, len);
}



static void ill(struct pico_device_ppp *ppp)
{
}

static void tlu(struct pico_device_ppp *ppp)
{
    dbg("PPP: LCP up.\n");

    switch (ppp->auth) {
    case 0x0000:
        evaluate_auth_state(ppp, PPP_AUTH_EVENT_UP_NONE);
        break;
    case 0xc023:
        evaluate_auth_state(ppp, PPP_AUTH_EVENT_UP_PAP);
        break;
    case 0xc223:
        evaluate_auth_state(ppp, PPP_AUTH_EVENT_UP_CHAP);
        break;
    default:
        dbg("PPP: Unknown authentication protocol.\n");
        break;
    }
}

static void tld(struct pico_device_ppp *ppp)
{
    dbg("PPP: LCP down.\n");

    evaluate_auth_state(ppp, PPP_AUTH_EVENT_DOWN);
}

static void tls(struct pico_device_ppp *ppp)
{
    dbg("PPP: LCP started.\n");

    evaluate_modem_state(ppp, PPP_MODEM_EVENT_START);
}

static void tlf(struct pico_device_ppp *ppp)
{
    dbg("PPP: LCP finished.\n");

    evaluate_modem_state(ppp, PPP_MODEM_EVENT_STOP);
}

static void irc(struct pico_device_ppp *ppp)
{
}

static void zrc(struct pico_device_ppp *ppp)
{
}

static void scr(struct pico_device_ppp *ppp)
{
    ppp_lcp_req(ppp);
}

static void sca(struct pico_device_ppp *ppp)
{
    lcp_ack(ppp, ppp->pkt, ppp->len);
}

static void scn(struct pico_device_ppp *ppp)
{
    lcp_reject(ppp, ppp->pkt, ppp->len, ppp->rej);
}

static void str(struct pico_device_ppp *ppp)
{
}

static void sta(struct pico_device_ppp *ppp)
{
}

static void scj(struct pico_device_ppp *ppp)
{
}

static void ser(struct pico_device_ppp *ppp)
{
}

static void irc_scr(struct pico_device_ppp *ppp)
{
    irc(ppp);
    scr(ppp);
}

static void irc_scr_sca(struct pico_device_ppp *ppp)
{
    irc(ppp);
    scr(ppp);
    sca(ppp);
}

static void irc_scr_scn(struct pico_device_ppp *ppp)
{
    irc(ppp);
    scr(ppp);
    scn(ppp);
}

static void irc_str(struct pico_device_ppp *ppp)
{
    irc(ppp);
    str(ppp);
}

static void sca_tlu(struct pico_device_ppp *ppp)
{
    sca(ppp);
    tlu(ppp);
}

static void irc_tlu(struct pico_device_ppp *ppp)
{
    irc(ppp);
    tlu(ppp);
}

static void tld_irc_str(struct pico_device_ppp *ppp)
{
    tld(ppp);
    irc(ppp);
    str(ppp);
}

static void tld_scr_sca(struct pico_device_ppp *ppp)
{
    tld(ppp);
    scr(ppp);
    sca(ppp);
}

static void tld_scr_scn(struct pico_device_ppp *ppp)
{
    tld(ppp);
    scr(ppp);
    scn(ppp);
}

static void tld_scr(struct pico_device_ppp *ppp)
{
    tld(ppp);
    scr(ppp);
}

static void tld_zrc_sta(struct pico_device_ppp *ppp)
{
    tld(ppp);
    zrc(ppp);
    sta(ppp);
}

static const struct pico_ppp_fsm ppp_lcp_fsm[PPP_LCP_STATE_MAX][PPP_LCP_EVENT_MAX] = {
    [PPP_LCP_STATE_INITIAL] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_CLOSED, NULL },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_STARTING, tls },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_INITIAL, NULL },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_INITIAL, ill },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_INITIAL, ill }
    },
    [PPP_LCP_STATE_STARTING] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_REQ_SENT, irc_scr },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_STARTING, NULL },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_INITIAL, tlf },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_STARTING, ill },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_STARTING, ill }
    },
    [PPP_LCP_STATE_CLOSED] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_CLOSED, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_INITIAL, NULL },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_REQ_SENT, irc_scr },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSED, NULL },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_CLOSED, ill },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_CLOSED, ill },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_CLOSED, sta },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_CLOSED, sta },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_CLOSED, sta },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_CLOSED, sta },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_CLOSED, sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_CLOSED, NULL },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_CLOSED, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_CLOSED, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_CLOSED, tlf },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_CLOSED, NULL }
    },
    [PPP_LCP_STATE_STOPPED] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_STOPPED, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_STARTING, tls },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_STOPPED, NULL},
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSED, NULL},
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_STOPPED, ill },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_STOPPED, ill },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_ACK_SENT, irc_scr_sca },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_REQ_SENT, irc_scr_scn },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_STOPPED, sta },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_STOPPED, sta },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_STOPPED, sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_STOPPED, NULL },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_STOPPED, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_STOPPED, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_STOPPED, NULL }
    },
    [PPP_LCP_STATE_CLOSING] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_CLOSING, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_INITIAL, NULL },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_STOPPING, NULL },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSING, NULL },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_CLOSING, str },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_CLOSED, tlf },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_CLOSING, NULL },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_CLOSING, NULL },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_CLOSING, NULL },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_CLOSING, NULL },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_CLOSING, sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_CLOSED, tlf },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_CLOSING, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_CLOSING, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_CLOSED, tlf },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_CLOSING, NULL }
    },
    [PPP_LCP_STATE_STOPPING] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_STOPPING, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_STARTING, NULL },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_STOPPING, NULL },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSING, NULL },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_STOPPING, str },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_STOPPING, NULL },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_STOPPING, NULL },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_STOPPING, NULL },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_STOPPING, NULL },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_STOPPING, sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_STOPPING, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_STOPPING, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_STOPPING, NULL }
    },
    [PPP_LCP_STATE_REQ_SENT] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_REQ_SENT, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_STARTING, NULL },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_REQ_SENT, NULL },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSING, irc_str },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_REQ_SENT, scr },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_ACK_SENT, sca },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_REQ_SENT, scn },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_ACK_RCVD, irc },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_REQ_SENT, irc_scr },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_REQ_SENT, sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_REQ_SENT, NULL },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_REQ_SENT, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_REQ_SENT, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_REQ_SENT, NULL }
    },
    [PPP_LCP_STATE_ACK_RCVD] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_ACK_RCVD, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_STARTING, NULL },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_ACK_RCVD, NULL },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSING, irc_str },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_REQ_SENT, scr },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_OPENED, sca_tlu },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_ACK_RCVD, scn },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_REQ_SENT, scr },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_REQ_SENT, scr },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_REQ_SENT, sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_REQ_SENT, NULL },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_ACK_RCVD, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_REQ_SENT, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_ACK_RCVD, NULL }
    },
    [PPP_LCP_STATE_ACK_SENT] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_ACK_SENT, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_STARTING, NULL },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_ACK_SENT, NULL },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSING, irc_str },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_ACK_SENT, scr },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_ACK_SENT, sca },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_REQ_SENT, scn },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_OPENED, irc_tlu },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_ACK_SENT, irc_scr },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_REQ_SENT, sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_ACK_SENT, NULL },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_ACK_SENT, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_ACK_SENT, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_STOPPED, tlf },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_ACK_SENT, NULL }
    },
    [PPP_LCP_STATE_OPENED] = {
            [PPP_LCP_EVENT_UP]      = { PPP_LCP_STATE_OPENED, ill },
            [PPP_LCP_EVENT_DOWN]    = { PPP_LCP_STATE_STARTING, tld },
            [PPP_LCP_EVENT_OPEN]    = { PPP_LCP_STATE_OPENED, NULL },
            [PPP_LCP_EVENT_CLOSE]   = { PPP_LCP_STATE_CLOSING, tld_irc_str },
            [PPP_LCP_EVENT_TO_POS]  = { PPP_LCP_STATE_OPENED, ill },
            [PPP_LCP_EVENT_TO_NEG]  = { PPP_LCP_STATE_OPENED, ill },
            [PPP_LCP_EVENT_RCR_POS] = { PPP_LCP_STATE_ACK_SENT, tld_scr_sca },
            [PPP_LCP_EVENT_RCR_NEG] = { PPP_LCP_STATE_REQ_SENT, tld_scr_scn },
            [PPP_LCP_EVENT_RCA]     = { PPP_LCP_STATE_REQ_SENT, tld_scr },
            [PPP_LCP_EVENT_RCN]     = { PPP_LCP_STATE_REQ_SENT, tld_scr },
            [PPP_LCP_EVENT_RTR]     = { PPP_LCP_STATE_STOPPING, tld_zrc_sta },
            [PPP_LCP_EVENT_RTA]     = { PPP_LCP_STATE_REQ_SENT, tld_scr },
            [PPP_LCP_EVENT_RUC]     = { PPP_LCP_STATE_OPENED, scj },
            [PPP_LCP_EVENT_RXJ_POS] = { PPP_LCP_STATE_OPENED, NULL },
            [PPP_LCP_EVENT_RXJ_NEG] = { PPP_LCP_STATE_STOPPING, tld_irc_str },
            [PPP_LCP_EVENT_RXR]     = { PPP_LCP_STATE_OPENED, ser}
    }
};

static void evaluate_lcp_state(struct pico_device_ppp *ppp, enum ppp_lcp_event event)
{
    const struct pico_ppp_fsm *fsm;

    /* Not every event should stop a timer, yes? */
    /* Maybe stop timer in specific event handler? */
    /* Kill timers */
    //pico_timer_cancel(ppp->timer);

    fsm = &ppp_lcp_fsm[ppp->lcp_state][event];

    ppp->lcp_state = fsm->next_state;

    if (fsm->event_handler)
        fsm->event_handler(ppp);
}

static void auth(struct pico_device_ppp *ppp)
{
    dbg("PPP: Authenticated.\n");

    evaluate_ipcp_state(ppp, PPP_IPCP_EVENT_UP);
}

static void deauth(struct pico_device_ppp *ppp)
{
    dbg("PPP: De-authenticated.\n");

    evaluate_ipcp_state(ppp, PPP_IPCP_EVENT_DOWN);
}

static void auth_req(struct pico_device_ppp *ppp)
{
}

static void auth_rsp(struct pico_device_ppp *ppp)
{
    struct pico_chap_hdr *ch = (struct pico_chap_hdr *)ppp->pkt;
    uint8_t resp[PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_chap_hdr) + CHAP_MD5_SIZE + PPP_FCS_SIZE + 1];
    struct pico_chap_hdr *rh = (struct pico_chap_hdr *) (resp + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
    uint8_t *md5resp = resp + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_chap_hdr);
    uint8_t *challenge;
    int i = 0, pwdlen;

    challenge = PICO_ZALLOC(CHALLENGE_SIZE(ppp, ch));

    if (!challenge)
        return;

    pwdlen = strlen(ppp->password);
    challenge[i++] = ch->id;
    memcpy(challenge + i, ppp->password, pwdlen);
    i += pwdlen;
    memcpy(challenge + i, ppp->pkt + sizeof(struct pico_chap_hdr), short_be(ch->len));
    i += ch->len;
    pico_md5sum(md5resp, challenge, i);
    pico_free(challenge);
    rh->id = ch->id;
    rh->code = CHAP_RESPONSE;
    rh->len = short_be(CHAP_MD5_SIZE + sizeof(struct pico_chap_hdr));
    dbg("Sending CHAP RESPONSE\n");
    pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_CHAP,
        resp,                         /* Start of PPP packet */
        PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + /* PPP Header, etc. */
        sizeof(struct pico_chap_hdr) +   /* CHAP HDR */
        CHAP_MD5_SIZE +                   /* Actual payload size */
        PPP_FCS_SIZE +                  /* FCS at the end of the frame */
        1,                              /* STOP Byte */
        PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
}

static const struct pico_ppp_fsm ppp_auth_fsm[PPP_AUTH_STATE_MAX][PPP_AUTH_EVENT_MAX] = {
    [PPP_AUTH_STATE_INITIAL] = {
            [PPP_AUTH_EVENT_UP_NONE] = { PPP_AUTH_STATE_AUTHENTICATED, auth },
            [PPP_AUTH_EVENT_UP_PAP]  = { PPP_AUTH_STATE_REQ_SENT, auth_req },
            [PPP_AUTH_EVENT_UP_CHAP] = { PPP_AUTH_STATE_STARTING, NULL },
            [PPP_AUTH_EVENT_DOWN]    = { PPP_AUTH_STATE_INITIAL, ill },
            [PPP_AUTH_EVENT_RAC]     = { PPP_AUTH_STATE_INITIAL, ill },
            [PPP_AUTH_EVENT_RAA]     = { PPP_AUTH_STATE_INITIAL, ill },
            [PPP_AUTH_EVENT_RAN]     = { PPP_AUTH_STATE_INITIAL, ill }
    },
    [PPP_AUTH_STATE_STARTING] = {
            [PPP_AUTH_EVENT_UP_NONE] = { PPP_AUTH_STATE_STARTING, ill },
            [PPP_AUTH_EVENT_UP_PAP]  = { PPP_AUTH_STATE_STARTING, ill },
            [PPP_AUTH_EVENT_UP_CHAP] = { PPP_AUTH_STATE_STARTING, ill },
            [PPP_AUTH_EVENT_DOWN]    = { PPP_AUTH_STATE_INITIAL, deauth },
            [PPP_AUTH_EVENT_RAC]     = { PPP_AUTH_STATE_RSP_SENT, auth_rsp },
            [PPP_AUTH_EVENT_RAA]     = { PPP_AUTH_STATE_STARTING, NULL },
            [PPP_AUTH_EVENT_RAN]     = { PPP_AUTH_STATE_STARTING, NULL }
    },
    [PPP_AUTH_STATE_RSP_SENT] = {
            [PPP_AUTH_EVENT_UP_NONE] = { PPP_AUTH_STATE_RSP_SENT, ill },
            [PPP_AUTH_EVENT_UP_PAP]  = { PPP_AUTH_STATE_RSP_SENT, ill },
            [PPP_AUTH_EVENT_UP_CHAP] = { PPP_AUTH_STATE_RSP_SENT, ill },
            [PPP_AUTH_EVENT_DOWN]    = { PPP_AUTH_STATE_INITIAL, deauth },
            [PPP_AUTH_EVENT_RAC]     = { PPP_AUTH_STATE_RSP_SENT, auth_rsp },
            [PPP_AUTH_EVENT_RAA]     = { PPP_AUTH_STATE_AUTHENTICATED, auth },
            [PPP_AUTH_EVENT_RAN]     = { PPP_AUTH_STATE_STARTING, NULL }
    },
    [PPP_AUTH_STATE_REQ_SENT] = {
            [PPP_AUTH_EVENT_UP_NONE] = { PPP_AUTH_STATE_REQ_SENT, ill },
            [PPP_AUTH_EVENT_UP_PAP]  = { PPP_AUTH_STATE_REQ_SENT, ill },
            [PPP_AUTH_EVENT_UP_CHAP] = { PPP_AUTH_STATE_REQ_SENT, ill },
            [PPP_AUTH_EVENT_DOWN]    = { PPP_AUTH_STATE_INITIAL, deauth },
            [PPP_AUTH_EVENT_RAC]     = { PPP_AUTH_STATE_REQ_SENT, NULL },
            [PPP_AUTH_EVENT_RAA]     = { PPP_AUTH_STATE_AUTHENTICATED, auth },
            [PPP_AUTH_EVENT_RAN]     = { PPP_AUTH_STATE_REQ_SENT, auth_req }
    },
    [PPP_AUTH_STATE_AUTHENTICATED] = {
            [PPP_AUTH_EVENT_UP_NONE] = { PPP_AUTH_STATE_AUTHENTICATED, ill },
            [PPP_AUTH_EVENT_UP_PAP]  = { PPP_AUTH_STATE_AUTHENTICATED, ill },
            [PPP_AUTH_EVENT_UP_CHAP] = { PPP_AUTH_STATE_AUTHENTICATED, ill },
            [PPP_AUTH_EVENT_DOWN]    = { PPP_AUTH_STATE_INITIAL, deauth },
            [PPP_AUTH_EVENT_RAC]     = { PPP_AUTH_STATE_RSP_SENT, auth_rsp },
            [PPP_AUTH_EVENT_RAA]     = { PPP_AUTH_STATE_AUTHENTICATED, NULL },
            [PPP_AUTH_EVENT_RAN]     = { PPP_AUTH_STATE_AUTHENTICATED, NULL }
    }
};

static void evaluate_auth_state(struct pico_device_ppp *ppp, enum ppp_auth_event event)
{
    const struct pico_ppp_fsm *fsm;

    fsm = &ppp_auth_fsm[ppp->auth_state][event];

    ppp->auth_state = fsm->next_state;

    if (fsm->event_handler)
        fsm->event_handler(ppp);
}

static void ipcp_scr(struct pico_device_ppp *ppp)
{
    ipcp_request(ppp);
}

static void ipcp_sca(struct pico_device_ppp *ppp)
{
    ipcp_ack(ppp, ppp->pkt, ppp->len);
}

static void ipcp_scn(struct pico_device_ppp *ppp)
{
}

static void ipcp_tlu(struct pico_device_ppp *ppp)
{
    dbg("PPP: IPCP up.\n");

    if (ppp->ipcp_ip) {
    char my_ip[16], my_dns[16];
        pico_ipv4_to_string(my_ip, ppp->ipcp_ip);
        dbg("Received IP config %s\n", my_ip);
        pico_ipv4_to_string(my_dns, ppp->ipcp_dns1);
        dbg("Received DNS: %s\n", my_dns);
        ppp_ipv4_conf(ppp);
    }
}

static void ipcp_tld(struct pico_device_ppp *ppp)
{
    dbg("PPP: IPCP down.\n");
}

static void ipcp_sca_tlu(struct pico_device_ppp *ppp)
{
    ipcp_sca(ppp);
    ipcp_tlu(ppp);
}

static void ipcp_tld_scr_sca(struct pico_device_ppp *ppp)
{
    ipcp_tld(ppp);
    ipcp_scr(ppp);
    ipcp_sca(ppp);
}

static void ipcp_tld_scr_scn(struct pico_device_ppp *ppp)
{
    ipcp_tld(ppp);
    ipcp_scr(ppp);
    ipcp_scn(ppp);
}

static const struct pico_ppp_fsm ppp_ipcp_fsm[PPP_IPCP_STATE_MAX][PPP_IPCP_EVENT_MAX] = {
    [PPP_IPCP_STATE_INITIAL] = {
            [PPP_IPCP_EVENT_UP]      = { PPP_IPCP_STATE_REQ_SENT, ipcp_scr },
            [PPP_IPCP_EVENT_DOWN]    = { PPP_IPCP_STATE_INITIAL, NULL },
            [PPP_IPCP_EVENT_RCR_POS] = { PPP_IPCP_STATE_INITIAL, ill },
            [PPP_IPCP_EVENT_RCR_NEG] = { PPP_IPCP_STATE_INITIAL, ill },
            [PPP_IPCP_EVENT_RCA]     = { PPP_IPCP_STATE_INITIAL, ill },
            [PPP_IPCP_EVENT_RCN]     = { PPP_IPCP_STATE_INITIAL, ill }
    },
    [PPP_IPCP_STATE_REQ_SENT] = {
            [PPP_IPCP_EVENT_UP]      = { PPP_IPCP_STATE_REQ_SENT, ill },
            [PPP_IPCP_EVENT_DOWN]    = { PPP_IPCP_STATE_INITIAL, NULL },
            [PPP_IPCP_EVENT_RCR_POS] = { PPP_IPCP_STATE_ACK_SENT, ipcp_sca },
            [PPP_IPCP_EVENT_RCR_NEG] = { PPP_IPCP_STATE_REQ_SENT, ipcp_scn },
            [PPP_IPCP_EVENT_RCA]     = { PPP_IPCP_STATE_ACK_RCVD, NULL },
            [PPP_IPCP_EVENT_RCN]     = { PPP_IPCP_STATE_REQ_SENT, ipcp_scr }
    },
    [PPP_IPCP_STATE_ACK_RCVD] = {
            [PPP_IPCP_EVENT_UP]      = { PPP_IPCP_STATE_ACK_RCVD, ill },
            [PPP_IPCP_EVENT_DOWN]    = { PPP_IPCP_STATE_INITIAL, NULL },
            [PPP_IPCP_EVENT_RCR_POS] = { PPP_IPCP_STATE_OPENED, ipcp_sca_tlu },
            [PPP_IPCP_EVENT_RCR_NEG] = { PPP_IPCP_STATE_ACK_RCVD, ipcp_scn },
            [PPP_IPCP_EVENT_RCA]     = { PPP_IPCP_STATE_REQ_SENT, ipcp_scr },
            [PPP_IPCP_EVENT_RCN]     = { PPP_IPCP_STATE_REQ_SENT, ipcp_scr }
    },
    [PPP_IPCP_STATE_ACK_SENT] = {
            [PPP_IPCP_EVENT_UP]      = { PPP_IPCP_STATE_ACK_SENT, ill },
            [PPP_IPCP_EVENT_DOWN]    = { PPP_IPCP_STATE_INITIAL, NULL },
            [PPP_IPCP_EVENT_RCR_POS] = { PPP_IPCP_STATE_ACK_SENT, ipcp_sca },
            [PPP_IPCP_EVENT_RCR_NEG] = { PPP_IPCP_STATE_REQ_SENT, ipcp_scn },
            [PPP_IPCP_EVENT_RCA]     = { PPP_IPCP_STATE_OPENED, ipcp_tlu },
            [PPP_IPCP_EVENT_RCN]     = { PPP_IPCP_STATE_ACK_SENT, ipcp_scr }
    },
    [PPP_IPCP_STATE_OPENED] = {
            [PPP_IPCP_EVENT_UP]      = { PPP_IPCP_STATE_OPENED, ill },
            [PPP_IPCP_EVENT_DOWN]    = { PPP_IPCP_STATE_INITIAL, ipcp_tld },
            [PPP_IPCP_EVENT_RCR_POS] = { PPP_IPCP_STATE_ACK_SENT, ipcp_tld_scr_sca },
            [PPP_IPCP_EVENT_RCR_NEG] = { PPP_IPCP_STATE_REQ_SENT, ipcp_tld_scr_scn },
            [PPP_IPCP_EVENT_RCA]     = { PPP_IPCP_STATE_REQ_SENT, ipcp_scr },
            [PPP_IPCP_EVENT_RCN]     = { PPP_IPCP_STATE_REQ_SENT, ipcp_scr }
    }
};

static void evaluate_ipcp_state(struct pico_device_ppp *ppp, enum ppp_ipcp_event event)
{
    const struct pico_ppp_fsm *fsm;

    fsm = &ppp_ipcp_fsm[ppp->ipcp_state][event];

    ppp->ipcp_state = fsm->next_state;

    if (fsm->event_handler)
        fsm->event_handler(ppp);
}

static void ppp_recv(struct pico_device_ppp *ppp, void *data, size_t len)
{
}

struct pico_ppp_fsm_action {
    void (*timeout)(struct pico_device_ppp *ppp);
    void (*recv)(struct pico_device_ppp *ppp, void *data, int len);
};

struct pico_ppp_fsm_action pico_ppp_fsm[PPP_MODEM_MAXSTATE] = {
      /* State                        timeout                 recv        */
//  { /* PPP_MODEM_RESET   */         ppp_send_creg,          ppp_recv_creg    },
//  { /* PPP_MODEM_CREG    */         ppp_send_cgreg,         ppp_recv_cgreg   },
//  { /* PPP_MODEM_CGREG   */         ppp_send_cgdcont,       ppp_recv_cgdcont },
//  { /* PPP_MODEM_CGDCONT */         ppp_send_cgatt,         ppp_recv_cgatt   },
//  { /* PPP_MODEM_CGATT   */         ppp_dial,               ppp_recv_connect },
//  { /* PPP_MODEM_CONNECT */         ppp_lcp_req,            ppp_recv_data    },
//  { /* PPP_ESTABLISH     */         ppp_lcp_req,            ppp_recv_data    },
//  { /* PPP_AUTH          */         NULL,                   ppp_recv_data    },
//  { /* PPP_NETCONFIG     */         ppp_netconf,            ppp_recv_data    },
//  { /* PPP_NETWORK       */         NULL,                   ppp_recv_data    },
//  { NULL, NULL}
};



static int pico_ppp_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *) dev;
    static size_t len = 0;
    int r;
    uint8_t *p, *endcmd, *end;
    if (ppp->serial_recv) {
        do {
            r = ppp->serial_recv(&ppp->dev, &ppp_recv_buf[len], 1);
            if (r <= 0)
                break;

            if (ppp->modem_state == PPP_MODEM_STATE_CONNECTED) {
                static int control_escape = 0;

                if (ppp_recv_buf[len] == PPPF_FLAG_SEQ) {
                    if (control_escape) {
                        /* Illegal sequence, discard frame */
                        control_escape = 0;
                        len = 0;
                    }
                    if (len > 0) {
                        ppp_recv_data(ppp, ppp_recv_buf, len);
                        len = 0;
                    }
                } else if (control_escape) {
                    ppp_recv_buf[len] ^= 0x20;
                    control_escape = 0;
                    len++;
                } else if (ppp_recv_buf[len] == PPPF_CTRL_ESC) {
                    control_escape = 1;
                } else {
                    len++;
                }
            } else {
                static int s3 = 0;

                if (ppp_recv_buf[len] == AT_S3) {
                    s3 = 1;
                    if (len > 0) {
                        ppp_recv_buf[len] = '\0';
                        ppp_modem_recv(ppp, ppp_recv_buf, len);
                        len = 0;
                    }
                } else if (ppp_recv_buf[len] == AT_S4) {
                    if (!s3) {
                        len++;
                    }
                    s3 = 0;
                } else {
                    s3 = 0;
                    len++;
                }

                /* TODO: check usage */
                /* loop_score--; */
            }
        } while ((r > 0) && (len < ARRAY_SIZE(ppp_recv_buf)) && (loop_score > 0));
    }
    return loop_score;
}

/* Public interface: create/destroy. */

static int pico_ppp_link_state(struct pico_device *dev)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    if (ppp->ipcp_state == PPP_IPCP_STATE_OPENED)
        return 1;
    return 0;
}


static void pico_ppp_tick(pico_time now, void *arg)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)arg;

    if (pico_ppp_fsm[ppp->state].timeout)
        pico_ppp_fsm[ppp->state].timeout(ppp);


    pico_timer_add(1000, pico_ppp_tick, ppp);
}

void pico_ppp_destroy(struct pico_device *ppp)
{
    if (!ppp)
        return;

    /* Perform custom cleanup here before calling 'pico_device_destroy'
     * or register a custom cleanup function during initialization
     * by setting 'ppp->dev.destroy'. */

    pico_device_destroy(ppp);
}

struct pico_device *pico_ppp_create(void)
{
    struct pico_device_ppp *ppp = PICO_ZALLOC(sizeof(struct pico_device_ppp));
    char devname[MAX_DEVICE_NAME];

    if (!ppp)
        return NULL;

    snprintf(devname, MAX_DEVICE_NAME, "ppp%d", ppp_devnum++);

    if( 0 != pico_device_init((struct pico_device *)ppp, devname, NULL)) {
        return NULL;
    }

    ppp->dev.overhead = PPP_HDR_SIZE;
    ppp->dev.mtu = PICO_PPP_MTU;
    ppp->dev.send = pico_ppp_send;
    ppp->dev.poll = pico_ppp_poll;
    ppp->dev.link_state  = pico_ppp_link_state;
    ppp->frame_id = (uint8_t)(pico_rand() % 0xFF);

    ppp->modem_state = PPP_MODEM_STATE_INITIAL;
    ppp->lcp_state = PPP_LCP_STATE_INITIAL;
    ppp->auth_state = PPP_AUTH_STATE_INITIAL;
    ppp->ipcp_state = PPP_IPCP_STATE_INITIAL;

    LCPOPT_SET_LOCAL(ppp, LCPOPT_MRU);
    LCPOPT_SET_LOCAL(ppp, LCPOPT_AUTH); /* We support authentication, even if it's not part of the req */
    LCPOPT_SET_LOCAL(ppp, LCPOPT_PROTO_COMP);
    LCPOPT_SET_LOCAL(ppp, LCPOPT_ADDRCTL_COMP);

    dbg("Device %s created.\n", ppp->dev.name);
    return (struct pico_device *)ppp;
}

int pico_ppp_connect(struct pico_device *dev)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    evaluate_lcp_state(ppp, PPP_LCP_EVENT_OPEN);
}

int pico_ppp_disconnect(struct pico_device *dev, void (*disconnect_cb)(void *), void *arg)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    evaluate_lcp_state(ppp, PPP_LCP_EVENT_CLOSE);
    disconnect_cb(arg);
}

int pico_ppp_set_serial_read(struct pico_device *dev, int (*sread)(struct pico_device *, void *, int))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    if (!dev)
        return -1;

    ppp->serial_recv = sread;
    return 0;
}

int pico_ppp_set_serial_write(struct pico_device *dev, int (*swrite)(struct pico_device *, const void *, int))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    if (!dev)
        return -1;

    ppp->serial_send = swrite;
    return 0;
}

int pico_ppp_set_serial_set_speed(struct pico_device *dev, int (*sspeed)(struct pico_device *, uint32_t))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    if (!dev)
        return -1;

    ppp->serial_set_speed = sspeed;
    return 0;
}

int pico_ppp_set_apn(struct pico_device *dev, const char *apn)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    if (!dev)
        return -1;

    if (!apn)
        return -1;

    strncpy(ppp->apn, apn, sizeof(ppp->apn) - 1);
    return 0;
}

int pico_ppp_set_username(struct pico_device *dev, const char *username)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    if (!dev)
        return -1;

    if (!username)
        return -1;

    strncpy(ppp->username, username, sizeof(ppp->username) - 1);
    return 0;
}

int pico_ppp_set_password(struct pico_device *dev, const char *password)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;

    if (!dev)
        return -1;

    if (!password)
        return -1;

    strncpy(ppp->password, password, sizeof(ppp->password) - 1);
    return 0;
}
