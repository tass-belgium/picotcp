/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera, Maxime Vincent
 *********************************************************************/


#include "pico_device.h"
#include "pico_dev_ppp.h"
#include "pico_stack.h"
#include "pico_md5.h"
#include "pico_dns_client.h"

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
static const unsigned char  PPPF_STARTSTOP = 0x7eu;
static const unsigned char  PPPF_CONT      = 0x7du;
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
    enum pico_ppp_state state;
    uint8_t frame_id;
    char apn[PPP_MAX_APN];
    char password[PPP_MAX_PASSWORD];
    char username[PPP_MAX_USERNAME];
    uint16_t lcpopt_local;
    uint16_t lcpopt_peer;
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

#define LCPOPT_SET_LOCAL(ppp, opt) ppp->lcpopt_local |= (1 << opt)
#define LCPOPT_SET_PEER(ppp, opt) ppp->lcpopt_peer |= (1 << opt)
#define LCPOPT_UNSET_LOCAL(ppp, opt) ppp->lcpopt_local &= ~(1 << opt)
#define LCPOPT_UNSET_PEER(ppp, opt) ppp->lcpopt_peer &= ~(1 << opt)
#define LCPOPT_ISSET_LOCAL(ppp, opt) ((ppp->lcpopt_local & (1 << opt)) != 0)
#define LCPOPT_ISSET_PEER(ppp, opt) ((ppp->lcpopt_peer & (1 << opt)) != 0)


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
    ptr[i++] = PPPF_STARTSTOP;
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
    pkt[len - 1] = PPPF_STARTSTOP;

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
    if (ppp->state != PPP_NETWORK)
        return len;

    if (!ppp->serial_send)
        return len;

    pico_ppp_data_buffer[i++] = PPPF_STARTSTOP;
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
    pico_ppp_data_buffer[i++] = PPPF_STARTSTOP;
    ppp->serial_send(&ppp->dev, pico_ppp_data_buffer, i);
    return len;
}


/* FSM functions */
static void ppp_chat_input(struct pico_device_ppp *ppp)
{
    int r;
    int i, j;
    const char ppp_error[] = "ERROR";
    do {
        r = ppp->serial_recv(&ppp->dev, ppp_recv_buf, PPP_MAXPKT);
        for (i = 0, j = 0; i < r; i++) {
            if (ppp_recv_buf[i] != ppp_error[j++]) {
                j = 0;
            }
            if (j == strlen(ppp_error))
                ppp->state = PPP_MODEM_RST;
        }
    } while (r > 0);
}


#define PPP_AT_CREG0 "ATZ\r\n"
#define PPP_AT_CREG1 "ATE0\r\n"
#define PPP_AT_CREG2 "AT+CREG=1\r\n"
#define PPP_AT_CREG3 "AT+CREG?\r\n"
void ppp_send_creg(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send || !ppp->serial_recv)
        return;
    ppp->serial_send(&ppp->dev, PPP_AT_CREG0, strlen(PPP_AT_CREG0));
    ppp_chat_input(ppp);
    ppp->serial_send(&ppp->dev, PPP_AT_CREG1, strlen(PPP_AT_CREG1));
    ppp_chat_input(ppp);
    ppp->serial_send(&ppp->dev, PPP_AT_CREG2, strlen(PPP_AT_CREG2));
    ppp_chat_input(ppp);
    ppp->serial_send(&ppp->dev, PPP_AT_CREG3, strlen(PPP_AT_CREG3));
}

void ppp_recv_creg(struct pico_device_ppp *ppp, void *data, int len)
{
    dbg("PPP: Recv: %s\n", data);
    if (strcmp(data, "+CREG: 1,1") == 0)
        ppp->state++;
}   

#define PPP_AT_CGREG "AT+CGREG=1\r\n"
#define PPP_AT_CGREG_Q "AT+CGREG?\r\n"
void ppp_send_cgreg(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;
    ppp->serial_send(&ppp->dev, PPP_AT_CGREG, strlen(PPP_AT_CGREG));
    ppp_chat_input(ppp);
    ppp->serial_send(&ppp->dev, PPP_AT_CGREG_Q, strlen(PPP_AT_CGREG_Q));
}

void ppp_recv_cgreg(struct pico_device_ppp *ppp, void *data, int len)
{
    dbg("PPP: Recv: %s\n", data);
    if (strcmp(data, "+CGREG: 1,1") == 0)
        ppp->state++;
}  

#define PPP_AT_CGDCONT "AT+CGDCONT=1,\"IP\",\"%s\",,,\r\n"
#define PPP_AT_CGDCONT_Q "AT+CGDCONT?\r\n"
void ppp_send_cgdcont(struct pico_device_ppp *ppp)
{
    char at_cgdcont[200];
    if (!ppp->serial_send)
        return;
    snprintf(at_cgdcont, 200, PPP_AT_CGDCONT, ppp->apn);
    ppp->serial_send(&ppp->dev, at_cgdcont, strlen(at_cgdcont));
    ppp_chat_input(ppp);
    ppp->serial_send(&ppp->dev, PPP_AT_CGDCONT_Q, strlen(PPP_AT_CGDCONT_Q));
}

void ppp_recv_cgdcont(struct pico_device_ppp *ppp, void *data, int len)
{
    dbg("PPP: Recv: %s\n", data);
    if (strncmp(data, "+CGDCONT: 1,", 12) == 0)
        ppp->state++;
}   


#define PPP_AT_CGATT "AT+CGATT=1\r\n"
#define PPP_AT_CGATT_Q "AT+CGATT?\r\n"
void ppp_send_cgatt(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;
    ppp->serial_send(&ppp->dev, PPP_AT_CGATT, strlen(PPP_AT_CGATT));
    ppp_chat_input(ppp);
    ppp->serial_send(&ppp->dev, PPP_AT_CGATT_Q, strlen(PPP_AT_CGATT_Q));
}

void ppp_recv_cgatt(struct pico_device_ppp *ppp, void *data, int len)
{
    dbg("PPP: Recv: %s\n", data);
    if (strcmp(data, "+CGATT: 1") == 0)
        ppp->state++;

}  

#define PPP_AT_DIALIN "ATD*99#\r\n"
void ppp_dial(struct pico_device_ppp *ppp)
{
    if (!ppp->serial_send)
        return;
    ppp->serial_send(&ppp->dev, PPP_AT_DIALIN, strlen(PPP_AT_DIALIN));

}

void ppp_recv_connect(struct pico_device_ppp *ppp, void *data, int len)
{
    dbg("PPP: Recv: %s\n", data);
    if (strncmp(data, "CONNECT", 7) == 0) {
        ppp->state++;
        dbg("PPP: Connection Established with peer.\n");
        /*
        if (ppp->serial_set_speed)
            ppp->serial_set_speed(ppp, 0);
            */
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

    dbg("Sending LCP req\n");
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

static void ppp_shift(uint8_t *buf, int i, int len)
{
    for(; i < len; i++) {
        buf[i] = buf[i + 1];
    }
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
    dbg("Sending REJECT\n");
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
        optflags = lcp_optflags(ppp, pkt,len);
        rejected = optflags & (~ppp->lcpopt_local);
        if (rejected) {
            lcp_reject(ppp, pkt, len, rejected);
        } else {
            ppp->lcpopt_peer = optflags;
            lcp_ack(ppp, pkt, len);
        }
        return;
    }
    if (pkt[0] == PICO_CONF_ACK) {
        dbg("LCP ACK! Optflags: %04x\n", lcp_optflags(NULL, pkt, len));
        ppp->state = PPP_AUTH;
        return;
    }
    if (pkt[0] == PICO_CONF_NAK) {
        dbg("LCP NACK!\n");
        return;
    }
    if (pkt[0] == PICO_CONF_REJ) {
        dbg("LCP REJECT!\n");
        return;
    }
}

static void pap_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{

}


static void chap_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len)
{
    struct pico_chap_hdr *ch = (struct pico_chap_hdr *)pkt;
    uint8_t resp[PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_chap_hdr) + CHAP_MD5_SIZE + PPP_FCS_SIZE + 1];
    struct pico_chap_hdr *rh = (struct pico_chap_hdr *) (resp + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
    uint8_t *md5resp = resp + PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + sizeof(struct pico_chap_hdr); 
    uint8_t *challenge;
    int i = 0, pwdlen;

    dbg("CHAP!\n");
    switch(ch->code) {
        case CHAP_CHALLENGE:
            challenge = PICO_ZALLOC(CHALLENGE_SIZE(ppp, ch));
            if (!challenge)
                return;
            pwdlen = strlen(ppp->password);
            dbg("Received challenge from peer\n");
            challenge[i++] = ch->id;
            memcpy(challenge + i, ppp->password, pwdlen);
            i += pwdlen;
            memcpy(challenge + i, pkt + sizeof(struct pico_chap_hdr), short_be(ch->len));
            i += ch->len;
            pico_md5sum(md5resp, challenge, i);
            pico_free(challenge);
            rh->id = ch->id;
            rh->code = CHAP_RESPONSE;
            rh->len = short_be(CHAP_MD5_SIZE + sizeof(struct pico_chap_hdr));
            pico_ppp_ctl_send(&ppp->dev, PPP_PROTO_CHAP, 
                resp,                         /* Start of PPP packet */
                PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE + /* PPP Header, etc. */
                sizeof(struct pico_chap_hdr) +   /* CHAP HDR */
                CHAP_MD5_SIZE +                   /* Actual payload size */
                PPP_FCS_SIZE +                  /* FCS at the end of the frame */
                1,                              /* STOP Byte */
                PPP_HDR_SIZE + PPP_PROTO_SLOT_SIZE);
            break;
        case CHAP_SUCCESS:
            dbg("AUTH: SUCCESS!!\n");
            ppp->state = PPP_NETCONFIG;
            break;
        case CHAP_FAILURE:
            dbg("AUTH: FAILURE!!\n");
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

    switch(ih->code) {
        case PICO_CONF_ACK:
            if (ppp->ipcp_ip) {
                char my_ip[16], my_dns[16];
                pico_ipv4_to_string(my_ip, ppp->ipcp_ip);
                dbg("Received IP config %s\n", my_ip);
                pico_ipv4_to_string(my_dns, ppp->ipcp_dns1);
                dbg("Received DNS: %s\n", my_dns);
                ppp->state = PPP_NETWORK;
                ppp_ipv4_conf(ppp);
            }
            break;
        case PICO_CONF_REQ:
            ipcp_ack(ppp, pkt, len);
            break;
        case PICO_CONF_NAK:
            ipcp_request(ppp);
            break;
        case PICO_CONF_REJ:
            ipcp_request(ppp);
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

static void ppp_process_packet(struct pico_device_ppp *ppp, uint8_t *pkt, int len) {
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
    int i;
    uint8_t *pkt = (uint8_t *)data;
    for (i = 0; i < len; i++) {
        if (pkt[i] == PPPF_CONT) {
            pkt[i] = pkt[i + 1] ^ 0x20;
            ppp_shift(pkt, i + 1, len);
            len--;
        }
    }

    if ((pkt[0] != PPPF_STARTSTOP) || (pkt[len -1] != PPPF_STARTSTOP))
        return;
    /* Remove start byte */
    pkt++; len--;
    /* Remove end byte */
    len--;
    ppp_process_packet(ppp, pkt, len);
}   

struct pico_ppp_fsm_action {
    void (*timeout)(struct pico_device_ppp *ppp);
    void (*recv)(struct pico_device_ppp *ppp, void *data, int len);
};

struct pico_ppp_fsm_action pico_ppp_fsm[PPP_MODEM_MAXSTATE] = {
      /* State                        timeout                 recv        */
    { /* PPP_MODEM_RESET   */         ppp_send_creg,          ppp_recv_creg    },
    { /* PPP_MODEM_CREG    */         ppp_send_cgreg,         ppp_recv_cgreg   },
    { /* PPP_MODEM_CGREG   */         ppp_send_cgdcont,       ppp_recv_cgdcont },
    { /* PPP_MODEM_CGDCONT */         ppp_send_cgatt,         ppp_recv_cgatt   },
    { /* PPP_MODEM_CGATT   */         ppp_dial,               ppp_recv_connect },
    { /* PPP_MODEM_CONNECT */         ppp_lcp_req,            ppp_recv_data    },
    { /* PPP_ESTABLISH     */         ppp_lcp_req,            ppp_recv_data    },
    { /* PPP_AUTH          */         NULL,                   ppp_recv_data    },
    { /* PPP_NETCONFIG     */         ppp_netconf,            ppp_recv_data    },
    { /* PPP_NETWORK       */         NULL,                   ppp_recv_data    },
    { NULL, NULL}
};



static int pico_ppp_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *) dev;
    int r;
    uint8_t *p, *endcmd, *end;
    if (ppp->serial_recv) {
        do{
            r = ppp->serial_recv(&ppp->dev, ppp_recv_buf, PPP_MAXPKT);
            if (r <= 0)
                break;
            if (ppp->state >= PPP_MODEM_CONNECT) {
                pico_ppp_fsm[ppp->state].recv(ppp, ppp_recv_buf, r);
            } else {
                p = ppp_recv_buf;
                endcmd = p + r;
                while (p < endcmd) {
                    end = p;
                    while( *end != '\r')
                        end++;
                    *end = 0;
                    if (strlen(p) > 0)
                        pico_ppp_fsm[ppp->state].recv(ppp, p, strlen(p));
                    p = end + 2;
                }
                loop_score--;
            }
        } while ((r > 0) && (loop_score > 0));
    }
    return loop_score;
}

/* Public interface: create/destroy. */

static int pico_ppp_link_state(struct pico_device *dev)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    if (ppp->state == PPP_NETWORK)
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
    strcpy(ppp->apn, "web.be");
    strcpy(ppp->password, "web");

    LCPOPT_SET_LOCAL(ppp, LCPOPT_MRU);
    LCPOPT_SET_LOCAL(ppp, LCPOPT_AUTH); /* We support authentication, even if it's not part of the req */
    LCPOPT_SET_LOCAL(ppp, LCPOPT_PROTO_COMP);
    LCPOPT_SET_LOCAL(ppp, LCPOPT_ADDRCTL_COMP);

    dbg("Device %s created.\n", ppp->dev.name);
    pico_timer_add(500, pico_ppp_tick, ppp);
    return (struct pico_device *)ppp;
}

void pico_ppp_set_serial_read(struct pico_device *dev, int (*sread)(struct pico_device *, void *, int))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    ppp->serial_recv = sread;
    

}

void pico_ppp_set_serial_write(struct pico_device *dev, int (*swrite)(struct pico_device *, const void *, int))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    ppp->serial_send = swrite;

}

void pico_ppp_set_serial_set_speed(struct pico_device *dev, int (*sspeed)(struct pico_device *, uint32_t))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    ppp->serial_set_speed = sspeed;
}
