/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_device.h"
#include "pico_dev_ppp.h"
#include "pico_stack.h"

#define PPP_MTU 476
#define PPP_MAXPKT 2048
#define PPP_MAX_APN 140
static int ppp_devnum = 0;
static uint8_t ppp_recv_buf[PPP_MAXPKT];

enum pico_ppp_state {
    PPP_MODEM_RST = 0,
    PPP_MODEM_CREG,
    PPP_MODEM_CGREG,
    PPP_MODEM_CGDCONT,
    PPP_MODEM_CGATT,
    PPP_MODEM_DIALING,
    PPP_MODEM_CONNECT,
    /* From here on, PPP states */
    PPP_ESTABLISH,
    PPP_AUTH,
    PPP_NETWORK,
    PPP_TERMINATE,
    /* MAXSTATE is the last one */
    PPP_MODEM_MAXSTATE
};

struct pico_device_ppp {
    struct pico_device dev;
    int statistics_frames_out;
    enum pico_ppp_state state;
    char apn[PPP_MAX_APN];
    int (*serial_recv)(struct pico_device *dev, void *buf, int len);
    int (*serial_send)(struct pico_device *dev, void *buf, int len);
    int (*serial_set_speed)(struct pico_device *dev, uint32_t speed);
};


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
        if (ppp->serial_set_speed)
            ppp->serial_set_speed(ppp, 0);
    }
}

void ppp_lcp_req(struct pico_device_ppp *ppp)
{
    uint8_t lcp_req[] = { 0xc0, 0x21, 0x01, 0x01, 0x00, 0x0a, 0x05, 0x06, 0xfc, 0xd4, 0x59, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    if (!ppp->serial_send)
        return;
    ppp->serial_send(&ppp->dev, lcp_req, sizeof(lcp_req));
    printf("Sent LCP request, %d bytes.\n", sizeof(lcp_req));

}

void ppp_recv_data(struct pico_device_ppp *ppp, void *data, int len)
{
    dbg("PPPDATA: Recv: %s\n", data);
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
    { NULL, NULL}
};



static int pico_ppp_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *) dev;
    IGNORE_PARAMETER(buf);
    IGNORE_PARAMETER(ppp);

    /* Discard the frame content silently. */
    return len;
}

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
    IGNORE_PARAMETER(dev);

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

    ppp->dev.overhead = 0;
    ppp->dev.mtu = PPP_MTU;
    ppp->dev.send = pico_ppp_send;
    ppp->dev.poll = pico_ppp_poll;
    ppp->dev.link_state  = pico_ppp_link_state;
    strcpy(ppp->apn, "web.be");
    dbg("Device %s created.\n", ppp->dev.name);
    pico_timer_add(500, pico_ppp_tick, ppp);
    return (struct pico_device *)ppp;
}

void pico_ppp_set_serial_read(struct pico_device *dev, int (*sread)(struct pico_device *, void *, int))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    ppp->serial_recv = sread;
    

}

void pico_ppp_set_serial_write(struct pico_device *dev, int (*swrite)(struct pico_device *, void *, int))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    ppp->serial_send = swrite;

}

void pico_ppp_set_serial_set_speed(struct pico_device *dev, int (*sspeed)(struct pico_device *, uint32_t))
{
    struct pico_device_ppp *ppp = (struct pico_device_ppp *)dev;
    ppp->serial_set_speed = sspeed;
}
