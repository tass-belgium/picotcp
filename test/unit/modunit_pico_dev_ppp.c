#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_device.h"
#include "pico_dev_ppp.h"
#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_md5.h"
#include "pico_dns_client.h"
#include "modules/pico_dev_ppp.c"
#include "check.h"

struct pico_device_ppp _ppp = {};
static enum ppp_modem_event ppp_modem_ev;
static enum ppp_lcp_event ppp_lcp_ev;
static enum ppp_auth_event ppp_auth_ev;
static enum ppp_ipcp_event ppp_ipcp_ev;

static int called_picotimer =  0;

Suite *pico_suite(void);

uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    IGNORE_PARAMETER(arg);
    IGNORE_PARAMETER(timer);
    IGNORE_PARAMETER(expire);
    called_picotimer++;
    return NULL;
}


static void modem_state(struct pico_device_ppp *ppp, enum ppp_modem_event event)
{
    IGNORE_PARAMETER(ppp);
    printf("Called MODEM FSM mock\n");
    ppp_modem_ev = event;
}
static void lcp_state(struct pico_device_ppp *ppp, enum ppp_lcp_event event)
{
    IGNORE_PARAMETER(ppp);
    printf("Called LCP FSM mock\n");
    ppp_lcp_ev = event;
}
static void auth_state(struct pico_device_ppp *ppp, enum ppp_auth_event event)
{
    IGNORE_PARAMETER(ppp);
    printf("Called AUTH FSM mock\n");
    ppp_auth_ev = event;
}
static void ipcp_state(struct pico_device_ppp *ppp, enum ppp_ipcp_event event)
{
    IGNORE_PARAMETER(ppp);
    printf("Called IPCP FSM mock\n");
    ppp_ipcp_ev = event;
}

static int called_serial_send = 0;
static uint8_t serial_out_first_char = 0;
static uint32_t serial_out_len = 0;
static uint8_t serial_buffer[64];

static int unit_serial_send(struct pico_device *dev, const void *buf, int len)
{
    IGNORE_PARAMETER(dev);
    printf("Called send function!\n");
    serial_out_len = (unsigned) len;
    if (len < 64) {
        memcpy(serial_buffer, buf, (unsigned) len);
    } else {
        memcpy(serial_buffer, buf, 64);
    }

    serial_out_first_char = *(uint8_t *)((uintptr_t)(buf));
    called_serial_send++;
    printf(" First char : %02x, len: %d\n", serial_out_first_char, serial_out_len);
    printf("  ---- %02x %02x %02x %02x %02x %02x %02x %02x\n",
           serial_buffer[0], serial_buffer[1], serial_buffer[2],
           serial_buffer[3], serial_buffer[4], serial_buffer[5],
           serial_buffer[6], serial_buffer[7]);
    return len;
}

uint8_t test_string[5][10] = {
    { 0x7e, 'a', 'b', 'c', 'd', 0x7e },
    { 0x7e, 'a', 0x7e, 'c', 'd', 0x7e },
    { 0x7e, 'a', 'b', 0x7d, 'd', 0x7e },
    { 0x7e, 0x7d, 'b', 'c', 0x7e, 0x7e },
    { 0x7e, 0xed, 0x7d, 0xff, 0x7d, 0x3F, 'c', 0x20, 0x7e }
};

uint8_t escape_string[5][12] = {
    { 0x7e, 'a', 'b', 'c', 'd', 0x7e },
    { 0x7e, 'a', 0x7d, 0x5e, 'c', 'd', 0x7e },
    { 0x7e, 'a', 'b', 0x7d, 0x5d, 'd', 0x7e },
    { 0x7e, 0x7d, 0x5d, 'b', 'c', 0x7d, 0x5e, 0x7e },
    { 0x7e, 0xed, 0x7d, 0x5d, 0xff, 0x7d, 0x5d, 0x3F, 'c', 0x20, 0x7e }
};

int test_string_len[] = {
    6, 6, 6, 6, 9
};
int escape_string_len[] = {
    6, 7, 7, 8, 11
};

START_TEST(tc_ppp_serial_send_escape)
{
    int i;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;

    for (i = 0; i < 5; i++) {
        called_serial_send = 0;
        fail_if(ppp_serial_send_escape(&_ppp, test_string[i], test_string_len[i]) != test_string_len[i]);
        fail_if(called_serial_send != 1);
        fail_if(serial_out_len != (unsigned) escape_string_len[i]);
        printf("  test string     ---- %02x %02x %02x %02x %02x %02x %02x %02x\n",
               test_string[i][0], test_string[i][1], test_string[i][2],
               test_string[i][3], test_string[i][4], test_string[i][5],
               test_string[i][6], test_string[i][7]);
        printf("  expected string ---- %02x %02x %02x %02x %02x %02x %02x %02x\n",
               escape_string[i][0], escape_string[i][1], escape_string[i][2],
               escape_string[i][3], escape_string[i][4], escape_string[i][5],
               escape_string[i][6], escape_string[i][7]);
        printf("  received string ---- %02x %02x %02x %02x %02x %02x %02x %02x\n",
               serial_buffer[0], serial_buffer[1], serial_buffer[2],
               serial_buffer[3], serial_buffer[4], serial_buffer[5],
               serial_buffer[6], serial_buffer[7]);

        fail_if(memcmp(escape_string[i], serial_buffer, serial_out_len) != 0);
    }
}
END_TEST


START_TEST(tc_lcp_timer_start)
{

    /* Reset counter, LCP REQ */
    memset(&_ppp, 0, sizeof(_ppp));
    lcp_timer_start(&_ppp, 0);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_count != 0);
    fail_if(_ppp.timer_val != PICO_PPP_DEFAULT_TIMER);

    /* LCP CONFIG REQ, Normal case */
    memset(&_ppp, 0, sizeof(_ppp));
    lcp_timer_start(&_ppp, PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_count != PICO_PPP_DEFAULT_MAX_CONFIGURE);
    fail_if(_ppp.timer_val != PICO_PPP_DEFAULT_TIMER);

    /* LCP TERMINATE REQ, Normal case */
    memset(&_ppp, 0, sizeof(_ppp));
    lcp_timer_start(&_ppp, PPP_TIMER_ON_LCPTERM);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_LCPTERM);
    fail_if(_ppp.timer_count != PICO_PPP_DEFAULT_MAX_TERMINATE);
    fail_if(_ppp.timer_val != PICO_PPP_DEFAULT_TIMER);
}
END_TEST
START_TEST(tc_lcp_zero_restart_count)
{
    /* Reset counter, LCP REQ */
    memset(&_ppp, 0, sizeof(_ppp));
    lcp_zero_restart_count(&_ppp);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_count != 0);
    fail_if(_ppp.timer_val != PICO_PPP_DEFAULT_TIMER);
}
END_TEST
START_TEST(tc_lcp_timer_stop)
{
    /* LCP CONFIG REQ, Normal case */
    memset(&_ppp, 0, sizeof(_ppp));
    lcp_timer_start(&_ppp, PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_count != PICO_PPP_DEFAULT_MAX_CONFIGURE);
    fail_if(_ppp.timer_val != PICO_PPP_DEFAULT_TIMER);
    /* Releasing timer */
    lcp_timer_stop(&_ppp, PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_on != 0);
}
END_TEST
START_TEST(tc_ppp_ctl_packet_size)
{
    uint32_t size = 10;
    uint32_t prefix = ppp_ctl_packet_size(&_ppp, 0, &size);
    fail_if(prefix != (PPP_HDR_SIZE +  PPP_PROTO_SLOT_SIZE));
    fail_if(size != (10 + prefix + PPP_FCS_SIZE + 1));
}
END_TEST
START_TEST(tc_ppp_fcs_char)
{
    char a = '*';
    uint16_t fcs;
    fcs = ppp_fcs_char(0u, (uint8_t)a);
    fail_if(fcs != 36440);
}
END_TEST
START_TEST(tc_ppp_fcs_continue)
{
    char a = '*';
    uint16_t fcs;
    fcs = ppp_fcs_continue(0, (uint8_t *) &a, 1);
    fail_if(fcs != 36440);
}
END_TEST
START_TEST(tc_ppp_fcs_finish)
{
    uint16_t fcs = 36440;
    fcs = ppp_fcs_finish(fcs);
    fail_if (fcs != 29095);
}
END_TEST
START_TEST(tc_ppp_fcs_start)
{
    uint16_t fcs;
    char s = '*';
    fcs = ppp_fcs_start((uint8_t*)&s, 1);
    fail_if(fcs != 33247);
}
END_TEST
START_TEST(tc_ppp_fcs_verify)
{
    char hello[8] = "hello";
    uint16_t fcs = ppp_fcs_start((uint8_t *)hello, 5);
    fcs = ppp_fcs_finish(fcs);
    memcpy(hello + 5, &fcs, 2);
    fail_if(0 != ppp_fcs_verify((uint8_t *)hello, 7));
    hello[0] = 'B';
    hello[1] = 'y';
    hello[2] = 'e';
    hello[3] = 'z';
    hello[4] = 'z';
    fail_if(-1 != ppp_fcs_verify((uint8_t *)hello, 7));

}
END_TEST
START_TEST(tc_pico_ppp_ctl_send)
{
    uint8_t pkt[32] = { };
    memset(&_ppp, 0, sizeof(_ppp));

    /* No serial_send associated */
    fail_if(pico_ppp_ctl_send(&_ppp.dev, 1, pkt, 30) != 30);
    fail_if(called_serial_send != 0);
    /* normal case */
    _ppp.serial_send = unit_serial_send;
    fail_if(pico_ppp_ctl_send(&_ppp.dev, 1, pkt, 30) != 30);
    fail_if(called_serial_send != 1);
    called_serial_send = 0;
    fail_if(serial_out_first_char != 0x7e);
    fail_if(serial_out_len != 30);
}
END_TEST
START_TEST(tc_pico_ppp_send)
{
    uint8_t pkt[32] = { };
    memset(&_ppp, 0, sizeof(_ppp));


    /* wrong ipcp_state */
    _ppp.serial_send = unit_serial_send;
    fail_if(pico_ppp_send(&_ppp.dev, pkt, 30) != 30);
    fail_if(called_serial_send != 0);

    /* No serial_send associated */
    _ppp.serial_send = NULL;
    _ppp.ipcp_state = PPP_IPCP_STATE_OPENED;
    fail_if(pico_ppp_send(&_ppp.dev, pkt, 30) != 30);
    fail_if(called_serial_send != 0);

    /* normal case */
    _ppp.serial_send = unit_serial_send;
    fail_if(pico_ppp_send(&_ppp.dev, pkt, 30) != 30);
    fail_if(called_serial_send != 1);
    called_serial_send = 0;
    fail_if(serial_out_first_char != 0x7e);
    fail_if(serial_out_len != 38);

    /* with LCPOPT_PROTO_COMP set */
    called_serial_send = 0;
    LCPOPT_SET_PEER((&_ppp), LCPOPT_PROTO_COMP);
    fail_if(pico_ppp_send(&_ppp.dev, pkt, 30) != 30);
    fail_if(called_serial_send != 1);
    called_serial_send = 0;
    fail_if(serial_out_first_char != 0x7e);
    fail_if(serial_out_len != 37);
    LCPOPT_UNSET_PEER((&_ppp), LCPOPT_PROTO_COMP);

    /* with LCPOPT_ADDRCTL_COMP set */
    called_serial_send = 0;
    LCPOPT_SET_PEER((&_ppp), LCPOPT_ADDRCTL_COMP);
    fail_if(pico_ppp_send(&_ppp.dev, pkt, 30) != 30);
    fail_if(called_serial_send != 1);
    called_serial_send = 0;
    fail_if(serial_out_first_char != 0x7e);
    fail_if(serial_out_len != 36);
    LCPOPT_UNSET_PEER((&_ppp), LCPOPT_ADDRCTL_COMP);

}
END_TEST
START_TEST(tc_ppp_modem_start_timer)
{
    memset(&_ppp, 0, sizeof(_ppp));
    ppp_modem_start_timer(&_ppp);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_MODEM);
    fail_if(_ppp.timer_val != PICO_PPP_DEFAULT_TIMER);
}
END_TEST
START_TEST(tc_ppp_modem_send_reset)
{
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    /* No serial send */
    ppp_modem_send_reset(&_ppp);
    fail_if(called_serial_send > 0);
    /* Normal way */
    _ppp.serial_send = unit_serial_send;
    ppp_modem_send_reset(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 5);

}
END_TEST
START_TEST(tc_ppp_modem_send_echo)
{
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    /* No serial send */
    ppp_modem_send_echo(&_ppp);
    fail_if(called_serial_send > 0);
    /* Normal way */
    _ppp.serial_send = unit_serial_send;
    ppp_modem_send_echo(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 6);
}
END_TEST
START_TEST(tc_ppp_modem_send_creg)
{
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    /* No serial send */
    ppp_modem_send_creg(&_ppp);
    fail_if(called_serial_send > 0);
    /* Normal way */
    _ppp.serial_send = unit_serial_send;
    ppp_modem_send_creg(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 11);
}
END_TEST
START_TEST(tc_ppp_modem_send_cgreg)
{
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    /* No serial send */
    ppp_modem_send_cgreg(&_ppp);
    fail_if(called_serial_send > 0);
    /* Normal way */
    _ppp.serial_send = unit_serial_send;
    ppp_modem_send_cgreg(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 12);
}
END_TEST
START_TEST(tc_ppp_modem_send_cgdcont)
{
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    /* No serial send */
    ppp_modem_send_cgdcont(&_ppp);
    fail_if(called_serial_send > 0);
    /* Normal way */
    _ppp.serial_send = unit_serial_send;
    ppp_modem_send_cgdcont(&_ppp);
    fail_if(called_serial_send != 1);
}
END_TEST
START_TEST(tc_ppp_modem_send_cgatt)
{
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    /* No serial send */
    ppp_modem_send_cgatt(&_ppp);
    fail_if(called_serial_send > 0);
    /* Normal way */
    _ppp.serial_send = unit_serial_send;
    ppp_modem_send_cgatt(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 12);
}
END_TEST
START_TEST(tc_ppp_modem_send_dial)
{
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    /* No serial send */
    ppp_modem_send_dial(&_ppp);
    fail_if(called_serial_send > 0);
    /* Normal way */
    _ppp.serial_send = unit_serial_send;
    ppp_modem_send_dial(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 13);
}
END_TEST

START_TEST(tc_ppp_modem_connected)
{
    memset(&_ppp, 0, sizeof(_ppp));
    ppp_lcp_ev = 0;
    ppp_modem_connected(&_ppp);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_UP);
}
END_TEST
START_TEST(tc_ppp_modem_disconnected)
{
    memset(&_ppp, 0, sizeof(_ppp));
    ppp_lcp_ev = 0;
    ppp_modem_disconnected(&_ppp);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_DOWN);
}
END_TEST
START_TEST(tc_ppp_modem_recv)
{
    char ok[] = "OK";
    char connect[] = "CONNECT HELLO HI THERE";
    char error[] = "ERROR";
    char blabla[] = "Blabla";
    ppp_modem_ev = 0;
    ppp_modem_recv(&_ppp, ok, strlen(ok));
    fail_if(ppp_modem_ev != PPP_MODEM_EVENT_OK);

    ppp_modem_ev = 0;
    ppp_modem_recv(&_ppp, connect, strlen(connect));
    fail_if(ppp_modem_ev != PPP_MODEM_EVENT_CONNECT);

    ppp_modem_ev = 0;
    ppp_modem_recv(&_ppp, error, strlen(error));
    fail_if(ppp_modem_ev != PPP_MODEM_EVENT_STOP);

    ppp_modem_ev = PPP_MODEM_EVENT_MAX; /* Which is basically illegal, just to check */
    ppp_modem_recv(&_ppp, blabla, 8);
    fail_if(ppp_modem_ev != PPP_MODEM_EVENT_MAX);

}
END_TEST
START_TEST(tc_lcp_send_configure_request)
{
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;

    /* With no options... */
    called_serial_send = 0;
    lcp_send_configure_request(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 12);

    /* With all the options... */
    called_serial_send = 0;
    LCPOPT_SET_LOCAL((&_ppp), LCPOPT_PROTO_COMP);
    LCPOPT_SET_LOCAL((&_ppp), LCPOPT_MRU);
    LCPOPT_SET_LOCAL((&_ppp), LCPOPT_ADDRCTL_COMP);
    lcp_send_configure_request(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 20);

    /* with a failing malloc... */
    pico_set_mm_failure(1);
    called_serial_send = 0;
    lcp_send_configure_request(&_ppp);
    fail_if(called_serial_send != 0);

}
END_TEST
START_TEST(tc_lcp_optflags)
{
    uint8_t pkt[4 + sizeof(struct pico_lcp_hdr)];
    uint8_t *p = pkt + sizeof(struct pico_lcp_hdr);
    p[0] = 0x03;
    p[1] = 0x42;
    p[2] = 0x56;
    p[3] = 0x99;
    memset(&_ppp, 0, sizeof(_ppp));
    fail_if(lcp_optflags(&_ppp, pkt, 4 + sizeof(struct pico_lcp_hdr), 1u) != 0x08);
    fail_if(_ppp.auth != 0x5699);
}
END_TEST

START_TEST(tc_lcp_send_configure_ack)
{
    uint8_t pkt[20] = "";
    struct pico_lcp_hdr *lcpreq;
    called_serial_send = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;
    _ppp.pkt = pkt;
    _ppp.len = 4;
    lcpreq = (struct pico_lcp_hdr *)_ppp.pkt;
    lcpreq->len = short_be(4);
    lcp_send_configure_ack(&_ppp);
    fail_if(called_serial_send != 1);
}
END_TEST
START_TEST(tc_lcp_send_terminate_request)
{
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;

    called_serial_send = 0;
    lcp_send_terminate_request(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 12);

}
END_TEST
START_TEST(tc_lcp_send_terminate_ack)
{
    uint8_t pkt[20] = "";
    struct pico_lcp_hdr *lcpreq;
    called_serial_send = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;
    _ppp.pkt = pkt;
    _ppp.len = 4;
    lcpreq = (struct pico_lcp_hdr *)_ppp.pkt;
    lcpreq->len = short_be(4);
    lcp_send_terminate_ack(&_ppp);
    fail_if(called_serial_send != 1);
}
END_TEST
START_TEST(tc_lcp_send_configure_nack)
{
    uint8_t pkt[20] = "";
    struct pico_lcp_hdr *lcpreq;
    called_serial_send = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;
    _ppp.pkt = pkt;
    _ppp.len = 4;
    lcpreq = (struct pico_lcp_hdr *)_ppp.pkt;
    lcpreq->len = short_be(4);
    lcp_send_configure_nack(&_ppp);
    fail_if(called_serial_send != 1);
}
END_TEST
START_TEST(tc_lcp_process_in)
{
    uint8_t pkt[64];
    called_serial_send = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;

    /* Receive ACK (RCA) */
    ppp_lcp_ev = 0;
    pkt[0] = PICO_CONF_ACK;
    lcp_process_in(&_ppp, pkt, 64);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_RCA);

    /* Receive NACK (RCN) */
    ppp_lcp_ev = 0;
    pkt[0] = PICO_CONF_NAK;
    lcp_process_in(&_ppp, pkt, 64);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_RCN);

    /* Receive REJ (RCN) */
    ppp_lcp_ev = 0;
    pkt[0] = PICO_CONF_REJ;
    lcp_process_in(&_ppp, pkt, 64);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_RCN);

    /* Receive REQ, with unwanted option field  (RCR-) */
    ppp_lcp_ev = 0;
    pkt[0] = PICO_CONF_REQ;
    pkt[sizeof(struct pico_lcp_hdr)] = 0x04;
    pkt[sizeof(struct pico_lcp_hdr) + 1] = 0x02;
    lcp_process_in(&_ppp, pkt, sizeof(struct pico_lcp_hdr) + 2);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_RCR_NEG);

    /* Receive REQ, with valid option field  (RCR+) */
    ppp_lcp_ev = 0;
    pkt[0] = PICO_CONF_REQ;
    pkt[sizeof(struct pico_lcp_hdr)] = 0x04;
    pkt[sizeof(struct pico_lcp_hdr) + 1] = 0x02;
    _ppp.lcpopt_local = (1 << 4);
    lcp_process_in(&_ppp, pkt, sizeof(struct pico_lcp_hdr) + 2);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_RCR_POS);
}
END_TEST
START_TEST(tc_pap_process_in)
{
    struct pico_pap_hdr hdr;
    memset(&_ppp, 0, sizeof(_ppp));

    /* Receive SUCCESS (RAA) */
    _ppp.auth = 0xc023;
    ppp_auth_ev = 0;
    hdr.code = PAP_AUTH_ACK;
    pap_process_in(&_ppp,  (uint8_t *)&hdr, sizeof(hdr));
    fail_if (ppp_auth_ev != PPP_AUTH_EVENT_RAA);

    /* Receive FAILURE (RAN) */
    ppp_auth_ev = 0;
    hdr.code = PAP_AUTH_NAK;
    pap_process_in(&_ppp,  (uint8_t *)&hdr, sizeof(hdr));
    fail_if (ppp_auth_ev != PPP_AUTH_EVENT_RAN);
}
END_TEST
START_TEST(tc_chap_process_in)
{
    struct pico_chap_hdr hdr;
    memset(&_ppp, 0, sizeof(_ppp));

    /* Receive challenge (RAC) */
    ppp_auth_ev = 0;
    _ppp.auth = 0xc223;
    hdr.code = CHAP_CHALLENGE;
    chap_process_in(&_ppp,  (uint8_t *)&hdr, sizeof(hdr));
    fail_if (ppp_auth_ev != PPP_AUTH_EVENT_RAC);

    /* Receive SUCCESS (RAA) */
    ppp_auth_ev = 0;
    hdr.code = CHAP_SUCCESS;
    chap_process_in(&_ppp,  (uint8_t *)&hdr, sizeof(hdr));
    fail_if (ppp_auth_ev != PPP_AUTH_EVENT_RAA);

    /* Receive FAILURE (RAN) */
    ppp_auth_ev = 0;
    hdr.code = CHAP_FAILURE;
    chap_process_in(&_ppp, (uint8_t *)&hdr, sizeof(hdr));
    fail_if (ppp_auth_ev != PPP_AUTH_EVENT_RAN);

}
END_TEST

START_TEST(tc_ipcp_ack)
{
    /* TODO: test this: static void ipcp_ack(struct pico_device_ppp *ppp, uint8_t *pkt, uint32_t len) */
    uint8_t pkt[20] = "";
    struct pico_ipcp_hdr *ipcp;
    called_serial_send = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;
    _ppp.pkt = pkt;
    _ppp.len = 4;
    ipcp = (struct pico_ipcp_hdr *)_ppp.pkt;
    ipcp->len = short_be(4);
    ipcp_send_ack(&_ppp);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 12);

}
END_TEST
START_TEST(tc_uint32_t)
{
    memset(&_ppp, 0, sizeof(_ppp));
    fail_if(ipcp_request_options_size(&_ppp) != 3 * IPCP_ADDR_LEN);

    _ppp.ipcp_nbns1 = 1;
    fail_if(ipcp_request_options_size(&_ppp) != 4 * IPCP_ADDR_LEN);

    _ppp.ipcp_nbns2 = 1;
    fail_if(ipcp_request_options_size(&_ppp) != 5 * IPCP_ADDR_LEN);

}
END_TEST
START_TEST(tc_ipcp_request_add_address)
{
    uint8_t dst[6];
    ipcp_request_add_address(dst, 0x42, 0xDDCCBBAA);
    fail_if(dst[0] != 0x42);
    fail_if(dst[1] != IPCP_ADDR_LEN);
    fail_if(dst[2] != 0xAA);
    fail_if(dst[3] != 0xBB);
    fail_if(dst[4] != 0xCC);
    fail_if(dst[5] != 0xDD);
}
END_TEST

START_TEST(tc_ipcp_request_fill)
{

    uint8_t opts[5 * IPCP_ADDR_LEN];
    memset(&_ppp, 0, sizeof(_ppp));

    _ppp.ipcp_allowed_fields = 0xffff;
    ipcp_request_fill(&_ppp, opts);
    fail_if(opts[0] != IPCP_OPT_IP);
    fail_if(opts[6] != IPCP_OPT_DNS1);
    fail_if(opts[12] != IPCP_OPT_DNS2);

    _ppp.ipcp_nbns1 = 1;
    ipcp_request_fill(&_ppp, opts);
    fail_if(opts[0] != IPCP_OPT_IP);
    fail_if(opts[6] != IPCP_OPT_DNS1);
    fail_if(opts[12] != IPCP_OPT_DNS2);
    fail_if(opts[18] != IPCP_OPT_NBNS1);

    _ppp.ipcp_nbns2 = 1;
    ipcp_request_fill(&_ppp, opts);
    fail_if(opts[0] != IPCP_OPT_IP);
    fail_if(opts[6] != IPCP_OPT_DNS1);
    fail_if(opts[12] != IPCP_OPT_DNS2);
    fail_if(opts[18] != IPCP_OPT_NBNS1);
    fail_if(opts[24] != IPCP_OPT_NBNS2);
}
END_TEST
START_TEST(tc_ipcp_send_req)
{
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;

    /* With no options... */
    called_serial_send = 0;
    ipcp_send_req(&_ppp);
    fail_if(called_serial_send != 1);
}
END_TEST

START_TEST(tc_ipcp_reject_vj)
{
    /* TODO: test this: static void ipcp_reject_vj(struct pico_device_ppp *ppp, uint8_t *comp_req) */
    uint8_t buf[IPCP_OPT_VJ + sizeof(struct pico_ipcp_hdr)] = { };
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;
    called_serial_send = 0;
    ipcp_reject_vj(&_ppp, buf);
    fail_if(called_serial_send != 1);
    fail_if(serial_out_len != 18);
}
END_TEST
START_TEST(tc_ppp_ipv4_conf)
{
    /* TODO: test this: static void ppp_ipv4_conf(struct pico_device_ppp *ppp) */
    /* This test needs an actual device */
}
END_TEST

START_TEST(tc_ipcp_process_in)
{
    /* TODO: test this: static void ipcp_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, uint32_t len) */
    uint8_t req[sizeof(struct pico_ipcp_hdr) + 5 * IPCP_ADDR_LEN];
    uint8_t *p = req + sizeof(struct pico_ipcp_hdr);
    ;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;

    /* * * ACK * * */
    req[0] = PICO_CONF_ACK;

    /* Fill addresses */
    *(p++) = IPCP_OPT_IP;
    *(p++) = IPCP_ADDR_LEN;
    *(((uint32_t*)p)) = 0x11223344;
    p += sizeof(uint32_t);

    *(p++) = IPCP_OPT_DNS1;
    *(p++) = IPCP_ADDR_LEN;
    *(((uint32_t*)p)) = 0x55667788;
    p += sizeof(uint32_t);

    *(p++) = IPCP_OPT_NBNS1;
    *(p++) = IPCP_ADDR_LEN;
    *(((uint32_t*)p)) = 0x99AABBCC;
    p += sizeof(uint32_t);

    *(p++) = IPCP_OPT_DNS2;
    *(p++) = IPCP_ADDR_LEN;
    *(((uint32_t*)p)) = 0xDDEEFF00;
    p += sizeof(uint32_t);

    *(p++) = IPCP_OPT_NBNS2;
    *(p++) = IPCP_ADDR_LEN;
    *(((uint32_t*)p)) = 0x11223344;
    p += sizeof(uint32_t);

    ppp_ipcp_ev = 0;
    ipcp_process_in(&_ppp, req, sizeof(req));
    fail_if(ppp_ipcp_ev != PPP_IPCP_EVENT_RCA);
    fail_if(_ppp.ipcp_ip     != 0x11223344);
    fail_if(_ppp.ipcp_dns1   != 0x55667788);
    fail_if(_ppp.ipcp_nbns1  != 0x99aabbcc);
    fail_if(_ppp.ipcp_dns2   != 0xddeeff00);
    fail_if(_ppp.ipcp_nbns2  != 0x11223344);

    /* Get a VJ reject ! */
    ppp_ipcp_ev = 0;
    called_serial_send = 0;
    p = req + sizeof(struct pico_ipcp_hdr);
    *(p++) = IPCP_OPT_VJ;
    *(p++) = IPCP_VJ_LEN;
    *(((uint32_t*)p)) = 0x1;
    ipcp_process_in(&_ppp, req, sizeof(struct pico_ipcp_hdr) + IPCP_VJ_LEN);
    fail_if(called_serial_send != 1);
    fail_if(ppp_ipcp_ev != 0);

    /* * * REQ * * */
    ppp_ipcp_ev = 0;
    req[0] = PICO_CONF_REQ;
    ipcp_process_in(&_ppp, req, sizeof(struct pico_ipcp_hdr));
    fail_if(ppp_ipcp_ev != PPP_IPCP_EVENT_RCR_POS);

    /* * * NAK * * */
    ppp_ipcp_ev = 0;
    req[0] = PICO_CONF_NAK;
    ipcp_process_in(&_ppp, req, sizeof(struct pico_ipcp_hdr));
    fail_if(ppp_ipcp_ev != PPP_IPCP_EVENT_RCN);

    /* * * REJ * * */
    ppp_ipcp_ev = 0;
    req[0] = PICO_CONF_REJ;
    ipcp_process_in(&_ppp, req, sizeof(struct pico_ipcp_hdr));
    fail_if(ppp_ipcp_ev != PPP_IPCP_EVENT_RCN);

}
END_TEST

START_TEST(tc_ipcp6_process_in)
{
    /* TODO: test this: static void ipcp6_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, uint32_t len) */
    /* When implemented, do... */
    uint8_t req[sizeof(struct pico_ipcp_hdr)];
    ppp_ipcp_ev = 0;
    req[0] = PICO_CONF_REJ;
    ipcp6_process_in(&_ppp, req, sizeof(struct pico_ipcp_hdr));
    fail_if(ppp_ipcp_ev != 0);
}
END_TEST

START_TEST(tc_ppp_process_packet_payload)
{
    /* Empty, tested with ppp_process_packet, below. */
}
END_TEST
START_TEST(tc_ppp_process_packet)
{
    /* Empty, tested with ppp_recv_data, below. */
}
END_TEST
START_TEST(tc_ppp_recv_data)
{
    uint8_t pkt[20] = "";
    struct pico_lcp_hdr *lcpreq;

    /* This creates an LCP ack */
    printf("Unit test: Packet forgery. Creating LCP ACK... \n");
    called_serial_send = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;
    _ppp.pkt = pkt;
    _ppp.len = 4;
    lcpreq = (struct pico_lcp_hdr *)_ppp.pkt;
    lcpreq->len = short_be(4);
    lcp_send_configure_ack(&_ppp);
    fail_if(called_serial_send != 1);
    /* LCP ack is now in the buffer, and can be processed */
    printf("Unit test: Packet forgery. Injecting LCP ACK... \n");
    ppp_lcp_ev = 0;
    ppp_recv_data(&_ppp, serial_buffer + 1, serial_out_len - 2);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_RCA);
    printf("OK!\n");
    /* TODO: Increase coverage. */
}
END_TEST

START_TEST(tc_lcp_this_layer_up)
{
    /* TODO: test this: static void lcp_this_layer_up(struct pico_device_ppp *ppp) */
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;

    ppp_auth_ev = 0;
    lcp_this_layer_up(&_ppp);
    fail_if(ppp_auth_ev != PPP_AUTH_EVENT_UP_NONE);

    ppp_auth_ev = 0;
    _ppp.auth = 0xc023;
    lcp_this_layer_up(&_ppp);
    fail_if(ppp_auth_ev != PPP_AUTH_EVENT_UP_PAP);

    ppp_auth_ev = 0;
    _ppp.auth = 0xc223;
    lcp_this_layer_up(&_ppp);
    fail_if(ppp_auth_ev != PPP_AUTH_EVENT_UP_CHAP);

    ppp_auth_ev = 0;
    _ppp.auth = 0xfefe;
    lcp_this_layer_up(&_ppp);
    fail_if(ppp_auth_ev != 0);
}
END_TEST
START_TEST(tc_lcp_this_layer_down)
{
    ppp_auth_ev = 0;
    lcp_this_layer_down(&_ppp);
    fail_if(ppp_auth_ev != PPP_AUTH_EVENT_DOWN);
}
END_TEST
START_TEST(tc_lcp_this_layer_started)
{
    ppp_modem_ev = 0;
    lcp_this_layer_started(&_ppp);
    fail_if(ppp_modem_ev != PPP_MODEM_EVENT_START);
}
END_TEST
START_TEST(tc_lcp_this_layer_finished)
{
    ppp_modem_ev = 0;
    lcp_this_layer_finished(&_ppp);
    fail_if(ppp_modem_ev != PPP_MODEM_EVENT_STOP);
}
END_TEST
START_TEST(tc_lcp_initialize_restart_count)
{
    /* TODO: test this: static void lcp_initialize_restart_count(struct pico_device_ppp *ppp) */
    memset(&_ppp, 0, sizeof(_ppp));
    lcp_initialize_restart_count(&_ppp);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_LCPREQ);
    fail_if(_ppp.timer_count != PICO_PPP_DEFAULT_MAX_CONFIGURE);
    fail_if(_ppp.timer_val != PICO_PPP_DEFAULT_TIMER);
}
END_TEST
START_TEST(tc_lcp_send_code_reject)
{
    /* TODO: test this: static void lcp_send_code_reject(struct pico_device_ppp *ppp) */
    lcp_send_code_reject(&_ppp);
}
END_TEST
START_TEST(tc_lcp_send_echo_reply)
{
    uint8_t pkt[20] = "";
    struct pico_lcp_hdr *lcpreq;
    called_serial_send = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    _ppp.serial_send = unit_serial_send;
    _ppp.pkt = pkt;
    _ppp.len = 4;
    lcpreq = (struct pico_lcp_hdr *)_ppp.pkt;
    lcpreq->len = short_be(4);
    lcp_send_echo_reply(&_ppp);
    fail_if(called_serial_send != 1);
}
END_TEST
START_TEST(tc_auth)
{
    ppp_ipcp_ev = 0;
    auth(&_ppp);
    fail_if(ppp_ipcp_ev != PPP_IPCP_EVENT_UP);
}
END_TEST
START_TEST(tc_deauth)
{
    ppp_ipcp_ev = 0;
    deauth(&_ppp);
    fail_if(ppp_ipcp_ev != PPP_IPCP_EVENT_DOWN);
}
END_TEST
START_TEST(tc_auth_req)
{
    auth_req(&_ppp);
}
END_TEST
START_TEST(tc_auth_rsp)
{
    uint8_t req[sizeof(struct pico_chap_hdr) + 1 + CHAP_MD5_SIZE] = { 0 }; // 21 bytes
    struct pico_chap_hdr *hdr = (struct pico_chap_hdr *)req;
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    _ppp.serial_send = unit_serial_send;

    _ppp.auth = 0xc223; /* hardcode CHAP */
    hdr->code = CHAP_CHALLENGE;
    hdr->len = short_be((uint16_t)(sizeof (struct pico_chap_hdr) + CHAP_MD5_SIZE));
    req[sizeof(struct pico_chap_hdr)] = CHAP_MD5_SIZE; // CHAP value size field
    _ppp.pkt = req;
    _ppp.len = sizeof(struct pico_chap_hdr) + CHAP_MD5_SIZE;
    auth_rsp(&_ppp);
    fail_if(called_serial_send != 1);
    printf("OK!\n");

}
END_TEST
START_TEST(tc_auth_start_timer)
{
    memset(&_ppp, 0, sizeof(_ppp));
    auth_start_timer(&_ppp);
    fail_if(_ppp.timer_on != PPP_TIMER_ON_AUTH);

}
END_TEST
START_TEST(tc_ipcp_send_ack)
{
    uint8_t req[sizeof(struct pico_chap_hdr) + 4 ];
    struct pico_ipcp_hdr *hdr = (struct pico_ipcp_hdr *)req;
    memset(&_ppp, 0, sizeof(_ppp));
    called_serial_send = 0;
    _ppp.serial_send = unit_serial_send;
    hdr->code = PICO_CONF_REQ;
    hdr->len = short_be((uint16_t)(sizeof (struct pico_ipcp_hdr) + 4));
    _ppp.pkt = req;
    _ppp.len = sizeof(struct pico_chap_hdr) + 4;
    ipcp_send_ack(&_ppp);
    fail_if(called_serial_send != 1);
    printf("OK!\n");
}
END_TEST
START_TEST(tc_ipcp_send_nack)
{
    ipcp_send_nack(&_ppp);
}
END_TEST
START_TEST(tc_ipcp_bring_up)
{
    memset(&_ppp, 0, sizeof(_ppp));
    /* without address */
    ipcp_bring_up(&_ppp);

    /* with address */
    _ppp.ipcp_ip = 0xAABBCCDD;
    ipcp_bring_up(&_ppp);
}
END_TEST
START_TEST(tc_ipcp_bring_down)
{
    /* TODO: test this: static void ipcp_bring_down(struct pico_device_ppp *ppp) */
    ipcp_bring_down(&_ppp);
}
END_TEST
START_TEST(tc_ipcp_start_timer)
{
    memset(&_ppp, 0, sizeof(_ppp));
    ipcp_start_timer(&_ppp);
    fail_if (_ppp.timer_on != PPP_TIMER_ON_IPCP);
    fail_if (_ppp.timer_val != PICO_PPP_DEFAULT_TIMER * PICO_PPP_DEFAULT_MAX_FAILURE);
}
END_TEST
START_TEST(tc_pico_ppp_poll)
{
    /* TODO: test this: static int pico_ppp_poll(struct pico_device *dev, int loop_score) */
}
END_TEST
START_TEST(tc_pico_ppp_link_state)
{
    memset(&_ppp, 0, sizeof(_ppp));
    fail_if(pico_ppp_link_state(&_ppp.dev) != 0);
    _ppp.ipcp_state = PPP_IPCP_STATE_OPENED;
    fail_if(pico_ppp_link_state(&_ppp.dev) == 0);
}
END_TEST
START_TEST(tc_check_to_modem)
{
    ppp_modem_ev = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    /* No timer on ... */
    check_to_modem(&_ppp);
    fail_if(ppp_modem_ev != 0);

    /* Timer set to 1 */
    _ppp.timer_on = PPP_TIMER_ON_MODEM;
    _ppp.timer_val = 1;
    check_to_modem(&_ppp);
    fail_if(ppp_modem_ev != 0);
    _ppp.timer_val--;
    /* Timer expired */
    check_to_modem(&_ppp);
    printf("Modem event: %02x\n", ppp_modem_ev);
    fail_if(ppp_modem_ev != PPP_MODEM_EVENT_TIMEOUT);

}
END_TEST
START_TEST(tc_check_to_lcp)
{
    ppp_lcp_ev = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    /* No timer on ... */
    check_to_lcp(&_ppp);
    fail_if(ppp_lcp_ev != 0);

    /* Count set to 1 */
    _ppp.timer_count = 1;

    /* Timer set to 1 */
    _ppp.timer_on = PPP_TIMER_ON_LCPTERM;
    _ppp.timer_val = 1;
    check_to_lcp(&_ppp);
    fail_if(ppp_lcp_ev != 0);
    _ppp.timer_val--;
    /* Timer expired */
    check_to_lcp(&_ppp);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_TO_POS);

    /* Timer set to 1 */
    ppp_lcp_ev = 0;
    _ppp.timer_on = PPP_TIMER_ON_LCPREQ;
    _ppp.timer_val = 1;
    check_to_lcp(&_ppp);
    fail_if(ppp_lcp_ev != 0);
    _ppp.timer_val--;
    /* Timer expired */
    check_to_lcp(&_ppp);
    fail_if(ppp_lcp_ev != PPP_LCP_EVENT_TO_NEG);
}
END_TEST
START_TEST(tc_check_to_auth)
{
    /* TODO: test this: static void check_to_auth(struct pico_device_ppp *ppp) */
    ppp_auth_ev = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    /* No timer on ... */
    check_to_auth(&_ppp);
    fail_if(ppp_auth_ev != 0);

    /* Timer set to 1 */
    _ppp.timer_on = PPP_TIMER_ON_AUTH;
    _ppp.timer_val = 1;
    check_to_auth(&_ppp);
    fail_if(ppp_auth_ev != 0);
    /* Timer expired */
    _ppp.timer_val--;
    check_to_auth(&_ppp);
    fail_if(ppp_auth_ev != PPP_AUTH_EVENT_TO);
}
END_TEST
START_TEST(tc_check_to_ipcp)
{
    ppp_ipcp_ev = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    /* No timer on ... */
    check_to_ipcp(&_ppp);
    fail_if(ppp_ipcp_ev != 0);

    /* Timer set to 1 */
    _ppp.timer_on = PPP_TIMER_ON_IPCP;
    _ppp.timer_val = 1;
    check_to_ipcp(&_ppp);
    fail_if(ppp_ipcp_ev != 0);
    /* Timer expired */
    _ppp.timer_val--;
    check_to_ipcp(&_ppp);
    fail_if(ppp_ipcp_ev != PPP_IPCP_EVENT_TO);
}
END_TEST

START_TEST(tc_pico_ppp_tick)
{
    called_picotimer = 0;
    memset(&_ppp, 0, sizeof(_ppp));
    pico_ppp_tick(0, &_ppp);
    fail_if(called_picotimer != 1);
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_ppp_serial_send_escape = tcase_create("Unit test for ppp_serial_send_escape");
    TCase *TCase_lcp_timer_start = tcase_create("Unit test for lcp_timer_start");
    TCase *TCase_lcp_zero_restart_count = tcase_create("Unit test for lcp_zero_restart_count");
    TCase *TCase_lcp_timer_stop = tcase_create("Unit test for lcp_timer_stop");
    TCase *TCase_ppp_ctl_packet_size = tcase_create("Unit test for ppp_ctl_packet_size");
    TCase *TCase_ppp_fcs_char = tcase_create("Unit test for ppp_fcs_char");
    TCase *TCase_ppp_fcs_continue = tcase_create("Unit test for ppp_fcs_continue");
    TCase *TCase_ppp_fcs_finish = tcase_create("Unit test for ppp_fcs_finish");
    TCase *TCase_ppp_fcs_start = tcase_create("Unit test for ppp_fcs_start");
    TCase *TCase_ppp_fcs_verify = tcase_create("Unit test for ppp_fcs_verify");
    TCase *TCase_pico_ppp_ctl_send = tcase_create("Unit test for pico_ppp_ctl_send");
    TCase *TCase_pico_ppp_send = tcase_create("Unit test for pico_ppp_send");
    TCase *TCase_ppp_modem_start_timer = tcase_create("Unit test for ppp_modem_start_timer");
    TCase *TCase_ppp_modem_send_reset = tcase_create("Unit test for ppp_modem_send_reset");
    TCase *TCase_ppp_modem_send_echo = tcase_create("Unit test for ppp_modem_send_echo");
    TCase *TCase_ppp_modem_send_creg = tcase_create("Unit test for ppp_modem_send_creg");
    TCase *TCase_ppp_modem_send_cgreg = tcase_create("Unit test for ppp_modem_send_cgreg");
    TCase *TCase_ppp_modem_send_cgdcont = tcase_create("Unit test for ppp_modem_send_cgdcont");
    TCase *TCase_ppp_modem_send_cgatt = tcase_create("Unit test for ppp_modem_send_cgatt");
    TCase *TCase_ppp_modem_send_dial = tcase_create("Unit test for ppp_modem_send_dial");
    TCase *TCase_ppp_modem_connected = tcase_create("Unit test for ppp_modem_connected");
    TCase *TCase_ppp_modem_disconnected = tcase_create("Unit test for ppp_modem_disconnected");
    TCase *TCase_ppp_modem_recv = tcase_create("Unit test for ppp_modem_recv");
    TCase *TCase_lcp_send_configure_request = tcase_create("Unit test for lcp_send_configure_request");
    TCase *TCase_lcp_optflags = tcase_create("Unit test for lcp_optflags");
    TCase *TCase_lcp_send_configure_ack = tcase_create("Unit test for lcp_send_configure_ack");
    TCase *TCase_lcp_send_terminate_request = tcase_create("Unit test for lcp_send_terminate_request");
    TCase *TCase_lcp_send_terminate_ack = tcase_create("Unit test for lcp_send_terminate_ack");
    TCase *TCase_lcp_send_configure_nack = tcase_create("Unit test for lcp_send_configure_nack");
    TCase *TCase_lcp_process_in = tcase_create("Unit test for lcp_process_in");
    TCase *TCase_pap_process_in = tcase_create("Unit test for pap_process_in");
    TCase *TCase_chap_process_in = tcase_create("Unit test for chap_process_in");
    TCase *TCase_ipcp_ack = tcase_create("Unit test for ipcp_ack");
    TCase *TCase_uint32_t = tcase_create("Unit test for uint32_t");
    TCase *TCase_ipcp_request_add_address = tcase_create("Unit test for ipcp_request_add_address");
    TCase *TCase_ipcp_request_fill = tcase_create("Unit test for ipcp_request_fill");
    TCase *TCase_ipcp_send_req = tcase_create("Unit test for ipcp_send_req");
    TCase *TCase_ipcp_reject_vj = tcase_create("Unit test for ipcp_reject_vj");
    TCase *TCase_ppp_ipv4_conf = tcase_create("Unit test for ppp_ipv4_conf");
    TCase *TCase_ipcp_process_in = tcase_create("Unit test for ipcp_process_in");
    TCase *TCase_ipcp6_process_in = tcase_create("Unit test for ipcp6_process_in");
    TCase *TCase_ppp_process_packet_payload = tcase_create("Unit test for ppp_process_packet_payload");
    TCase *TCase_ppp_process_packet = tcase_create("Unit test for ppp_process_packet");
    TCase *TCase_ppp_recv_data = tcase_create("Unit test for ppp_recv_data");
    TCase *TCase_lcp_this_layer_up = tcase_create("Unit test for lcp_this_layer_up");
    TCase *TCase_lcp_this_layer_down = tcase_create("Unit test for lcp_this_layer_down");
    TCase *TCase_lcp_this_layer_started = tcase_create("Unit test for lcp_this_layer_started");
    TCase *TCase_lcp_this_layer_finished = tcase_create("Unit test for lcp_this_layer_finished");
    TCase *TCase_lcp_initialize_restart_count = tcase_create("Unit test for lcp_initialize_restart_count");
    TCase *TCase_lcp_send_code_reject = tcase_create("Unit test for lcp_send_code_reject");
    TCase *TCase_lcp_send_echo_reply = tcase_create("Unit test for lcp_send_echo_reply");
    TCase *TCase_auth = tcase_create("Unit test for auth");
    TCase *TCase_deauth = tcase_create("Unit test for deauth");
    TCase *TCase_auth_req = tcase_create("Unit test for auth_req");
    TCase *TCase_auth_rsp = tcase_create("Unit test for auth_rsp");
    TCase *TCase_auth_start_timer = tcase_create("Unit test for auth_start_timer");
    TCase *TCase_ipcp_send_ack = tcase_create("Unit test for ipcp_send_ack");
    TCase *TCase_ipcp_send_nack = tcase_create("Unit test for ipcp_send_nack");
    TCase *TCase_ipcp_bring_up = tcase_create("Unit test for ipcp_bring_up");
    TCase *TCase_ipcp_bring_down = tcase_create("Unit test for ipcp_bring_down");
    TCase *TCase_ipcp_start_timer = tcase_create("Unit test for ipcp_start_timer");
    TCase *TCase_pico_ppp_poll = tcase_create("Unit test for pico_ppp_poll");
    TCase *TCase_pico_ppp_link_state = tcase_create("Unit test for pico_ppp_link_state");
    TCase *TCase_check_to_modem = tcase_create("Unit test for check_to_modem");
    TCase *TCase_check_to_lcp = tcase_create("Unit test for check_to_lcp");
    TCase *TCase_check_to_auth = tcase_create("Unit test for check_to_auth");
    TCase *TCase_check_to_ipcp = tcase_create("Unit test for check_to_ipcp");
    TCase *TCase_pico_ppp_tick = tcase_create("Unit test for pico_ppp_tick");


    tcase_add_test(TCase_ppp_serial_send_escape, tc_ppp_serial_send_escape);
    suite_add_tcase(s, TCase_ppp_serial_send_escape);
    tcase_add_test(TCase_lcp_timer_start, tc_lcp_timer_start);
    suite_add_tcase(s, TCase_lcp_timer_start);
    tcase_add_test(TCase_lcp_zero_restart_count, tc_lcp_zero_restart_count);
    suite_add_tcase(s, TCase_lcp_zero_restart_count);
    tcase_add_test(TCase_lcp_timer_stop, tc_lcp_timer_stop);
    suite_add_tcase(s, TCase_lcp_timer_stop);
    tcase_add_test(TCase_ppp_ctl_packet_size, tc_ppp_ctl_packet_size);
    suite_add_tcase(s, TCase_ppp_ctl_packet_size);
    tcase_add_test(TCase_ppp_fcs_char, tc_ppp_fcs_char);
    suite_add_tcase(s, TCase_ppp_fcs_char);
    tcase_add_test(TCase_ppp_fcs_continue, tc_ppp_fcs_continue);
    suite_add_tcase(s, TCase_ppp_fcs_continue);
    tcase_add_test(TCase_ppp_fcs_finish, tc_ppp_fcs_finish);
    suite_add_tcase(s, TCase_ppp_fcs_finish);
    tcase_add_test(TCase_ppp_fcs_start, tc_ppp_fcs_start);
    suite_add_tcase(s, TCase_ppp_fcs_start);
    tcase_add_test(TCase_ppp_fcs_verify, tc_ppp_fcs_verify);
    suite_add_tcase(s, TCase_ppp_fcs_verify);
    tcase_add_test(TCase_pico_ppp_ctl_send, tc_pico_ppp_ctl_send);
    suite_add_tcase(s, TCase_pico_ppp_ctl_send);
    tcase_add_test(TCase_pico_ppp_send, tc_pico_ppp_send);
    suite_add_tcase(s, TCase_pico_ppp_send);
    tcase_add_test(TCase_ppp_modem_start_timer, tc_ppp_modem_start_timer);
    suite_add_tcase(s, TCase_ppp_modem_start_timer);
    tcase_add_test(TCase_ppp_modem_send_reset, tc_ppp_modem_send_reset);
    suite_add_tcase(s, TCase_ppp_modem_send_reset);
    tcase_add_test(TCase_ppp_modem_send_echo, tc_ppp_modem_send_echo);
    suite_add_tcase(s, TCase_ppp_modem_send_echo);
    tcase_add_test(TCase_ppp_modem_send_creg, tc_ppp_modem_send_creg);
    suite_add_tcase(s, TCase_ppp_modem_send_creg);
    tcase_add_test(TCase_ppp_modem_send_cgreg, tc_ppp_modem_send_cgreg);
    suite_add_tcase(s, TCase_ppp_modem_send_cgreg);
    tcase_add_test(TCase_ppp_modem_send_cgdcont, tc_ppp_modem_send_cgdcont);
    suite_add_tcase(s, TCase_ppp_modem_send_cgdcont);
    tcase_add_test(TCase_ppp_modem_send_cgatt, tc_ppp_modem_send_cgatt);
    suite_add_tcase(s, TCase_ppp_modem_send_cgatt);
    tcase_add_test(TCase_ppp_modem_send_dial, tc_ppp_modem_send_dial);
    suite_add_tcase(s, TCase_ppp_modem_send_dial);
    tcase_add_test(TCase_ppp_modem_connected, tc_ppp_modem_connected);
    suite_add_tcase(s, TCase_ppp_modem_connected);
    tcase_add_test(TCase_ppp_modem_disconnected, tc_ppp_modem_disconnected);
    suite_add_tcase(s, TCase_ppp_modem_disconnected);
    tcase_add_test(TCase_ppp_modem_recv, tc_ppp_modem_recv);
    suite_add_tcase(s, TCase_ppp_modem_recv);
    tcase_add_test(TCase_lcp_send_configure_request, tc_lcp_send_configure_request);
    suite_add_tcase(s, TCase_lcp_send_configure_request);
    tcase_add_test(TCase_lcp_optflags, tc_lcp_optflags);
    suite_add_tcase(s, TCase_lcp_optflags);
    tcase_add_test(TCase_lcp_send_configure_ack, tc_lcp_send_configure_ack);
    suite_add_tcase(s, TCase_lcp_send_configure_ack);
    tcase_add_test(TCase_lcp_send_terminate_request, tc_lcp_send_terminate_request);
    suite_add_tcase(s, TCase_lcp_send_terminate_request);
    tcase_add_test(TCase_lcp_send_terminate_ack, tc_lcp_send_terminate_ack);
    suite_add_tcase(s, TCase_lcp_send_terminate_ack);
    tcase_add_test(TCase_lcp_send_configure_nack, tc_lcp_send_configure_nack);
    suite_add_tcase(s, TCase_lcp_send_configure_nack);
    tcase_add_test(TCase_lcp_process_in, tc_lcp_process_in);
    suite_add_tcase(s, TCase_lcp_process_in);
    tcase_add_test(TCase_pap_process_in, tc_pap_process_in);
    suite_add_tcase(s, TCase_pap_process_in);
    tcase_add_test(TCase_chap_process_in, tc_chap_process_in);
    suite_add_tcase(s, TCase_chap_process_in);
    tcase_add_test(TCase_ipcp_ack, tc_ipcp_ack);
    suite_add_tcase(s, TCase_ipcp_ack);
    tcase_add_test(TCase_uint32_t, tc_uint32_t);
    suite_add_tcase(s, TCase_uint32_t);
    tcase_add_test(TCase_ipcp_request_add_address, tc_ipcp_request_add_address);
    suite_add_tcase(s, TCase_ipcp_request_add_address);
    tcase_add_test(TCase_ipcp_request_fill, tc_ipcp_request_fill);
    suite_add_tcase(s, TCase_ipcp_request_fill);
    tcase_add_test(TCase_ipcp_send_req, tc_ipcp_send_req);
    suite_add_tcase(s, TCase_ipcp_send_req);
    tcase_add_test(TCase_ipcp_reject_vj, tc_ipcp_reject_vj);
    suite_add_tcase(s, TCase_ipcp_reject_vj);
    tcase_add_test(TCase_ppp_ipv4_conf, tc_ppp_ipv4_conf);
    suite_add_tcase(s, TCase_ppp_ipv4_conf);
    tcase_add_test(TCase_ipcp_process_in, tc_ipcp_process_in);
    suite_add_tcase(s, TCase_ipcp_process_in);
    tcase_add_test(TCase_ipcp6_process_in, tc_ipcp6_process_in);
    suite_add_tcase(s, TCase_ipcp6_process_in);
    tcase_add_test(TCase_ppp_process_packet_payload, tc_ppp_process_packet_payload);
    suite_add_tcase(s, TCase_ppp_process_packet_payload);
    tcase_add_test(TCase_ppp_process_packet, tc_ppp_process_packet);
    suite_add_tcase(s, TCase_ppp_process_packet);
    tcase_add_test(TCase_ppp_recv_data, tc_ppp_recv_data);
    suite_add_tcase(s, TCase_ppp_recv_data);
    tcase_add_test(TCase_lcp_this_layer_up, tc_lcp_this_layer_up);
    suite_add_tcase(s, TCase_lcp_this_layer_up);
    tcase_add_test(TCase_lcp_this_layer_down, tc_lcp_this_layer_down);
    suite_add_tcase(s, TCase_lcp_this_layer_down);
    tcase_add_test(TCase_lcp_this_layer_started, tc_lcp_this_layer_started);
    suite_add_tcase(s, TCase_lcp_this_layer_started);
    tcase_add_test(TCase_lcp_this_layer_finished, tc_lcp_this_layer_finished);
    suite_add_tcase(s, TCase_lcp_this_layer_finished);
    tcase_add_test(TCase_lcp_initialize_restart_count, tc_lcp_initialize_restart_count);
    suite_add_tcase(s, TCase_lcp_initialize_restart_count);
    tcase_add_test(TCase_lcp_send_code_reject, tc_lcp_send_code_reject);
    suite_add_tcase(s, TCase_lcp_send_code_reject);
    tcase_add_test(TCase_lcp_send_echo_reply, tc_lcp_send_echo_reply);
    suite_add_tcase(s, TCase_lcp_send_echo_reply);
    tcase_add_test(TCase_auth, tc_auth);
    suite_add_tcase(s, TCase_auth);
    tcase_add_test(TCase_deauth, tc_deauth);
    suite_add_tcase(s, TCase_deauth);
    tcase_add_test(TCase_auth_req, tc_auth_req);
    suite_add_tcase(s, TCase_auth_req);
    tcase_add_test(TCase_auth_rsp, tc_auth_rsp);
    suite_add_tcase(s, TCase_auth_rsp);
    tcase_add_test(TCase_auth_start_timer, tc_auth_start_timer);
    suite_add_tcase(s, TCase_auth_start_timer);
    tcase_add_test(TCase_ipcp_send_ack, tc_ipcp_send_ack);
    suite_add_tcase(s, TCase_ipcp_send_ack);
    tcase_add_test(TCase_ipcp_send_nack, tc_ipcp_send_nack);
    suite_add_tcase(s, TCase_ipcp_send_nack);
    tcase_add_test(TCase_ipcp_bring_up, tc_ipcp_bring_up);
    suite_add_tcase(s, TCase_ipcp_bring_up);
    tcase_add_test(TCase_ipcp_bring_down, tc_ipcp_bring_down);
    suite_add_tcase(s, TCase_ipcp_bring_down);
    tcase_add_test(TCase_ipcp_start_timer, tc_ipcp_start_timer);
    suite_add_tcase(s, TCase_ipcp_start_timer);
    tcase_add_test(TCase_pico_ppp_poll, tc_pico_ppp_poll);
    suite_add_tcase(s, TCase_pico_ppp_poll);
    tcase_add_test(TCase_pico_ppp_link_state, tc_pico_ppp_link_state);
    suite_add_tcase(s, TCase_pico_ppp_link_state);
    tcase_add_test(TCase_check_to_modem, tc_check_to_modem);
    suite_add_tcase(s, TCase_check_to_modem);
    tcase_add_test(TCase_check_to_lcp, tc_check_to_lcp);
    suite_add_tcase(s, TCase_check_to_lcp);
    tcase_add_test(TCase_check_to_auth, tc_check_to_auth);
    suite_add_tcase(s, TCase_check_to_auth);
    tcase_add_test(TCase_check_to_ipcp, tc_check_to_ipcp);
    suite_add_tcase(s, TCase_check_to_ipcp);
    tcase_add_test(TCase_pico_ppp_tick, tc_pico_ppp_tick);
    suite_add_tcase(s, TCase_pico_ppp_tick);
    return s;
}

int main(void)
{
    int fails;
    Suite *s = pico_suite();
    SRunner *sr = srunner_create(s);
    mock_modem_state = modem_state;
    mock_lcp_state = lcp_state;
    mock_auth_state = auth_state;
    mock_ipcp_state = ipcp_state;
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);
    return fails;
}
