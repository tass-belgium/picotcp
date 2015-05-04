#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_device.h"
#include "pico_dev_ppp.h"
#include "pico_stack.h"
#include "pico_md5.h"
#include "pico_dns_client.h"
#include "modules/pico_dev_ppp.c"
#include "check.h"


START_TEST(tc_ppp_ctl_packet_size)
{
   /* TODO: test this: static int ppp_ctl_packet_size(struct pico_device_ppp *ppp, uint16_t proto, int *size) */
}
END_TEST
START_TEST(tc_ppp_fcs_char)
{
   /* TODO: test this: static uint16_t ppp_fcs_char(uint16_t old_crc, uint8_t data) */
}
END_TEST
START_TEST(tc_ppp_fcs_continue)
{
   /* TODO: test this: static uint16_t ppp_fcs_continue(uint16_t fcs, uint8_t *buf, int len) */
}
END_TEST
START_TEST(tc_ppp_fcs_finish)
{
   /* TODO: test this: static uint16_t ppp_fcs_finish(uint16_t fcs) */
}
END_TEST
START_TEST(tc_ppp_fcs_start)
{
   /* TODO: test this: static uint16_t ppp_fcs_start(uint8_t *buf, int len) */
}
END_TEST
START_TEST(tc_ppp_fcs_verify)
{
   /* TODO: test this: static int ppp_fcs_verify(uint8_t *buf, int len) */
}
END_TEST
START_TEST(tc_pico_ppp_ctl_send)
{
   /* TODO: test this: static int pico_ppp_ctl_send(struct pico_device *dev, uint16_t code, uint8_t *pkt, int len, int prefix) */
}
END_TEST
START_TEST(tc_pico_ppp_send)
{
   /* TODO: test this: static int pico_ppp_send(struct pico_device *dev, void *buf, int len) */
}
END_TEST
START_TEST(tc_ppp_modem_send_reset)
{
   /* TODO: test this: static void ppp_modem_send_reset(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_echo)
{
   /* TODO: test this: static void ppp_modem_send_echo(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_creg)
{
   /* TODO: test this: static void ppp_modem_send_creg(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_creg_q)
{
   /* TODO: test this: static void ppp_modem_send_creg_q(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_cgreg)
{
   /* TODO: test this: static void ppp_modem_send_cgreg(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_cgreg_q)
{
   /* TODO: test this: static void ppp_modem_send_cgreg_q(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_cgdcont)
{
   /* TODO: test this: static void ppp_modem_send_cgdcont(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_cgdcont_q)
{
   /* TODO: test this: static void ppp_modem_send_cgdcont_q(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_cgatt)
{
   /* TODO: test this: static void ppp_modem_send_cgatt(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_cgatt_q)
{
   /* TODO: test this: static void ppp_modem_send_cgatt_q(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_send_dial)
{
   /* TODO: test this: static void ppp_modem_send_dial(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_connected)
{
   /* TODO: test this: static void ppp_modem_connected(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_modem_disconnected)
{
   /* TODO: test this: static void ppp_modem_disconnected(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_evaluate_modem_state)
{
   /* TODO: test this: static void evaluate_modem_state(struct pico_device_ppp *ppp, enum ppp_modem_event event) */
}
END_TEST
START_TEST(tc_ppp_modem_recv)
{
   /* TODO: test this: static void ppp_modem_recv(struct pico_device_ppp *ppp, void *data, size_t len) */
}
END_TEST
START_TEST(tc_lcp_optflags)
{
   /* TODO: test this: static uint16_t lcp_optflags(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_lcp_ack)
{
   /* TODO: test this: static void lcp_ack(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_lcp_reject)
{
   /* TODO: test this: static void lcp_reject(struct pico_device_ppp *ppp, uint8_t *pkt, int len, uint16_t rejected) */
}
END_TEST
START_TEST(tc_lcp_process_in)
{
   /* TODO: test this: static void lcp_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_pap_process_in)
{
   /* TODO: test this: static void pap_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_chap_process_in)
{
   /* TODO: test this: static void chap_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_ipcp_ack)
{
   /* TODO: test this: static void ipcp_ack(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_int)
{
   /* TODO: test this: static inline int ipcp_request_options_size(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_request_add_address)
{
   /* TODO: test this: static int ipcp_request_add_address(uint8_t *dst, uint8_t tag, uint32_t arg) */
}
END_TEST
START_TEST(tc_ipcp_request_fill)
{
   /* TODO: test this: static void ipcp_request_fill(struct pico_device_ppp *ppp, uint8_t *opts) */
}
END_TEST
START_TEST(tc_ipcp_request)
{
   /* TODO: test this: static void ipcp_request(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_reject_vj)
{
   /* TODO: test this: static void ipcp_reject_vj(struct pico_device_ppp *ppp, uint8_t *comp_req, int len) */
}
END_TEST
START_TEST(tc_ppp_ipv4_conf)
{
   /* TODO: test this: static void ppp_ipv4_conf(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_process_in)
{
   /* TODO: test this: static void ipcp_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_ipcp6_process_in)
{
   /* TODO: test this: static void ipcp6_process_in(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_ppp_recv_ipv4)
{
   /* TODO: test this: static void ppp_recv_ipv4(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_ppp_recv_ipv6)
{
   /* TODO: test this: static void ppp_recv_ipv6(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_ppp_netconf)
{
   /* TODO: test this: static void ppp_netconf(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ppp_process_packet_payload)
{
   /* TODO: test this: static void ppp_process_packet_payload(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_ppp_process_packet)
{
   /* TODO: test this: static void ppp_process_packet(struct pico_device_ppp *ppp, uint8_t *pkt, int len) */
}
END_TEST
START_TEST(tc_ppp_recv_data)
{
   /* TODO: test this: static void ppp_recv_data(struct pico_device_ppp *ppp, void *data, int len) */
}
END_TEST
START_TEST(tc_ill)
{
   /* TODO: test this: static void ill(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tlu)
{
   /* TODO: test this: static void tlu(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tld)
{
   /* TODO: test this: static void tld(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tls)
{
   /* TODO: test this: static void tls(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tlf)
{
   /* TODO: test this: static void tlf(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_irc)
{
   /* TODO: test this: static void irc(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_zrc)
{
   /* TODO: test this: static void zrc(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_scr)
{
   /* TODO: test this: static void scr(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_sca)
{
   /* TODO: test this: static void sca(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_scn)
{
   /* TODO: test this: static void scn(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_str)
{
   /* TODO: test this: static void str(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_sta)
{
   /* TODO: test this: static void sta(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_scj)
{
   /* TODO: test this: static void scj(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ser)
{
   /* TODO: test this: static void ser(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_irc_scr)
{
   /* TODO: test this: static void irc_scr(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_irc_scr_sca)
{
   /* TODO: test this: static void irc_scr_sca(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_irc_scr_scn)
{
   /* TODO: test this: static void irc_scr_scn(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_irc_str)
{
   /* TODO: test this: static void irc_str(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_sca_tlu)
{
   /* TODO: test this: static void sca_tlu(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_irc_tlu)
{
   /* TODO: test this: static void irc_tlu(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tld_irc_str)
{
   /* TODO: test this: static void tld_irc_str(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tld_scr_sca)
{
   /* TODO: test this: static void tld_scr_sca(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tld_scr_scn)
{
   /* TODO: test this: static void tld_scr_scn(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tld_scr)
{
   /* TODO: test this: static void tld_scr(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_tld_zrc_sta)
{
   /* TODO: test this: static void tld_zrc_sta(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_evaluate_lcp_state)
{
   /* TODO: test this: static void evaluate_lcp_state(struct pico_device_ppp *ppp, enum ppp_lcp_event event) */
}
END_TEST
START_TEST(tc_auth)
{
   /* TODO: test this: static void auth(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_deauth)
{
   /* TODO: test this: static void deauth(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_auth_req)
{
   /* TODO: test this: static void auth_req(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_auth_rsp)
{
   /* TODO: test this: static void auth_rsp(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_evaluate_auth_state)
{
   /* TODO: test this: static void evaluate_auth_state(struct pico_device_ppp *ppp, enum ppp_auth_event event) */
}
END_TEST
START_TEST(tc_ipcp_scr)
{
   /* TODO: test this: static void ipcp_scr(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_sca)
{
   /* TODO: test this: static void ipcp_sca(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_scn)
{
   /* TODO: test this: static void ipcp_scn(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_tlu)
{
   /* TODO: test this: static void ipcp_tlu(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_tld)
{
   /* TODO: test this: static void ipcp_tld(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_sca_tlu)
{
   /* TODO: test this: static void ipcp_sca_tlu(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_tld_scr_sca)
{
   /* TODO: test this: static void ipcp_tld_scr_sca(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_ipcp_tld_scr_scn)
{
   /* TODO: test this: static void ipcp_tld_scr_scn(struct pico_device_ppp *ppp) */
}
END_TEST
START_TEST(tc_evaluate_ipcp_state)
{
   /* TODO: test this: static void evaluate_ipcp_state(struct pico_device_ppp *ppp, enum ppp_ipcp_event event) */
}
END_TEST
START_TEST(tc_ppp_recv)
{
   /* TODO: test this: static void ppp_recv(struct pico_device_ppp *ppp, void *data, size_t len) */
}
END_TEST
START_TEST(tc_pico_ppp_poll)
{
   /* TODO: test this: static int pico_ppp_poll(struct pico_device *dev, int loop_score) */
}
END_TEST
START_TEST(tc_pico_ppp_link_state)
{
   /* TODO: test this: static int pico_ppp_link_state(struct pico_device *dev) */
}
END_TEST
START_TEST(tc_pico_ppp_tick)
{
   /* TODO: test this: static void pico_ppp_tick(pico_time now, void *arg) */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_ppp_ctl_packet_size = tcase_create("Unit test for ppp_ctl_packet_size");
    TCase *TCase_ppp_fcs_char = tcase_create("Unit test for ppp_fcs_char");
    TCase *TCase_ppp_fcs_continue = tcase_create("Unit test for ppp_fcs_continue");
    TCase *TCase_ppp_fcs_finish = tcase_create("Unit test for ppp_fcs_finish");
    TCase *TCase_ppp_fcs_start = tcase_create("Unit test for ppp_fcs_start");
    TCase *TCase_ppp_fcs_verify = tcase_create("Unit test for ppp_fcs_verify");
    TCase *TCase_pico_ppp_ctl_send = tcase_create("Unit test for pico_ppp_ctl_send");
    TCase *TCase_pico_ppp_send = tcase_create("Unit test for pico_ppp_send");
    TCase *TCase_ppp_modem_send_reset = tcase_create("Unit test for ppp_modem_send_reset");
    TCase *TCase_ppp_modem_send_echo = tcase_create("Unit test for ppp_modem_send_echo");
    TCase *TCase_ppp_modem_send_creg = tcase_create("Unit test for ppp_modem_send_creg");
    TCase *TCase_ppp_modem_send_creg_q = tcase_create("Unit test for ppp_modem_send_creg_q");
    TCase *TCase_ppp_modem_send_cgreg = tcase_create("Unit test for ppp_modem_send_cgreg");
    TCase *TCase_ppp_modem_send_cgreg_q = tcase_create("Unit test for ppp_modem_send_cgreg_q");
    TCase *TCase_ppp_modem_send_cgdcont = tcase_create("Unit test for ppp_modem_send_cgdcont");
    TCase *TCase_ppp_modem_send_cgdcont_q = tcase_create("Unit test for ppp_modem_send_cgdcont_q");
    TCase *TCase_ppp_modem_send_cgatt = tcase_create("Unit test for ppp_modem_send_cgatt");
    TCase *TCase_ppp_modem_send_cgatt_q = tcase_create("Unit test for ppp_modem_send_cgatt_q");
    TCase *TCase_ppp_modem_send_dial = tcase_create("Unit test for ppp_modem_send_dial");
    TCase *TCase_ppp_modem_connected = tcase_create("Unit test for ppp_modem_connected");
    TCase *TCase_ppp_modem_disconnected = tcase_create("Unit test for ppp_modem_disconnected");
    TCase *TCase_evaluate_modem_state = tcase_create("Unit test for evaluate_modem_state");
    TCase *TCase_ppp_modem_recv = tcase_create("Unit test for ppp_modem_recv");
    TCase *TCase_lcp_optflags = tcase_create("Unit test for lcp_optflags");
    TCase *TCase_lcp_ack = tcase_create("Unit test for lcp_ack");
    TCase *TCase_lcp_reject = tcase_create("Unit test for lcp_reject");
    TCase *TCase_lcp_process_in = tcase_create("Unit test for lcp_process_in");
    TCase *TCase_pap_process_in = tcase_create("Unit test for pap_process_in");
    TCase *TCase_chap_process_in = tcase_create("Unit test for chap_process_in");
    TCase *TCase_ipcp_ack = tcase_create("Unit test for ipcp_ack");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_ipcp_request_add_address = tcase_create("Unit test for ipcp_request_add_address");
    TCase *TCase_ipcp_request_fill = tcase_create("Unit test for ipcp_request_fill");
    TCase *TCase_ipcp_request = tcase_create("Unit test for ipcp_request");
    TCase *TCase_ipcp_reject_vj = tcase_create("Unit test for ipcp_reject_vj");
    TCase *TCase_ppp_ipv4_conf = tcase_create("Unit test for ppp_ipv4_conf");
    TCase *TCase_ipcp_process_in = tcase_create("Unit test for ipcp_process_in");
    TCase *TCase_ipcp6_process_in = tcase_create("Unit test for ipcp6_process_in");
    TCase *TCase_ppp_recv_ipv4 = tcase_create("Unit test for ppp_recv_ipv4");
    TCase *TCase_ppp_recv_ipv6 = tcase_create("Unit test for ppp_recv_ipv6");
    TCase *TCase_ppp_netconf = tcase_create("Unit test for ppp_netconf");
    TCase *TCase_ppp_process_packet_payload = tcase_create("Unit test for ppp_process_packet_payload");
    TCase *TCase_ppp_process_packet = tcase_create("Unit test for ppp_process_packet");
    TCase *TCase_ppp_recv_data = tcase_create("Unit test for ppp_recv_data");
    TCase *TCase_ill = tcase_create("Unit test for ill");
    TCase *TCase_tlu = tcase_create("Unit test for tlu");
    TCase *TCase_tld = tcase_create("Unit test for tld");
    TCase *TCase_tls = tcase_create("Unit test for tls");
    TCase *TCase_tlf = tcase_create("Unit test for tlf");
    TCase *TCase_irc = tcase_create("Unit test for irc");
    TCase *TCase_zrc = tcase_create("Unit test for zrc");
    TCase *TCase_scr = tcase_create("Unit test for scr");
    TCase *TCase_sca = tcase_create("Unit test for sca");
    TCase *TCase_scn = tcase_create("Unit test for scn");
    TCase *TCase_str = tcase_create("Unit test for str");
    TCase *TCase_sta = tcase_create("Unit test for sta");
    TCase *TCase_scj = tcase_create("Unit test for scj");
    TCase *TCase_ser = tcase_create("Unit test for ser");
    TCase *TCase_irc_scr = tcase_create("Unit test for irc_scr");
    TCase *TCase_irc_scr_sca = tcase_create("Unit test for irc_scr_sca");
    TCase *TCase_irc_scr_scn = tcase_create("Unit test for irc_scr_scn");
    TCase *TCase_irc_str = tcase_create("Unit test for irc_str");
    TCase *TCase_sca_tlu = tcase_create("Unit test for sca_tlu");
    TCase *TCase_irc_tlu = tcase_create("Unit test for irc_tlu");
    TCase *TCase_tld_irc_str = tcase_create("Unit test for tld_irc_str");
    TCase *TCase_tld_scr_sca = tcase_create("Unit test for tld_scr_sca");
    TCase *TCase_tld_scr_scn = tcase_create("Unit test for tld_scr_scn");
    TCase *TCase_tld_scr = tcase_create("Unit test for tld_scr");
    TCase *TCase_tld_zrc_sta = tcase_create("Unit test for tld_zrc_sta");
    TCase *TCase_evaluate_lcp_state = tcase_create("Unit test for evaluate_lcp_state");
    TCase *TCase_auth = tcase_create("Unit test for auth");
    TCase *TCase_deauth = tcase_create("Unit test for deauth");
    TCase *TCase_auth_req = tcase_create("Unit test for auth_req");
    TCase *TCase_auth_rsp = tcase_create("Unit test for auth_rsp");
    TCase *TCase_evaluate_auth_state = tcase_create("Unit test for evaluate_auth_state");
    TCase *TCase_ipcp_scr = tcase_create("Unit test for ipcp_scr");
    TCase *TCase_ipcp_sca = tcase_create("Unit test for ipcp_sca");
    TCase *TCase_ipcp_scn = tcase_create("Unit test for ipcp_scn");
    TCase *TCase_ipcp_tlu = tcase_create("Unit test for ipcp_tlu");
    TCase *TCase_ipcp_tld = tcase_create("Unit test for ipcp_tld");
    TCase *TCase_ipcp_sca_tlu = tcase_create("Unit test for ipcp_sca_tlu");
    TCase *TCase_ipcp_tld_scr_sca = tcase_create("Unit test for ipcp_tld_scr_sca");
    TCase *TCase_ipcp_tld_scr_scn = tcase_create("Unit test for ipcp_tld_scr_scn");
    TCase *TCase_evaluate_ipcp_state = tcase_create("Unit test for evaluate_ipcp_state");
    TCase *TCase_ppp_recv = tcase_create("Unit test for ppp_recv");
    TCase *TCase_pico_ppp_poll = tcase_create("Unit test for pico_ppp_poll");
    TCase *TCase_pico_ppp_link_state = tcase_create("Unit test for pico_ppp_link_state");
    TCase *TCase_pico_ppp_tick = tcase_create("Unit test for pico_ppp_tick");


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
    tcase_add_test(TCase_ppp_modem_send_reset, tc_ppp_modem_send_reset);
    suite_add_tcase(s, TCase_ppp_modem_send_reset);
    tcase_add_test(TCase_ppp_modem_send_echo, tc_ppp_modem_send_echo);
    suite_add_tcase(s, TCase_ppp_modem_send_echo);
    tcase_add_test(TCase_ppp_modem_send_creg, tc_ppp_modem_send_creg);
    suite_add_tcase(s, TCase_ppp_modem_send_creg);
    tcase_add_test(TCase_ppp_modem_send_creg_q, tc_ppp_modem_send_creg_q);
    suite_add_tcase(s, TCase_ppp_modem_send_creg_q);
    tcase_add_test(TCase_ppp_modem_send_cgreg, tc_ppp_modem_send_cgreg);
    suite_add_tcase(s, TCase_ppp_modem_send_cgreg);
    tcase_add_test(TCase_ppp_modem_send_cgreg_q, tc_ppp_modem_send_cgreg_q);
    suite_add_tcase(s, TCase_ppp_modem_send_cgreg_q);
    tcase_add_test(TCase_ppp_modem_send_cgdcont, tc_ppp_modem_send_cgdcont);
    suite_add_tcase(s, TCase_ppp_modem_send_cgdcont);
    tcase_add_test(TCase_ppp_modem_send_cgdcont_q, tc_ppp_modem_send_cgdcont_q);
    suite_add_tcase(s, TCase_ppp_modem_send_cgdcont_q);
    tcase_add_test(TCase_ppp_modem_send_cgatt, tc_ppp_modem_send_cgatt);
    suite_add_tcase(s, TCase_ppp_modem_send_cgatt);
    tcase_add_test(TCase_ppp_modem_send_cgatt_q, tc_ppp_modem_send_cgatt_q);
    suite_add_tcase(s, TCase_ppp_modem_send_cgatt_q);
    tcase_add_test(TCase_ppp_modem_send_dial, tc_ppp_modem_send_dial);
    suite_add_tcase(s, TCase_ppp_modem_send_dial);
    tcase_add_test(TCase_ppp_modem_connected, tc_ppp_modem_connected);
    suite_add_tcase(s, TCase_ppp_modem_connected);
    tcase_add_test(TCase_ppp_modem_disconnected, tc_ppp_modem_disconnected);
    suite_add_tcase(s, TCase_ppp_modem_disconnected);
    tcase_add_test(TCase_evaluate_modem_state, tc_evaluate_modem_state);
    suite_add_tcase(s, TCase_evaluate_modem_state);
    tcase_add_test(TCase_ppp_modem_recv, tc_ppp_modem_recv);
    suite_add_tcase(s, TCase_ppp_modem_recv);
    tcase_add_test(TCase_lcp_optflags, tc_lcp_optflags);
    suite_add_tcase(s, TCase_lcp_optflags);
    tcase_add_test(TCase_lcp_ack, tc_lcp_ack);
    suite_add_tcase(s, TCase_lcp_ack);
    tcase_add_test(TCase_lcp_reject, tc_lcp_reject);
    suite_add_tcase(s, TCase_lcp_reject);
    tcase_add_test(TCase_lcp_process_in, tc_lcp_process_in);
    suite_add_tcase(s, TCase_lcp_process_in);
    tcase_add_test(TCase_pap_process_in, tc_pap_process_in);
    suite_add_tcase(s, TCase_pap_process_in);
    tcase_add_test(TCase_chap_process_in, tc_chap_process_in);
    suite_add_tcase(s, TCase_chap_process_in);
    tcase_add_test(TCase_ipcp_ack, tc_ipcp_ack);
    suite_add_tcase(s, TCase_ipcp_ack);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_ipcp_request_add_address, tc_ipcp_request_add_address);
    suite_add_tcase(s, TCase_ipcp_request_add_address);
    tcase_add_test(TCase_ipcp_request_fill, tc_ipcp_request_fill);
    suite_add_tcase(s, TCase_ipcp_request_fill);
    tcase_add_test(TCase_ipcp_request, tc_ipcp_request);
    suite_add_tcase(s, TCase_ipcp_request);
    tcase_add_test(TCase_ipcp_reject_vj, tc_ipcp_reject_vj);
    suite_add_tcase(s, TCase_ipcp_reject_vj);
    tcase_add_test(TCase_ppp_ipv4_conf, tc_ppp_ipv4_conf);
    suite_add_tcase(s, TCase_ppp_ipv4_conf);
    tcase_add_test(TCase_ipcp_process_in, tc_ipcp_process_in);
    suite_add_tcase(s, TCase_ipcp_process_in);
    tcase_add_test(TCase_ipcp6_process_in, tc_ipcp6_process_in);
    suite_add_tcase(s, TCase_ipcp6_process_in);
    tcase_add_test(TCase_ppp_recv_ipv4, tc_ppp_recv_ipv4);
    suite_add_tcase(s, TCase_ppp_recv_ipv4);
    tcase_add_test(TCase_ppp_recv_ipv6, tc_ppp_recv_ipv6);
    suite_add_tcase(s, TCase_ppp_recv_ipv6);
    tcase_add_test(TCase_ppp_netconf, tc_ppp_netconf);
    suite_add_tcase(s, TCase_ppp_netconf);
    tcase_add_test(TCase_ppp_process_packet_payload, tc_ppp_process_packet_payload);
    suite_add_tcase(s, TCase_ppp_process_packet_payload);
    tcase_add_test(TCase_ppp_process_packet, tc_ppp_process_packet);
    suite_add_tcase(s, TCase_ppp_process_packet);
    tcase_add_test(TCase_ppp_recv_data, tc_ppp_recv_data);
    suite_add_tcase(s, TCase_ppp_recv_data);
    tcase_add_test(TCase_ill, tc_ill);
    suite_add_tcase(s, TCase_ill);
    tcase_add_test(TCase_tlu, tc_tlu);
    suite_add_tcase(s, TCase_tlu);
    tcase_add_test(TCase_tld, tc_tld);
    suite_add_tcase(s, TCase_tld);
    tcase_add_test(TCase_tls, tc_tls);
    suite_add_tcase(s, TCase_tls);
    tcase_add_test(TCase_tlf, tc_tlf);
    suite_add_tcase(s, TCase_tlf);
    tcase_add_test(TCase_irc, tc_irc);
    suite_add_tcase(s, TCase_irc);
    tcase_add_test(TCase_zrc, tc_zrc);
    suite_add_tcase(s, TCase_zrc);
    tcase_add_test(TCase_scr, tc_scr);
    suite_add_tcase(s, TCase_scr);
    tcase_add_test(TCase_sca, tc_sca);
    suite_add_tcase(s, TCase_sca);
    tcase_add_test(TCase_scn, tc_scn);
    suite_add_tcase(s, TCase_scn);
    tcase_add_test(TCase_str, tc_str);
    suite_add_tcase(s, TCase_str);
    tcase_add_test(TCase_sta, tc_sta);
    suite_add_tcase(s, TCase_sta);
    tcase_add_test(TCase_scj, tc_scj);
    suite_add_tcase(s, TCase_scj);
    tcase_add_test(TCase_ser, tc_ser);
    suite_add_tcase(s, TCase_ser);
    tcase_add_test(TCase_irc_scr, tc_irc_scr);
    suite_add_tcase(s, TCase_irc_scr);
    tcase_add_test(TCase_irc_scr_sca, tc_irc_scr_sca);
    suite_add_tcase(s, TCase_irc_scr_sca);
    tcase_add_test(TCase_irc_scr_scn, tc_irc_scr_scn);
    suite_add_tcase(s, TCase_irc_scr_scn);
    tcase_add_test(TCase_irc_str, tc_irc_str);
    suite_add_tcase(s, TCase_irc_str);
    tcase_add_test(TCase_sca_tlu, tc_sca_tlu);
    suite_add_tcase(s, TCase_sca_tlu);
    tcase_add_test(TCase_irc_tlu, tc_irc_tlu);
    suite_add_tcase(s, TCase_irc_tlu);
    tcase_add_test(TCase_tld_irc_str, tc_tld_irc_str);
    suite_add_tcase(s, TCase_tld_irc_str);
    tcase_add_test(TCase_tld_scr_sca, tc_tld_scr_sca);
    suite_add_tcase(s, TCase_tld_scr_sca);
    tcase_add_test(TCase_tld_scr_scn, tc_tld_scr_scn);
    suite_add_tcase(s, TCase_tld_scr_scn);
    tcase_add_test(TCase_tld_scr, tc_tld_scr);
    suite_add_tcase(s, TCase_tld_scr);
    tcase_add_test(TCase_tld_zrc_sta, tc_tld_zrc_sta);
    suite_add_tcase(s, TCase_tld_zrc_sta);
    tcase_add_test(TCase_evaluate_lcp_state, tc_evaluate_lcp_state);
    suite_add_tcase(s, TCase_evaluate_lcp_state);
    tcase_add_test(TCase_auth, tc_auth);
    suite_add_tcase(s, TCase_auth);
    tcase_add_test(TCase_deauth, tc_deauth);
    suite_add_tcase(s, TCase_deauth);
    tcase_add_test(TCase_auth_req, tc_auth_req);
    suite_add_tcase(s, TCase_auth_req);
    tcase_add_test(TCase_auth_rsp, tc_auth_rsp);
    suite_add_tcase(s, TCase_auth_rsp);
    tcase_add_test(TCase_evaluate_auth_state, tc_evaluate_auth_state);
    suite_add_tcase(s, TCase_evaluate_auth_state);
    tcase_add_test(TCase_ipcp_scr, tc_ipcp_scr);
    suite_add_tcase(s, TCase_ipcp_scr);
    tcase_add_test(TCase_ipcp_sca, tc_ipcp_sca);
    suite_add_tcase(s, TCase_ipcp_sca);
    tcase_add_test(TCase_ipcp_scn, tc_ipcp_scn);
    suite_add_tcase(s, TCase_ipcp_scn);
    tcase_add_test(TCase_ipcp_tlu, tc_ipcp_tlu);
    suite_add_tcase(s, TCase_ipcp_tlu);
    tcase_add_test(TCase_ipcp_tld, tc_ipcp_tld);
    suite_add_tcase(s, TCase_ipcp_tld);
    tcase_add_test(TCase_ipcp_sca_tlu, tc_ipcp_sca_tlu);
    suite_add_tcase(s, TCase_ipcp_sca_tlu);
    tcase_add_test(TCase_ipcp_tld_scr_sca, tc_ipcp_tld_scr_sca);
    suite_add_tcase(s, TCase_ipcp_tld_scr_sca);
    tcase_add_test(TCase_ipcp_tld_scr_scn, tc_ipcp_tld_scr_scn);
    suite_add_tcase(s, TCase_ipcp_tld_scr_scn);
    tcase_add_test(TCase_evaluate_ipcp_state, tc_evaluate_ipcp_state);
    suite_add_tcase(s, TCase_evaluate_ipcp_state);
    tcase_add_test(TCase_ppp_recv, tc_ppp_recv);
    suite_add_tcase(s, TCase_ppp_recv);
    tcase_add_test(TCase_pico_ppp_poll, tc_pico_ppp_poll);
    suite_add_tcase(s, TCase_pico_ppp_poll);
    tcase_add_test(TCase_pico_ppp_link_state, tc_pico_ppp_link_state);
    suite_add_tcase(s, TCase_pico_ppp_link_state);
    tcase_add_test(TCase_pico_ppp_tick, tc_pico_ppp_tick);
    suite_add_tcase(s, TCase_pico_ppp_tick);
return s;
}

int main(void)
{
    int fails;
    Suite *s = pico_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);
    return fails;
}
