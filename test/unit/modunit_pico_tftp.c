#include <pico_defines.h>
#include <pico_stack.h>
#include <pico_socket.h>
#include <pico_tftp.h>
#include "modules/pico_tftp.c"
#include "check.h"


START_TEST(tc_check_opcode)
{
   /* TODO: test this: static int check_opcode(struct pico_tftp_hdr *th) */
}
END_TEST
START_TEST(tc_tftp_finish)
{
   /* TODO: test this: static void tftp_finish(void) */
}
END_TEST
START_TEST(tc_tftp_send_ack)
{
   /* TODO: test this: static void tftp_send_ack(void) */
}
END_TEST
START_TEST(tc_tftp_send_req)
{
   /* TODO: test this: static void tftp_send_req(union pico_address *a, uint16_t port, char *filename, uint16_t opcode) */
}
END_TEST
START_TEST(tc_tftp_send_rx_req)
{
   /* TODO: test this: static void tftp_send_rx_req(union pico_address *a, uint16_t port, char *filename) */
}
END_TEST
START_TEST(tc_tftp_send_tx_req)
{
   /* TODO: test this: static void tftp_send_tx_req(union pico_address *a, uint16_t port, char *filename) */
}
END_TEST
START_TEST(tc_tftp_send_error)
{
   /* TODO: test this: static void tftp_send_error(union pico_address *a, uint16_t port, uint16_t errcode, const char *errmsg) */
}
END_TEST
START_TEST(tc_tftp_send_data)
{
   /* TODO: test this: static void tftp_send_data(const uint8_t *data, uint32_t len) */
}
END_TEST
START_TEST(tc_tftp_data)
{
   /* TODO: test this: static void tftp_data(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_ack)
{
   /* TODO: test this: static void tftp_ack(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_timeout)
{
   /* TODO: test this: static void tftp_timeout(pico_time t) */
}
END_TEST
START_TEST(tc_tftp_req)
{
   /* TODO: test this: static void tftp_req(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_data_err)
{
   /* TODO: test this: static void tftp_data_err(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_fsm_receive_request)
{
   /* TODO: test this: static void tftp_fsm_receive_request(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_fsm_receive)
{
   /* TODO: test this: static void tftp_fsm_receive(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_fsm_error)
{
   /* TODO: test this: static void tftp_fsm_error(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_fsm_timeout)
{
   /* TODO: test this: static void tftp_fsm_timeout(pico_time now, void *arg) */
}
END_TEST
START_TEST(tc_tftp_receive)
{
   /* TODO: test this: static void tftp_receive(uint8_t *block, uint32_t r, union pico_address *a, uint16_t port) */
}
END_TEST
START_TEST(tc_tftp_cb)
{
   /* TODO: test this: static void tftp_cb(uint16_t ev, struct pico_socket *s) */
}
END_TEST
START_TEST(tc_tftp_bind)
{
   /* TODO: test this: static void tftp_bind(void) */
}
END_TEST
START_TEST(tc_tftp_socket_open)
{
   /* TODO: test this: static int tftp_socket_open(uint16_t family, union pico_address *a, uint16_t port) */
}
END_TEST


Suite *pico_suite(void)                       
{
    Suite *s = suite_create("PicoTCP");             

    TCase *TCase_check_opcode = tcase_create("Unit test for check_opcode");
    TCase *TCase_tftp_finish = tcase_create("Unit test for tftp_finish");
    TCase *TCase_tftp_send_ack = tcase_create("Unit test for tftp_send_ack");
    TCase *TCase_tftp_send_req = tcase_create("Unit test for tftp_send_req");
    TCase *TCase_tftp_send_rx_req = tcase_create("Unit test for tftp_send_rx_req");
    TCase *TCase_tftp_send_tx_req = tcase_create("Unit test for tftp_send_tx_req");
    TCase *TCase_tftp_send_error = tcase_create("Unit test for tftp_send_error");
    TCase *TCase_tftp_send_data = tcase_create("Unit test for tftp_send_data");
    TCase *TCase_tftp_data = tcase_create("Unit test for tftp_data");
    TCase *TCase_tftp_ack = tcase_create("Unit test for tftp_ack");
    TCase *TCase_tftp_timeout = tcase_create("Unit test for tftp_timeout");
    TCase *TCase_tftp_req = tcase_create("Unit test for tftp_req");
    TCase *TCase_tftp_data_err = tcase_create("Unit test for tftp_data_err");
    TCase *TCase_tftp_fsm_receive_request = tcase_create("Unit test for tftp_fsm_receive_request");
    TCase *TCase_tftp_fsm_receive = tcase_create("Unit test for tftp_fsm_receive");
    TCase *TCase_tftp_fsm_error = tcase_create("Unit test for tftp_fsm_error");
    TCase *TCase_tftp_fsm_timeout = tcase_create("Unit test for tftp_fsm_timeout");
    TCase *TCase_tftp_receive = tcase_create("Unit test for tftp_receive");
    TCase *TCase_tftp_cb = tcase_create("Unit test for tftp_cb");
    TCase *TCase_tftp_bind = tcase_create("Unit test for tftp_bind");
    TCase *TCase_tftp_socket_open = tcase_create("Unit test for tftp_socket_open");


    tcase_add_test(TCase_check_opcode, tc_check_opcode);
    suite_add_tcase(s, TCase_check_opcode);
    tcase_add_test(TCase_tftp_finish, tc_tftp_finish);
    suite_add_tcase(s, TCase_tftp_finish);
    tcase_add_test(TCase_tftp_send_ack, tc_tftp_send_ack);
    suite_add_tcase(s, TCase_tftp_send_ack);
    tcase_add_test(TCase_tftp_send_req, tc_tftp_send_req);
    suite_add_tcase(s, TCase_tftp_send_req);
    tcase_add_test(TCase_tftp_send_rx_req, tc_tftp_send_rx_req);
    suite_add_tcase(s, TCase_tftp_send_rx_req);
    tcase_add_test(TCase_tftp_send_tx_req, tc_tftp_send_tx_req);
    suite_add_tcase(s, TCase_tftp_send_tx_req);
    tcase_add_test(TCase_tftp_send_error, tc_tftp_send_error);
    suite_add_tcase(s, TCase_tftp_send_error);
    tcase_add_test(TCase_tftp_send_data, tc_tftp_send_data);
    suite_add_tcase(s, TCase_tftp_send_data);
    tcase_add_test(TCase_tftp_data, tc_tftp_data);
    suite_add_tcase(s, TCase_tftp_data);
    tcase_add_test(TCase_tftp_ack, tc_tftp_ack);
    suite_add_tcase(s, TCase_tftp_ack);
    tcase_add_test(TCase_tftp_timeout, tc_tftp_timeout);
    suite_add_tcase(s, TCase_tftp_timeout);
    tcase_add_test(TCase_tftp_req, tc_tftp_req);
    suite_add_tcase(s, TCase_tftp_req);
    tcase_add_test(TCase_tftp_data_err, tc_tftp_data_err);
    suite_add_tcase(s, TCase_tftp_data_err);
    tcase_add_test(TCase_tftp_fsm_receive_request, tc_tftp_fsm_receive_request);
    suite_add_tcase(s, TCase_tftp_fsm_receive_request);
    tcase_add_test(TCase_tftp_fsm_receive, tc_tftp_fsm_receive);
    suite_add_tcase(s, TCase_tftp_fsm_receive);
    tcase_add_test(TCase_tftp_fsm_error, tc_tftp_fsm_error);
    suite_add_tcase(s, TCase_tftp_fsm_error);
    tcase_add_test(TCase_tftp_fsm_timeout, tc_tftp_fsm_timeout);
    suite_add_tcase(s, TCase_tftp_fsm_timeout);
    tcase_add_test(TCase_tftp_receive, tc_tftp_receive);
    suite_add_tcase(s, TCase_tftp_receive);
    tcase_add_test(TCase_tftp_cb, tc_tftp_cb);
    suite_add_tcase(s, TCase_tftp_cb);
    tcase_add_test(TCase_tftp_bind, tc_tftp_bind);
    suite_add_tcase(s, TCase_tftp_bind);
    tcase_add_test(TCase_tftp_socket_open, tc_tftp_socket_open);
    suite_add_tcase(s, TCase_tftp_socket_open);
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
