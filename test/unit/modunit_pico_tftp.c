#include <pico_defines.h>
#include <pico_stack.h>
#include <pico_socket.h>
#include <pico_tftp.h>
#include "modules/pico_tftp.c"
#include "check.h"


Suite *pico_suite(void);
int tftp_user_cb(struct pico_tftp_session *session, uint16_t err, uint8_t *block, int32_t len, void *arg);
/* MOCKS */
static int called_pico_socket_close = 0;
static uint16_t expected_opcode = 0;
static int called_user_cb = 0;
static int called_sendto = 0;
static uint32_t called_pico_timer_add = 0;
static int called_pico_timer_cancel = 0;
static struct pico_socket example_socket;
static struct pico_tftp_session example_session;

int pico_socket_close(struct pico_socket *s)
{
    fail_if(s != example_session.socket);
    called_pico_socket_close++;
    return 0;
}

int pico_socket_sendto(struct pico_socket *s, const void *buf, const int len, void *dst, uint16_t remote_port)
{
    const struct pico_tftp_hdr *h = (const struct pico_tftp_hdr *)buf;
    fail_if(s != &example_socket);
    fail_if(short_be(h->opcode) != expected_opcode);
    fail_if(len <= 0);
    (void)dst;
    (void)remote_port;
    called_sendto++;
    return 0;
}

int tftp_user_cb(struct pico_tftp_session *session, uint16_t err, uint8_t *block, int32_t len, void *arg)
{
    (void)session;
    (void)err;
    (void)block;
    (void)len;
    (void)arg;
    called_user_cb++;
    return 0;
}

uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    (void)expire;
    (void)timer;
    (void)arg;

    return ++called_pico_timer_add;
}

void pico_timer_cancel(uint32_t t)
{
    (void)t;
    called_pico_timer_cancel++;
}

/* TESTS */

/* START_TEST(tc_check_opcode) */
/* { */
/*    / * TODO: test this: static int check_opcode(struct pico_tftp_hdr *th) * / */
/*    struct pico_tftp_hdr th; */
/*    th.opcode = 0; */
/*    fail_unless(check_opcode(&th) == -1); */
/*    th.opcode = short_be(PICO_TFTP_RRQ); */
/*    fail_unless(check_opcode(&th) == 0); */
/*    th.opcode = short_be(0xFF); */
/*    fail_unless(check_opcode(&th) == -1); */
/* } */
/* END_TEST */


START_TEST(tc_find_session_by_socket)
{
    tftp_sessions = (struct pico_tftp_session *)PICO_ZALLOC(sizeof(struct pico_tftp_session));
    tftp_sessions->socket = &example_socket;
    tftp_sessions->next = (struct pico_tftp_session *)PICO_ZALLOC(sizeof(struct pico_tftp_session));
    tftp_sessions->socket = NULL;
    tftp_sessions->next = NULL;
    fail_if(find_session_by_socket(&example_socket) != tftp_sessions->next);
}
END_TEST

START_TEST(tc_tftp_finish)
{
    tftp_sessions = 0;

    /* Test case: client */
    example_session.socket = &example_socket;
    called_pico_socket_close = 0;
    tftp_finish(&example_session);
    fail_if(!called_pico_socket_close);

    /* Test eval_finish() len is 5*/
    example_session.socket = &example_socket;
    called_pico_socket_close = 0;
    tftp_eval_finish(&example_session, 5);
    fail_if(example_session.state != TFTP_STATE_CLOSING);
    fail_if(!called_pico_socket_close);

    /* Test eval_finish() len is PICO_TFTP_TOTAL_BLOCK_SIZE */
    example_session.socket = &example_socket;
    called_pico_socket_close = 0;
    tftp_eval_finish(&example_session, PICO_TFTP_TOTAL_BLOCK_SIZE);
    fail_if(called_pico_socket_close);
}
END_TEST

START_TEST(tc_tftp_send_ack)
{
    example_session.socket = &example_socket;
#ifdef PICO_FAULTY
    /* send_ack must not segfault when out of memory */
    pico_set_mm_failure(1);
    tftp_send_ack(&example_session);
    fail_if(called_sendto > 0);
#endif
    expected_opcode = PICO_TFTP_ACK;
    tftp_send_ack(&example_session);
    fail_if(called_sendto < 1);

}
END_TEST

START_TEST(tc_tftp_send_req)
{
    /* Not needed. The tftp_send_rx_req and tftp_send_tx_req cover this. */
}
END_TEST

START_TEST(tc_tftp_send_rx_req)
{
    char filename[14] = "some filename";

    example_session.socket = &example_socket;
    called_user_cb = 0;
    called_pico_socket_close = 0;
    called_sendto = 0;
#ifdef PICO_FAULTY
    example_session.callback = tftp_user_cb;

    /* send_req must call error cb when out of memory */
    pico_set_mm_failure(1);
    tftp_send_rx_req(&example_session, NULL, 0, filename);
    fail_if(called_user_cb < 1);
    fail_if(called_sendto > 0);
#endif
    expected_opcode = PICO_TFTP_RRQ;
    tftp_send_rx_req(&example_session, NULL, 0, NULL);
    fail_if(called_sendto > 0); /* Calling with filename = NULL: not good */

    tftp_send_rx_req(&example_session, NULL, 0, filename);
    fail_if(called_sendto < 0);
}
END_TEST

START_TEST(tc_tftp_send_tx_req)
{
    char filename[14] = "some filename";

    example_session.socket = &example_socket;
    called_user_cb = 0;
    called_pico_socket_close = 0;
    called_sendto = 0;
#ifdef PICO_FAULTY
    example_session.callback = tftp_user_cb;

    /* send_req must call error cb when out of memory */
    pico_set_mm_failure(1);
    tftp_send_tx_req(&example_session, NULL, 0, filename);
    fail_if(called_user_cb < 1);
    fail_if(called_sendto > 0);
#endif
    expected_opcode = PICO_TFTP_WRQ;
    tftp_send_tx_req(&example_session, NULL, 0, NULL);
    fail_if(called_sendto > 0); /* Calling with filename = NULL: not good */

    tftp_send_tx_req(&example_session, NULL, 0, filename);
    fail_if(called_sendto < 0);
}
END_TEST

START_TEST(tc_tftp_send_error)
{
    char longtext[1024];
    example_session.socket = &example_socket;
    called_user_cb = 0;
    called_pico_socket_close = 0;

    /* Sending empty msg */
    called_sendto = 0;
    expected_opcode = PICO_TFTP_ERROR;
    tftp_send_error(&example_session, NULL, 0, 0, NULL);
    fail_if(called_sendto < 1);
    /* Sending some msg */
    called_sendto = 0;
    expected_opcode = PICO_TFTP_ERROR;
    tftp_send_error(&example_session, NULL, 0, 0, "some text here");
    fail_if(called_sendto < 1);

    /* sending some very long msg */
    memset(longtext, 'a', 1023);
    longtext[1023] = (char)0;
    called_sendto = 0;
    expected_opcode = PICO_TFTP_ERROR;
    tftp_send_error(&example_session, NULL, 0, 0, longtext);
    fail_if(called_sendto < 1);
}
END_TEST

START_TEST(tc_tftp_send_data)
{
    example_session.state = 0;
    example_session.socket = &example_socket;
    called_sendto = 0;
    expected_opcode = PICO_TFTP_DATA;
    tftp_send_data(&example_session, (const uint8_t*)"buffer", strlen("buffer"));
    fail_if(called_sendto < 1);
    fail_if(example_session.state != TFTP_STATE_WAIT_LAST_ACK);
}
END_TEST

START_TEST(tc_pico_tftp_abort)
{
    int ret;
    server.listen_socket = NULL;

    /*first case: no session and no listening socket*/
    ret = pico_tftp_abort(NULL, TFTP_ERR_EUSR, "test");
    fail_if(ret != -1);
    /*second case: no session but listening socket*/
    server.listen_socket = example_session.socket = &example_socket;
    pico_tftp_abort(NULL, TFTP_ERR_EUSR, "test");
    fail_if(ret != -1);
    /*tirdh case: session non into list*/
    ret = pico_tftp_abort(&example_session, TFTP_ERR_EUSR, "test");
    fail_if(ret != -1);
}
END_TEST

/* Receiving functions */

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
START_TEST(tc_tftp_socket_open)
{
    /* TODO: test this: static int tftp_socket_open(uint16_t family, union pico_address *a, uint16_t port) */
    fail_if(tftp_socket_open(0xFFFF, 21) != NULL);
    fail_if(tftp_socket_open(0xFFFF, 0xFFFF) != NULL);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

/*    TCase *TCase_check_opcode = tcase_create("Unit test for check_opcode"); */
    TCase *TCase_find_session_by_socket = tcase_create("Unit test for find_session_by_socket");
    TCase *TCase_tftp_finish = tcase_create("Unit test for tftp_finish");
    TCase *TCase_tftp_send_ack = tcase_create("Unit test for tftp_send_ack");
    TCase *TCase_tftp_send_req = tcase_create("Unit test for tftp_send_req");
    TCase *TCase_tftp_send_rx_req = tcase_create("Unit test for tftp_send_rx_req");
    TCase *TCase_tftp_send_tx_req = tcase_create("Unit test for tftp_send_tx_req");
    TCase *TCase_tftp_send_error = tcase_create("Unit test for tftp_send_error");
    TCase *TCase_tftp_send_data = tcase_create("Unit test for tftp_send_data");
    TCase *Tcase_pico_tftp_abort = tcase_create("Unit test for pico_tftp_abort");
    TCase *TCase_tftp_data = tcase_create("Unit test for tftp_data");
    TCase *TCase_tftp_ack = tcase_create("Unit test for tftp_ack");
    TCase *TCase_tftp_timeout = tcase_create("Unit test for tftp_timeout");
    TCase *TCase_tftp_req = tcase_create("Unit test for tftp_req");
    TCase *TCase_tftp_data_err = tcase_create("Unit test for tftp_data_err");
    TCase *TCase_tftp_fsm_timeout = tcase_create("Unit test for tftp_fsm_timeout");
    TCase *TCase_tftp_receive = tcase_create("Unit test for tftp_receive");
    TCase *TCase_tftp_cb = tcase_create("Unit test for tftp_cb");
    TCase *TCase_tftp_socket_open = tcase_create("Unit test for tftp_socket_open");


/*    tcase_add_test(TCase_check_opcode, tc_check_opcode); */
/*    suite_add_tcase(s, TCase_check_opcode); */
    tcase_add_test(TCase_find_session_by_socket, tc_find_session_by_socket);
    suite_add_tcase(s, TCase_find_session_by_socket);
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
    suite_add_tcase(s, Tcase_pico_tftp_abort);
    tcase_add_test(Tcase_pico_tftp_abort, tc_pico_tftp_abort);
    suite_add_tcase(s, TCase_tftp_data);
    tcase_add_test(TCase_tftp_ack, tc_tftp_ack);
    suite_add_tcase(s, TCase_tftp_ack);
    tcase_add_test(TCase_tftp_timeout, tc_tftp_timeout);
    suite_add_tcase(s, TCase_tftp_timeout);
    tcase_add_test(TCase_tftp_req, tc_tftp_req);
    suite_add_tcase(s, TCase_tftp_req);
    tcase_add_test(TCase_tftp_data_err, tc_tftp_data_err);
    suite_add_tcase(s, TCase_tftp_data_err);
    tcase_add_test(TCase_tftp_fsm_timeout, tc_tftp_fsm_timeout);
    suite_add_tcase(s, TCase_tftp_fsm_timeout);
    tcase_add_test(TCase_tftp_receive, tc_tftp_receive);
    suite_add_tcase(s, TCase_tftp_receive);
    tcase_add_test(TCase_tftp_cb, tc_tftp_cb);
    suite_add_tcase(s, TCase_tftp_cb);
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
