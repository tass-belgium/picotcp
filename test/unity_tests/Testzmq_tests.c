#include "unity.h"
#include "zmq_tests.h"
#include "pico_zmq.c"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "Mockpico_zmtp.h"

struct zmq_socket_req dummy_req;

void setUp(void)
{
}

void tearDown(void)
{
}

void zmq_socket_open_test_callback(uint16_t net, uint16_t proto, uint8_t type, void (*wakeup)(uint16_t ev, struct zmtp_socket* s), int cmock_num_calls)
{
    TEST_ASSERT_EQUAL_UINT16(net, PICO_PROTO_IPV4);
    TEST_ASSERT_EQUAL_UINT16(proto, PICO_PROTO_TCP);
}

void test_zmq_tests_NeedToImplement(void)
{
    TEST_IGNORE();
}

void test_zmq_socket_req(void) 
{
    struct zmq_socket_base* temp = NULL;
    /* Testing request */
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMQ_TYPE_REQ, &cb_zmtp_sockets, NULL);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMQ_TYPE_REQ, &cb_zmtp_sockets, &dummy_req);
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMQ_TYPE_REQ));

    temp = (struct zmq_socket_base *)zmq_socket(NULL, ZMQ_TYPE_REQ);
    TEST_ASSERT_EQUAL(temp->type, ZMQ_TYPE_REQ);

    /* Test invalid 0mq socket type */
    TEST_ASSERT_NULL(zmq_socket(NULL, 9));    //is not one of the defined types (REP, REQ, SUBSCRIBER, PUBLISHE ... )
}

void test_zmq_socket_rep(void) 
{
    TEST_IGNORE();
}

void test_zmq_socket_pub(void)
{
    TEST_IGNORE();
}

void test_zmq_connect(void)
{
    TEST_IGNORE();
}
