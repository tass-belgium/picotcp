#include "unity.h"
#include "zmq_tests.h"
#include "pico_zmq.c"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "Mockpico_zmtp.h"
#include "Mockpico_ipv4.h"
#include "Mockpico_vector.h"

struct zmtp_socket dummy_zmtp_sock;

void setUp(void)
{
}

void tearDown(void)
{
}

void test_zmq_socket_req(void) 
{
    struct zmq_socket_base* temp = NULL;
    /* Testing request */
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_zmtp_sockets, NULL);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_zmtp_sockets, &dummy_zmtp_sock);
    pico_vector_init_IgnoreAndReturn(NULL); //Init the in_vector
    pico_vector_init_IgnoreAndReturn(NULL); //Init the out_vector
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMQ_TYPE_REQ));
    
    temp = (struct zmq_socket_base *)zmq_socket(NULL, ZMQ_TYPE_REQ);
    TEST_ASSERT_EQUAL(ZMQ_TYPE_REQ, temp->type);
    TEST_ASSERT_EQUAL(ZMQ_SEND_ENABLED ,((struct zmq_socket_req *)temp)->send_enable);

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

int pico_string_to_ipv4_cb(const char *ipstr, uint32_t *ip, int NumCalls)
{
    *ip = 123456;
}

void test_zmq_connect(void)
{
    void *dummy_ptr = NULL;
    
    pico_string_to_ipv4_StubWithCallback(&pico_string_to_ipv4_cb);
    zmtp_socket_connect_IgnoreAndReturn(0);
    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(&dummy_ptr, NULL));
    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(NULL, "tcp://127.0.0.1:5555"));
}

int vector_push_cb(struct pico_vector* vector, void* data, int NumCalls) 
{
    printf("Numcalls = %i\n", NumCalls);
}

void test_zmq_req(void)
{
    struct zmq_socket_base* dummy_zmq_sock = NULL;
    struct zmtp_socket dummy_zmtp_sock;

    /* Mocking for zmq_socket */
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_zmtp_sockets, &dummy_zmtp_sock);
    pico_vector_init_IgnoreAndReturn(NULL); //Init the in_vector
    pico_vector_init_IgnoreAndReturn(NULL); //Init the out_vector

    /* Creating dummy_zmq_sock */
    dummy_zmq_sock = zmq_socket(NULL, ZMQ_TYPE_REQ);
    dummy_zmq_sock->sock = &dummy_zmtp_sock;

    /* Test for bad arguments */
    TEST_ASSERT_EQUAL_INT(-1, zmq_send(NULL, NULL, 0, 0));
    
    /* Test for final frame */
    zmtp_socket_send_ExpectAndReturn(&dummy_zmtp_sock, &dummy_zmq_sock->out_vector, 0);
    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, "Hello", 5, 0));

    /* Following should fail because receive must be called before a second send can be done */
    TEST_ASSERT_EQUAL_INT(-1, zmq_send(dummy_zmq_sock, "Hello", 5, 0));

    /* Test for more frame */
    ((struct zmq_socket_req *)dummy_zmq_sock)->send_enable = ZMQ_SEND_ENABLED; //reset the socket
    zmtp_socket_send_ExpectAndReturn(&dummy_zmtp_sock, &dummy_zmq_sock->out_vector, 0);
    pico_vector_push_back_IgnoreAndReturn(0);
    //pico_vector_push_back_IgnoreAndReturn(0);
    
    //pico_vector_push_back_StubWithCallback(&vector_push_cb);

    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, "Hello", 5, ZMQ_SNDMORE));
    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, "Hello", 5, ZMQ_SNDMORE));
    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, "World", 5, ZMQ_SNDMORE));
    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, "Test", 4, 0));
    
    /* Following should fail because receive must be called before a second send can be done */
    TEST_ASSERT_EQUAL_INT(-1, zmq_send(dummy_zmq_sock, "Hello", 5, 0));
}

