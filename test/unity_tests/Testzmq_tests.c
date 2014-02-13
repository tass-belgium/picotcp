#include "unity.h"
#include "zmq_tests.h"
#include "pico_zmq.c"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "Mockpico_zmtp.h"
#include "Mockpico_ipv4.h"
#include "Mockpico_vector.h"
#include "Mockpico_zalloc.h"

struct zmtp_socket dummy_zmtp_sock;
volatile pico_err_t pico_err;

void setUp(void)
{
}

void tearDown(void)
{
}

void test_zmq_socket_req(void)
{
    struct zmq_socket_base* temp = NULL;
    struct zmq_socket_req req_sock;
    
    /* Make pico_zalloc return NULL */
    pico_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_req), NULL);
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMTP_TYPE_REQ));
    
    /* Make pico_zmtp_open return NULL */
    pico_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_req), &req_sock);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_REQ, &cb_zmtp_sockets, NULL);
    pico_free_Expect(&req_sock);
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMTP_TYPE_REQ));

    /* Normal situation */
    pico_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_req), &req_sock);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_REQ, &cb_zmtp_sockets, &dummy_zmtp_sock);
    pico_vector_init_ExpectAndReturn(&req_sock.base.in_vector, 5, sizeof(struct zmq_msg_t), 0);
    pico_vector_init_ExpectAndReturn(&req_sock.base.out_vector, 5, sizeof(struct zmq_msg_t), 0);
    
    temp = (struct zmq_socket_base *)zmq_socket(NULL, ZMTP_TYPE_REQ);
    TEST_ASSERT_NOT_NULL(temp);
    TEST_ASSERT_EQUAL(ZMTP_TYPE_REQ, temp->type);
    TEST_ASSERT_EQUAL_PTR(&dummy_zmtp_sock, temp->sock);
    TEST_ASSERT_EQUAL_PTR(&req_sock.base.in_vector, &temp->in_vector);
    TEST_ASSERT_EQUAL_PTR(&req_sock.base.out_vector, &temp->out_vector);

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

//void test_zmq_connect(void)
//{
//    void *dummy_ptr = NULL;
//    
//    pico_string_to_ipv4_StubWithCallback(&pico_string_to_ipv4_cb);
//    zmtp_socket_connect_IgnoreAndReturn(0);
//    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(NULL, NULL));
//    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(&dummy_ptr, NULL));
//    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(NULL, "tcp://127.0.0.1:5555"));
//}

//void test_zmq_req_send(void)
//{
//    struct zmq_socket_base* dummy_zmq_sock = NULL;
//    struct zmtp_socket dummy_zmtp_sock;
//    struct zmtp_frame_t* zmtp_frame;
//    uint8_t* test_data = "Testdata";
//    struct pico_vector_iterator* it;
//
//    /* Mocking for zmq_socket */
//    zmtp_socket_open_IgnoreAndReturn(&dummy_zmtp_sock);
//
//    /* Creating dummy_zmq_sock */
//    dummy_zmq_sock = zmq_socket(NULL, ZMTP_TYPE_REQ);
//    dummy_zmq_sock->sock = &dummy_zmtp_sock;
//
//    /* Test for bad arguments */
//    TEST_ASSERT_EQUAL_INT(-1, zmq_send(NULL, NULL, 0, 0));
//    
//    /* Test for final frame */
//    zmtp_socket_send_ExpectAndReturn(&dummy_zmtp_sock, &dummy_zmq_sock->out_vector, 0);
//    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, test_data, 5, 0));
//    TEST_ASSERT_EQUAL_INT(0, dummy_zmq_sock->out_vector.size);
//
//    /* Following should fail because receive must be called before a second send can be done */
//    TEST_ASSERT_EQUAL_INT(-1, zmq_send(dummy_zmq_sock, test_data, 5, 0));
//
//    /* Test for more frame */
//    ((struct zmq_socket_req *)dummy_zmq_sock)->send_enable = ZMQ_SEND_ENABLED; //reset the socket
//
//    /* Send 4 more frames */
//    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, test_data, strlen(test_data), ZMQ_SNDMORE));
//    TEST_ASSERT_EQUAL_INT_MESSAGE(1, dummy_zmq_sock->out_vector.size, "Size of out_vector incorrect");
//    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, test_data, strlen(test_data), ZMQ_SNDMORE));
//    TEST_ASSERT_EQUAL_INT_MESSAGE(2, dummy_zmq_sock->out_vector.size, "Size of out_vector incorrect");
//    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, test_data, strlen(test_data), ZMQ_SNDMORE));
//    TEST_ASSERT_EQUAL_INT_MESSAGE(3, dummy_zmq_sock->out_vector.size, "Size of out_vector incorrect");
//    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, test_data, strlen(test_data), ZMQ_SNDMORE));
//    TEST_ASSERT_EQUAL_INT_MESSAGE(4, dummy_zmq_sock->out_vector.size, "Size of out_vector incorrect");
//
//    /* Check the out_vector if it contains all the more frames */
//    it = pico_vector_begin(&dummy_zmq_sock->out_vector);
//    zmtp_frame = it->data;
//    TEST_ASSERT_EQUAL_INT(0, memcmp(zmtp_frame->buf, test_data, strlen(test_data)));
//    zmtp_frame = pico_vector_iterator_next(it)->data;
//    TEST_ASSERT_EQUAL_INT(0, memcmp(zmtp_frame->buf, test_data, strlen(test_data)));
//    zmtp_frame = pico_vector_iterator_next(it)->data;
//    TEST_ASSERT_EQUAL_INT(0, memcmp(zmtp_frame->buf, test_data, strlen(test_data)));
//    zmtp_frame = pico_vector_iterator_next(it)->data;
//    TEST_ASSERT_EQUAL_INT(0, memcmp(zmtp_frame->buf, test_data, strlen(test_data)));
//
//    TEST_ASSERT_NULL(pico_vector_iterator_next(it)); /* Only 4 frames should be in the vector! */
//
//    zmtp_socket_send_ExpectAndReturn(&dummy_zmtp_sock, &dummy_zmq_sock->out_vector, 0);
//    TEST_ASSERT_EQUAL_INT(0, zmq_send(dummy_zmq_sock, test_data, strlen(test_data), 0));
//
//    TEST_ASSERT_EQUAL_INT_MESSAGE(0, dummy_zmq_sock->out_vector.size, "out_vector should be cleared after passing all the messages to the ZMTP sockets");
//    
//    /* Following should fail because receive must be called before a second send can be done */
//    TEST_ASSERT_EQUAL_INT(-1, zmq_send(dummy_zmq_sock, "Hello", 5, 0));
//}
