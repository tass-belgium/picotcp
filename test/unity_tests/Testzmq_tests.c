#include "unity.h"
#include "pico_zmq.c"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "Mockpico_zmtp.h"
#include "Mockpico_ipv4.h"
#include "Mockpico_vector.h"
#include "Mockpico_mm.h"


int pico_string_to_ipv4_cb(const char* ipstr, uint32_t *ip, int cmock_num_calls);

struct zmtp_socket dummy_zmtp_sock;
volatile pico_err_t pico_err;
uint32_t* addr_pointer_to_verify;

void setUp(void)
{
}

void tearDown(void)
{
}

static void init_normal_publisher_socket(struct zmq_socket_pub* pub)
{
     /* Normal situation */
     pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_pub), pub);
     zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_PUB, pub, &cb_zmtp_sockets, &dummy_zmtp_sock);
     pico_vector_init_ExpectAndReturn(&pub->base.in_vector, 5, sizeof(struct zmq_msg_t), 0);
     pico_vector_init_ExpectAndReturn(&pub->base.out_vector, 5, sizeof(struct zmq_msg_t), 0);
     pico_vector_init_ExpectAndReturn(&pub->subscribers, 5, sizeof(struct zmq_sock_flag_pair), 0);
     pico_vector_init_ExpectAndReturn(&pub->subscriptions, 5, sizeof(struct zmq_sub_sub_pair), 0);
}


void test_zmq_socket_req(void)
{
    struct zmq_socket_base* temp = NULL;
    struct zmq_socket_req req_sock;
    
    /* Make pico_mem_zalloc return NULL */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_req), NULL);
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMTP_TYPE_REQ));
    
    /* Make pico_zmtp_open return NULL */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_req), &req_sock);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_REQ, &req_sock, &cb_zmtp_sockets, NULL);
    pico_mem_free_Expect(&req_sock);
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMTP_TYPE_REQ));

    /* Normal situation */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_req), &req_sock);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_REQ, &req_sock, &cb_zmtp_sockets, &dummy_zmtp_sock);
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

int zmtp_socket_bind_cb(struct zmtp_socket* s,  void* local_addr, uint16_t* port, int cmock_num_calls)
{
    IGNORE_PARAMETER(cmock_num_calls);
    TEST_ASSERT_EQUAL_PTR(s, &dummy_zmtp_sock);
    TEST_ASSERT_EQUAL_PTR(addr_pointer_to_verify, local_addr);
    TEST_ASSERT_EQUAL_INT(short_be(5555), *port);
    return 0;
}

void test_zmq_socket_pub(void)
{
    struct zmq_socket_pub* temp = NULL;
    struct zmq_socket_pub pub_sock;

    /* Make pico_mem_zalloc return NULL */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_pub), NULL);
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMTP_TYPE_PUB));

    /* Make pico_zmtp_open return NULL */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_pub), &pub_sock);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_PUB, &pub_sock, &cb_zmtp_sockets, NULL);
    pico_mem_free_Expect(&pub_sock);
    TEST_ASSERT_NULL(zmq_socket(NULL, ZMTP_TYPE_PUB));

    /* Normal situation */
    init_normal_publisher_socket(&pub_sock);

    temp = (struct zmq_socket_pub *)zmq_socket(NULL, ZMTP_TYPE_PUB);
    TEST_ASSERT_NOT_NULL(temp);
    TEST_ASSERT_EQUAL_PTR(&pub_sock, temp);
    TEST_ASSERT_EQUAL(ZMTP_TYPE_PUB, temp->base.type);
    
    /* Bind the socket with bad arguments */
    TEST_ASSERT_EQUAL_INT(-1, zmq_bind(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, zmq_bind(temp, NULL));
    TEST_ASSERT_EQUAL_INT(-1, zmq_bind(NULL, "tcp://*:5555"));
    temp->base.type = ZMTP_TYPE_REQ;
    TEST_ASSERT_EQUAL_INT(-1, zmq_bind(temp, "tcp://*:5555")); /* Pass wrong socket type */
    temp->base.type = ZMTP_TYPE_PUB;

    /* Bind the socket with good arguments */
    zmtp_socket_bind_StubWithCallback(&zmtp_socket_bind_cb);
    pico_string_to_ipv4_StubWithCallback(&pico_string_to_ipv4_cb);
    TEST_ASSERT_EQUAL_INT(0, zmq_bind(temp, "tcp://*:5555"));
}

void test_zmq_add_subscription(void)
{
    struct zmq_socket_pub pub;
    struct zmtp_socket test_zmtp_sock;
    struct zmq_sub_sub_pair pair;
    struct pico_vector_iterator it;

    pair.subscription = calloc(1, 6);
    strncpy(pair.subscription, "Hello", 6);

    init_normal_publisher_socket(&pub);
    zmq_socket(NULL, ZMTP_TYPE_PUB);

    /* Insert new subscription into the subscriptions list */
    pico_vector_begin_ExpectAndReturn(&pub.subscriptions, NULL);    /* Simulate empty subscriptions vector */
    pico_mem_zalloc_ExpectAndReturn(strlen(pair.subscription)+1, pair.subscription);
    pico_vector_init_IgnoreAndReturn(0);    /* Init subscriberslist of the newly created subscription */
    pico_vector_push_back_IgnoreAndReturn(0); 
    add_subscription(pair.subscription, strlen(pair.subscription)+1, &pub, &test_zmtp_sock);

    /* Add new subscriber to existing subscription */
    it.data = &pair;
    pico_vector_begin_ExpectAndReturn(&pub.subscriptions, &it);
    pico_vector_push_back_IgnoreAndReturn(0);
    pico_mem_free_Expect(&it);

    add_subscription(pair.subscription, strlen(pair.subscription)+1, &pub, &test_zmtp_sock);
    
}

void test_zmq_socket_pub_add_subscriber_to_publisher(void)
{
    struct zmq_socket_pub pub;
    struct zmtp_socket test_zmtp_sock;
    
    init_normal_publisher_socket(&pub);
    zmq_socket(NULL, ZMTP_TYPE_PUB);

    /* Test for NULL arguments */
    TEST_ASSERT_EQUAL_INT(-1, add_subscriber_to_publisher(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, add_subscriber_to_publisher(&pub, NULL));
    TEST_ASSERT_EQUAL_INT(-1, add_subscriber_to_publisher(NULL, &test_zmtp_sock));

    /* Test for wrong socket type */
    pub.base.type = ZMTP_TYPE_REQ;
    TEST_ASSERT_EQUAL_INT(-1, add_subscriber_to_publisher(&pub, &test_zmtp_sock));
    pub.base.type = ZMTP_TYPE_PUB;
    /* Normal situation */
    pico_vector_push_back_IgnoreAndReturn(0);

    add_subscriber_to_publisher(&pub, &test_zmtp_sock);
}


int pico_string_to_ipv4_cb(const char *ipstr, uint32_t *ip, int cmock_num_calls)
{
    IGNORE_PARAMETER(cmock_num_calls);
    IGNORE_PARAMETER(ipstr);
    addr_pointer_to_verify = ip;
    return 0;
}

int zmtp_socket_connect_cb(struct zmtp_socket* s, void* srv_addr, uint16_t remote_port, int cmock_num_calls)
{
    IGNORE_PARAMETER(cmock_num_calls);
    IGNORE_PARAMETER(s);
    TEST_ASSERT_EQUAL_PTR(addr_pointer_to_verify, srv_addr);
    TEST_ASSERT_EQUAL_INT(45845, remote_port);    //45854 = short_be(5555)
    return 0;
}

void test_zmq_req_connect(void)
{
    struct zmq_socket_base* temp = NULL;
    struct zmq_socket_req req_sock;

    /* Test for bad arguments */
    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(NULL, "tcp://10.40.0.1:5555"));
    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(&req_sock, NULL));
    TEST_ASSERT_EQUAL_INT(-1, zmq_connect(NULL, NULL));

    /* Test normal situation */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_req), &req_sock);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_REQ, &req_sock, &cb_zmtp_sockets, &dummy_zmtp_sock);
    pico_vector_init_ExpectAndReturn(&req_sock.base.in_vector, 5, sizeof(struct zmq_msg_t), 0);
    pico_vector_init_ExpectAndReturn(&req_sock.base.out_vector, 5, sizeof(struct zmq_msg_t), 0);
    
    temp = (struct zmq_socket_base *)zmq_socket(NULL, ZMTP_TYPE_REQ);

    addr_pointer_to_verify = calloc(sizeof(uint32_t), 1);
    pico_string_to_ipv4_StubWithCallback(&pico_string_to_ipv4_cb);
    zmtp_socket_connect_StubWithCallback(&zmtp_socket_connect_cb);
    TEST_ASSERT_EQUAL_INT(0, zmq_connect(temp, "tcp://10.40.0.1:5555"));
}

void test_send_pub(void)
{
    struct zmq_socket_pub psock;
    struct pico_vector vector;
    struct pico_vector_iterator it_marked; /* Iterator that will point to the marked pair */
    struct pico_vector_iterator it_not_marked; /* Iterator that will point to the NOT marked pair */
    struct zmq_sock_flag_pair pair_marked; /* Has mark = MARK_SOCKET_TO_SEND */
    struct zmq_sock_flag_pair pair_not_marked; /* Has mark = CLEAR_MARK_SOCKET_TO_SEND */
    struct zmtp_socket zmtp_sock;
    
    /* Test for NULL arguments */
    TEST_ASSERT_EQUAL_INT(-1, send_pub(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, send_pub(NULL, &vector));
    TEST_ASSERT_EQUAL_INT(-1, send_pub(&psock, NULL));

    /* Test for wrong socket type */
    psock.base.type = ZMTP_TYPE_REQ;
    TEST_ASSERT_EQUAL_INT(-1, send_pub(&psock, &vector));

    /* Normal situation */
    pair_marked.mark = MARK_SOCKET_TO_SEND;
    pair_marked.socket = &zmtp_sock;
    pair_not_marked.mark = CLEAR_MARK_SOCKET_TO_SEND;
    pair_not_marked.socket = &zmtp_sock;
    psock.subscribers = vector;
    psock.base.type = ZMTP_TYPE_PUB;
    it_marked.data = &pair_marked;
    it_not_marked.data = &pair_not_marked;

    /* Setup for scan_and_mark method */
    pico_vector_begin_ExpectAndReturn(&psock.subscribers, NULL);

    /* Setup for send_pub */
    pico_vector_begin_ExpectAndReturn(&psock.subscribers, &it_marked);
    zmtp_socket_send_ExpectAndReturn(&zmtp_sock, &vector, 0);
    pico_vector_iterator_next_ExpectAndReturn(&it_marked, &it_not_marked);
    pico_vector_iterator_next_ExpectAndReturn(&it_not_marked, NULL);

    TEST_ASSERT_EQUAL_INT(0, send_pub(&psock, &vector));
}

void test_zmq_pub_send(void)
{
    struct zmq_socket_pub pub_sock;
    struct zmtp_socket zmtp_sock;
    const char* test_data = "Hello";
    struct pico_vector_iterator iterator;
    
    /* Create the pub_sock */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmq_socket_pub), &pub_sock);
    zmtp_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMTP_TYPE_PUB, &pub_sock, &cb_zmtp_sockets, &dummy_zmtp_sock);
    pico_vector_init_ExpectAndReturn(&pub_sock.base.in_vector, 5, sizeof(struct zmq_msg_t), 0);
    pico_vector_init_ExpectAndReturn(&pub_sock.base.out_vector, 5, sizeof(struct zmq_msg_t), 0);
    pico_vector_init_ExpectAndReturn(&pub_sock.subscribers, 5, sizeof(struct zmq_sock_flag_pair), 0); 
    pico_vector_init_ExpectAndReturn(&pub_sock.subscriptions, 5, sizeof(struct zmq_sub_sub_pair), 0); 

    zmq_socket(NULL, ZMTP_TYPE_PUB);

    iterator.data = &zmtp_sock;
    
    pico_mem_zalloc_ExpectAndReturn(5, calloc(1, 5));
    //pico_vector_push_back_ExpectAndReturn(&pub_sock.base.out_vector, &frame, 0);
    pico_vector_push_back_IgnoreAndReturn(0);
    pico_vector_begin_ExpectAndReturn(&pub_sock.subscribers, &iterator);
    
    pico_vector_iterator_next_IgnoreAndReturn(NULL);    /* Test for only 1 subscriber so return NULL now */
    
    pico_vector_clear_Expect(&pub_sock.base.out_vector);
    zmtp_socket_send_ExpectAndReturn(&zmtp_sock, &pub_sock.base.out_vector, 0);
    zmq_send(&pub_sock, test_data, strlen(test_data), 0);

}

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
