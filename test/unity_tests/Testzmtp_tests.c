#include "unity.h"
#include "pico_zmtp.c"
#include "Mockpico_socket.h"
#include <stdint.h>
#include "Mockpico_vector.h"
#include "Mockpico_mm.h"
#include "Mockpico_tree.h"

volatile pico_err_t pico_err;
#define BLACK 1
struct pico_tree_node LEAF = {
    NULL, /* key */
    &LEAF, &LEAF, &LEAF, /* parent, left,right */
    BLACK, /* color */
};


struct pico_socket* e_pico_s;
struct pico_socket* e_new_pico_s;
struct zmtp_socket* e_zmtp_s;
void* e_buf;
int e_len;
void* read_data;
int read_data_len;
void* e_data;
uint16_t e_ev;
size_t zmq_cb_counter;

void setUp(void)
{
}

void tearDown(void)
{
}

/* parameters to set: e_pico_s, e_buf, e_len e_data*/
int pico_socket_write_cb(struct pico_socket* a_pico_s, const void* a_buf, int a_len, int numCalls)
{
    uint8_t buff[a_len];
    memcpy(buff, a_buf, (size_t)a_len);
    IGNORE_PARAMETER(numCalls);
    TEST_ASSERT_EQUAL(e_pico_s, a_pico_s);
    TEST_ASSERT_EQUAL(e_buf, a_buf);
    TEST_ASSERT_EQUAL_INT(e_len, a_len);
    TEST_ASSERT_EQUAL_MEMORY(e_data, buff, e_len);

    return e_len;
}

/* alternative function for pico_socket_write_cb to prevent expect_greeting of changing e_pico_s */
struct pico_socket* e_pico_s_greeting;
int e_len_greeting;
void* e_data_greeting;
int pico_socket_write_greeting_cb(struct pico_socket* a_pico_s, const void* a_buf, int a_len, int numCalls)
{
    uint8_t buff[a_len];
    memcpy(buff, a_buf, (size_t)a_len);
    IGNORE_PARAMETER(numCalls);
    TEST_ASSERT_EQUAL_PTR(e_pico_s_greeting, a_pico_s);
    TEST_ASSERT_EQUAL_INT(e_len_greeting, a_len);
    TEST_ASSERT_EQUAL_MEMORY(e_data_greeting, buff, e_len);

    free(e_data_greeting);

    return e_len_greeting;
}

void expect_greeting(struct pico_socket *pico_s, uint8_t type)
{
    uint8_t greeting[14] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x01, type, 0x00, 0x00};

    e_len_greeting = 14;
    e_pico_s_greeting = pico_s;

    e_data_greeting = calloc(1, (size_t)e_len_greeting);
    memcpy(e_data_greeting, greeting, (size_t)e_len_greeting);
    pico_socket_write_StubWithCallback(&pico_socket_write_greeting_cb);
}

void map_tcp_to_zmtp(struct zmtp_socket *zmtp_s)
{
    pico_tree_findKey_IgnoreAndReturn(zmtp_s);
}

void zmq_cb_mock(uint16_t ev, struct zmtp_socket* zmtp_s)
{
    TEST_ASSERT_EQUAL_UINT16(e_ev, ev);
    TEST_ASSERT_EQUAL(e_zmtp_s, zmtp_s);
    zmq_cb_counter ++;
    e_ev = 0;
    e_zmtp_s = NULL;
}

/* compares the argument values and writes read_data with lenght e_len into a_buf */
int pico_socket_read_cb(struct pico_socket* a_pico_s, void* a_buf, int a_len, int numCalls)
{
    IGNORE_PARAMETER(numCalls);
    TEST_ASSERT_EQUAL(e_pico_s, a_pico_s);
    TEST_ASSERT_EQUAL(e_len, a_len);
    memcpy(a_buf, read_data, (size_t)read_data_len);
    return read_data_len;
}

struct pico_socket* pico_socket_accept_cb(struct pico_socket* pico_s, void* orig, uint16_t* port, int numCalls)
{
    IGNORE_PARAMETER(numCalls);
    IGNORE_PARAMETER(orig);
    IGNORE_PARAMETER(port);
    TEST_ASSERT_EQUAL_PTR(e_pico_s, pico_s);
    return e_new_pico_s;
}

void test_check_signature(void)
{
    struct zmtp_socket *zmtp_s;
    struct pico_socket *pico_s;
    uint8_t signature[10] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f};

    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    zmtp_s->sock = pico_s;

    e_len = 10;
    e_pico_s = pico_s;
    read_data = calloc(1, (size_t)e_len);
    read_data_len = e_len;

    /* Good signatures */
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0 ,check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_SIGNATURE, zmtp_s->state);

    signature[8] = 0x01;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0 ,check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_SIGNATURE, zmtp_s->state);

   /* Bad signatures */
    signature[8] = 0x00;
    signature[0] = 0xfe;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1 ,check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_SND_GREETING, zmtp_s->state);

    signature[0] = 0xff;
    signature[9] = 0x8f;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1, check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_SND_GREETING, zmtp_s->state);

    signature[9] = 0x7f;
    signature[4] = 0x90;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1, check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_SND_GREETING, zmtp_s->state);


    free(zmtp_s);
    free(pico_s);
    free(read_data);
}

void test_check_revision(void)
{
    struct zmtp_socket *zmtp_s;
    struct pico_socket *pico_s;
    void* a_buf;
    uint8_t revision = 0x01;

    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    zmtp_s->sock = pico_s;

    a_buf = calloc(1, (size_t)e_len);
    e_buf = a_buf;

    /* variables for pico_socket_read_cb */
    e_pico_s = pico_s;
    e_len = 1;
    read_data = calloc(1, (size_t)e_len);
    read_data_len = e_len;
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);

    /* Check for revision 0x01 */
    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    memcpy(read_data, &revision, (size_t)e_len);
    TEST_ASSERT_EQUAL(0, check_revision(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_REVISION, zmtp_s->state);

    /* Check for revision 0x00 */
    revision = 0x00;
    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    memcpy(read_data, &revision, (size_t)e_len);
    TEST_ASSERT_EQUAL(0, check_revision(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_REVISION, zmtp_s->state);

    /* If no data available */
    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    read_data_len = 0;
    TEST_ASSERT_EQUAL(-1, check_revision(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_SIGNATURE, zmtp_s->state);


    free(pico_s);
    free(zmtp_s);
    free(a_buf);
    free(read_data);
}
/*
void test_check_revision(void)
{
    struct zmtp_socket *zmtp_s;
    struct pico_socket *pico_s;
    void* a_buf;
    uint8_t revision[1] = {0x01};


    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    zmtp_s->sock = pico_s;

    e_len = 1;
    a_buf = calloc(1, (size_t)e_len);
    e_buf = a_buf;
    e_pico_s = pico_s;
    read_data = calloc(1, (size_t)e_len);


    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    memcpy(read_data, revision, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0, check_revision(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_REVISION, zmtp_s->state);

    revision[0] = 0x00;
    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    memcpy(read_data, revision, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0, check_revision(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_REVISION, zmtp_s->state);


    free(pico_s);
    free(zmtp_s);
    free(a_buf);
    free(read_data);
}
*/
void test_check_socket_type(void)
{
    struct zmtp_socket *zmtp_s;
    struct pico_socket *pico_s;
    void* a_buf;
    uint8_t type[1] = {0x01};


    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    zmtp_s->sock = pico_s;

    e_len = 1;
    a_buf = calloc(1, (size_t)e_len);
    e_buf = a_buf;
    e_pico_s = pico_s;
    read_data = calloc(1, (size_t)e_len);
    read_data_len = e_len;


    zmtp_s->state = ZMTP_ST_RCVD_REVISION;
    memcpy(read_data, type, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0, check_socket_type(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_TYPE, zmtp_s->state);


    free(pico_s);
    free(zmtp_s);
    free(a_buf);
    free(read_data);
}

void test_check_identity(void)
{
    struct zmtp_socket *zmtp_s;
    struct pico_socket *pico_s;
    uint8_t identity[2] = {0x00, 0x00};


    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    zmtp_s->sock = pico_s;

    e_len = 2;
    e_pico_s = pico_s;
    read_data = calloc(1, (size_t)e_len);
    read_data_len = e_len;

    /* Empty identity */
    zmtp_s->state = ZMTP_ST_RCVD_TYPE;
    memcpy(read_data, identity, (size_t)e_len);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0, check_identity(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RDY, zmtp_s->state);

    /* Bad identity flag */
    identity[0] = 0x03;
    zmtp_s->state = ZMTP_ST_RCVD_TYPE;
    memcpy(read_data, identity, (size_t)e_len);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1, check_identity(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_TYPE, zmtp_s->state);

    free(pico_s);
    free(zmtp_s);
    free(read_data);
}

/* zmq calls zmtp_socket_accept with good args */
void test_zmtp_socket_accept_normal(void)
{
    /* zmtp_s is the listener socket of the publisher, pico_s is its pico socket */
    /* new_zmtp_s is the socket that will be returned by zmtp_socket_accept() */
    struct zmtp_socket* zmtp_s;
    struct zmtp_socket* new_zmtp_s;
    struct pico_socket* pico_s;
    struct pico_socket* new_pico_s;
    struct pico_vector* out_buff;

    new_pico_s = calloc(1,sizeof(struct pico_socket));
    zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    new_zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    pico_s = calloc(1,sizeof(struct pico_socket));
    out_buff = calloc(1,sizeof(struct pico_vector));

    /* setting the members of zmtp_s */
    zmtp_s->zmq_cb = &zmq_cb_mock;
    zmtp_s->sock = pico_s;
    zmtp_s->type = ZMTP_TYPE_PUB;
    
    /* zmtp_socket_accept should accept the pico socket and store it in a new 
       zmtp socket */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), new_zmtp_s);
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct pico_vector), out_buff);

    /* zmtp_socket_accept calls pico_socket_accept to accept the new pico connection */
    /* e_pico_s and e_new_pico_s are global variables used in pico_socket_accept_cb */
    e_pico_s = pico_s;
    e_new_pico_s = new_pico_s;
    pico_socket_accept_StubWithCallback(&pico_socket_accept_cb);

    /* the new zmtp socket should be stored in the pico tree */
    pico_tree_insert_IgnoreAndReturn(NULL);

    /* zmtp sends greeting immediately */
    expect_greeting(new_pico_s, zmtp_s->type);

    new_zmtp_s = zmtp_socket_accept(zmtp_s);
    TEST_ASSERT_EQUAL(ZMTP_ST_SND_GREETING, new_zmtp_s->state);
    TEST_ASSERT_EQUAL(zmtp_s->type, new_zmtp_s->type);
    TEST_ASSERT_EQUAL_PTR(new_pico_s, new_zmtp_s->sock);
    TEST_ASSERT_EQUAL(zmtp_s->zmq_cb, new_zmtp_s->zmq_cb);
    TEST_ASSERT_EQUAL_PTR(zmtp_s->parent, new_zmtp_s->parent);

    free(zmtp_s);
    free(new_zmtp_s);
    free(pico_s);
    free(new_pico_s);
}

/* zmq calls zmtp_socket_accept with zmtp_s is NULL */
void test_zmtp_socket_accept_zmtp_null(void)
{
    TEST_ASSERT_NULL(zmtp_socket_accept(NULL));
}

/* no memory to allocate new zmtp socket */
void test_zmtp_socket_accept_no_mem(void)
{
    struct zmtp_socket* zmtp_s;
    struct pico_socket* pico_s;

    zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    pico_s = calloc(1,sizeof(struct pico_socket));

    zmtp_s->zmq_cb = &zmq_cb_mock;
    zmtp_s->sock = pico_s;
    zmtp_s->type = ZMTP_TYPE_PUB;
    
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), NULL);

    TEST_ASSERT_NULL(zmtp_socket_accept(zmtp_s));

    free(zmtp_s);
    free(pico_s);
}

/* no memory to allocate new out_buff */
void test_zmtp_socket_accept_no_mem2(void)
{
    struct zmtp_socket* zmtp_s;
    struct zmtp_socket* new_zmtp_s;
    struct pico_socket* pico_s;

    zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    new_zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    pico_s = calloc(1,sizeof(struct pico_socket));

    /* setting the members of zmtp_s */
    zmtp_s->zmq_cb = &zmq_cb_mock;
    zmtp_s->sock = pico_s;
    zmtp_s->type = ZMTP_TYPE_PUB;
    
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), new_zmtp_s);
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct pico_vector), NULL);
    pico_mem_free_Expect(new_zmtp_s);

    TEST_ASSERT_NULL(zmtp_socket_accept(zmtp_s));

    free(zmtp_s);
    free(new_zmtp_s);
    free(pico_s);
}

/* Error when trying to read from pico socket*/
void test_zmtp_socket_accept_error_when_reading(void)
{
    struct zmtp_socket* zmtp_s;
    struct zmtp_socket* new_zmtp_s;
    struct pico_socket* pico_s;
    struct pico_vector* out_buff;

    zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    new_zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    pico_s = calloc(1,sizeof(struct pico_socket));
    out_buff = calloc(1,sizeof(struct pico_vector));

    /* setting the members of zmtp_s */
    zmtp_s->zmq_cb = &zmq_cb_mock;
    zmtp_s->sock = pico_s;
    zmtp_s->type = ZMTP_TYPE_PUB;
    
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), new_zmtp_s);
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct pico_vector), out_buff);

    e_pico_s = pico_s;
    e_new_pico_s = NULL;
    pico_socket_accept_StubWithCallback(&pico_socket_accept_cb);

    pico_mem_free_Expect(out_buff);
    pico_mem_free_Expect(new_zmtp_s);

    TEST_ASSERT_NULL(zmtp_socket_accept(zmtp_s));

    free(zmtp_s);
    free(new_zmtp_s);
    free(pico_s);
}
/* TODO: */
/* zmq calls zmtp_socket_accept while pico has no new connection */
/* What is the behaviour of pico_socket_accept in this case? */


void test_zmtp_tcp_cb(void)
{
    uint16_t ev;
    struct zmtp_socket* zmtp_s;
    struct pico_socket* pico_s;

    TEST_IGNORE();
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));

    zmtp_s->sock = pico_s;
    zmtp_s->type = ZMTP_TYPE_PUB;
    zmtp_s->zmq_cb = &zmq_cb_mock;
    
    /* 
    event: connection established 
    expected: callback to zmq
    */
    zmtp_s->state = ZMTP_ST_IDLE;
    ev = PICO_SOCK_EV_CONN;

    map_tcp_to_zmtp(zmtp_s);

    e_zmtp_s = zmtp_s;
    e_ev = ZMTP_EV_CONN;
    zmq_cb_counter = 0;

    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL(1, zmq_cb_counter);

    /* 
    event: signature available
    expected: read signature if greeting was send
    */
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    ev = PICO_SOCK_EV_RD;
    map_tcp_to_zmtp(zmtp_s);
    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_SIGNATURE, zmtp_s->state);

//    /*
//    event: revision available
//    expected: read revision
//    */
//    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
//    ev = PICO_SOCK_EV_RD;
//    map_tcp_to_zmtp(zmtp_s);
//    zmtp_tcp_cb(ev, zmtp_s->sock);
//    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_REVISION, zmtp_s->state);
//
//    /*
//    event: socket type available
//    expected: read socket type
//    */
//    zmtp_s->state = ZMTP_ST_RCVD_REVISION;
//    ev = PICO_SOCK_EV_RD;
//    map_tcp_to_zmtp(zmtp_s);
//    zmtp_tcp_cb(ev, zmtp_s->sock);
//    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_TYPE, zmtp_s->state);
//
//
//    /*
//    event: empty identity frame available
//    expected: read identity length
//    */
//    zmtp_s->state = ZMTP_ST_RCVD_TYPE;
//    ev = PICO_SOCK_EV_RD;
//    map_tcp_to_zmtp(zmtp_s);
//    zmtp_tcp_cb(ev, zmtp_s->sock);
//    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RDY, zmtp_s->state);
//
//
//    /*
//    event: signature and revision availble
//    expected: read both
//    */
//    zmtp_s->state = ZMTP_ST_SND_GREETING;
//    ev = PICO_SOCK_EV_RD;
//    map_tcp_to_zmtp(zmtp_s);
//    zmtp_tcp_cb(ev, zmtp_s->sock);
//    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_REVISION, zmtp_s->state);
//
//
//    /*
//    event: revision and type available
//    expected: read both
//    */
//    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
//    ev = PICO_SOCK_EV_RD;
//    map_tcp_to_zmtp(zmtp_s);
//    zmtp_tcp_cb(ev, zmtp_s->sock);
//    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_TYPE, zmtp_s->state);
//
    free(zmtp_s);
    free(pico_s);
}

void dummy_callback(uint16_t ev, struct zmtp_socket*s)
{
    IGNORE_PARAMETER(ev);
    IGNORE_PARAMETER(s);
    TEST_FAIL();
}

/* set callback_include_count to false! */
int stub_callback1(struct pico_socket* zmtp_s, const void* buf, int len, int numCalls)
{
    uint8_t greeting[14] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x01, ZMTP_TYPE_REQ, 0x00, 0x00};
    int greeting_len = 14;
    uint8_t buff[len];
    memcpy(buff, buf, (size_t) len);
    IGNORE_PARAMETER(numCalls);
    IGNORE_PARAMETER(zmtp_s);

    TEST_ASSERT_EQUAL_INT(greeting_len, len);
    TEST_ASSERT_EQUAL_MEMORY(greeting, buff, greeting_len);
    
    return 0;
}

void zmtp_socket_callback(uint16_t ev, struct zmtp_socket* s)
{
    IGNORE_PARAMETER(ev);
    IGNORE_PARAMETER(s);
}

void test_zmtp_socket_connect(void)
{
    /* Only supporting zmtp2.0 (whole greeting send at once) */

    /* Add tests for NULL arguments */ 

    struct zmtp_socket* zmtp_s;
    void* srv_addr =  NULL;
    uint16_t remote_port = 1320;

    zmtp_s = calloc(1, sizeof(struct zmtp_socket));

    /*----=== Test valid arguments ===----*/
    /* Setup mocking objects */
    pico_socket_connect_ExpectAndReturn(zmtp_s->sock, srv_addr, remote_port, 0);
    //pico_socket_write_StubWithCallback(stub_callback1);

    /* Test */
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_connect(zmtp_s, srv_addr, remote_port));

    /*----=== Test invalid arguments ===----
    The zmq_connect only returns -1 if the zmtp_socket was NULL 
    or if pico_socket_connect returns -1*/

    /* Setup mocking objects */
    pico_socket_connect_ExpectAndReturn(zmtp_s->sock, srv_addr, remote_port, -1);
    /* Test */
    TEST_ASSERT_EQUAL_INT(-1, zmtp_socket_connect(zmtp_s, srv_addr, remote_port));
    TEST_ASSERT_EQUAL_INT(-1, zmtp_socket_connect(NULL, srv_addr, remote_port));
}


void test_zmtp_socket_open(void)
{
    uint16_t net = PICO_PROTO_IPV4;
    uint16_t proto = PICO_PROTO_TCP;
    uint8_t type = ZMTP_TYPE_PUB;
    struct zmtp_socket* zmtp_s;
    struct zmtp_socket* zmtp_ret_s;
    struct pico_socket* pico_s;
    void* parent;
    struct pico_vector* vector;
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s->sock = pico_s;
    vector = calloc(1, sizeof(struct pico_vector));
    parent = calloc(1, 3); /* dummy size */
    zmtp_s->out_buff = vector;
    /* Test */
    /*----=== Test invalid arguments ===----*/
    /* test type < 0 is not possible as type is uint8_t*/

    /* test type = ZMTP_TYPE_END */
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, ZMTP_TYPE_END, parent, &zmtp_socket_callback));

    /* test cb == NULL */
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, parent, NULL));

    /* test parent == NULL */
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, NULL, &zmtp_socket_callback));


    /* test zmtp_sock == NULL */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), NULL);
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, parent, &zmtp_socket_callback));

    /* test outbuff == NULL */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), zmtp_s);
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct pico_vector), NULL);
    pico_mem_free_Expect(zmtp_s);
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, parent, &zmtp_socket_callback));

    /* test pico_sock == NULL */
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), zmtp_s);
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct pico_vector), vector);
    pico_vector_init_IgnoreAndReturn(NULL);
    pico_socket_open_ExpectAndReturn(net, proto, &zmtp_tcp_cb, NULL);
    pico_mem_free_Expect(vector);
    pico_mem_free_Expect(zmtp_s);
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, parent, &zmtp_socket_callback));

    /*----=== Test valid arguments ===----*/
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), zmtp_s);
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct pico_vector), vector);
    pico_socket_open_ExpectAndReturn(net, proto, &zmtp_tcp_cb, pico_s);
    pico_vector_init_IgnoreAndReturn(NULL);
    pico_tree_insert_IgnoreAndReturn(zmtp_s);
 
    zmtp_ret_s = zmtp_socket_open(net, proto, type, parent, &zmtp_socket_callback); 
    TEST_ASSERT_EQUAL_PTR(pico_s, zmtp_ret_s->sock);
    TEST_ASSERT_EQUAL_INT(ZMTP_ST_IDLE, zmtp_ret_s->state);
    TEST_ASSERT_EQUAL_PTR(parent, zmtp_ret_s->parent);

    free(zmtp_s);
    free(pico_s);
    free(parent);
    free(vector);
}


void test_zmtp_socket_bind(void)
{
   struct zmtp_socket* zmtp_s;
   struct pico_socket* pico_s;
   uint16_t port = 23445;

   zmtp_s = calloc(1, sizeof(struct zmtp_socket));
   pico_s = calloc(1, sizeof(struct pico_socket));
   /*----=== Test empty sockets ===----*/
   /*we don't test pico_socket_bind here so we can use whatever value for the local_addr and port*/
   TEST_ASSERT_EQUAL_INT(-1, zmtp_socket_bind(NULL, NULL, &port));
   TEST_ASSERT_EQUAL_INT(-1, zmtp_socket_bind(zmtp_s, NULL, &port));
   pico_socket_bind_IgnoreAndReturn(-1);
   zmtp_s->sock = pico_s;
   TEST_ASSERT_EQUAL_INT(-1, zmtp_socket_bind(zmtp_s, NULL, &port));

   /*----=== Test valid arguments ===----*/
   pico_socket_bind_IgnoreAndReturn(0);
   pico_socket_listen_IgnoreAndReturn(1);
   TEST_ASSERT_EQUAL_INT(0, zmtp_socket_bind(zmtp_s, NULL, &port));
   
}

void test_zmtp_socket_close(void)
{
    struct zmtp_socket* zmtp_s;
    struct pico_socket* pico_s;
    struct pico_vector* buff;
    int i = 2;
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    buff = calloc(1, sizeof(struct pico_vector));

    /*----=== Test empty sockets ===----*/
    if(i > 0)
    TEST_ASSERT_EQUAL_INT(zmtp_socket_close(NULL), -1);
    
    if(i > 1)
    {
    pico_socket_close_ExpectAndReturn(NULL, -1);
    pico_mem_free_Expect(zmtp_s);
    //pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(zmtp_socket_close(zmtp_s),-1);
    }

    if(i > 2)
    {
    zmtp_s->sock = pico_s;
    pico_socket_close_ExpectAndReturn(pico_s, -1);
    pico_mem_free_Expect(zmtp_s->sock);
    pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(zmtp_socket_close(zmtp_s), -1);
    }

    /*----=== Test valid arguments ===----*/
    if(i > 3)
    {
    zmtp_s->out_buff = buff;
    pico_socket_close_IgnoreAndReturn(0);
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    pico_vector_destroy_Expect(buff);
    TEST_ASSERT_EQUAL_INT(zmtp_socket_close(zmtp_s), 0);
    }

    free(zmtp_s);
    free(pico_s);
    free(buff);

}

void test_zmtp_socket_read(void)
{
   struct zmtp_socket* zmtp_s;
   struct pico_socket* pico_s;
   int buffLen = 20;
   char buff[buffLen];
   zmtp_s = calloc(1, sizeof(struct zmtp_socket));
   pico_s = calloc(1, sizeof(struct pico_socket));
   /*----=== Test empty sockets ===----*/
   TEST_ASSERT_EQUAL_INT(zmtp_socket_read(NULL, (void*)buff, buffLen), -1);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_read(zmtp_s, (void*)buff, buffLen), -1);
   /*invalid buff or buffLen should be handled by pico_socket*/

   zmtp_s->sock = pico_s;
   pico_socket_read_IgnoreAndReturn(-1);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_read(zmtp_s, (void*)buff, buffLen), -1);
   /*----=== Test valid arguments ===----*/
   pico_socket_read_IgnoreAndReturn(0);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_read(zmtp_s, (void*)buff, buffLen), 0);

   free(zmtp_s);
   free(pico_s);
}

void * pico_vector_pop_front_stub(struct pico_vector* vec, int numCalls)
{
    IGNORE_PARAMETER(numCalls);
    vec->size--;
    return calloc(1, sizeof(struct pico_vector));
}

int pico_vector_push_back_stub(struct pico_vector* vec, void* data, int numCalls)
{
    IGNORE_PARAMETER(data);
    IGNORE_PARAMETER(numCalls);
    vec->size++;
    return 0;
}

struct iterator_emulator {
    uint8_t count;
    void* data;
};

struct pico_vector_iterator* pico_vector_begin_stub(const struct pico_vector* vec, int numCalls)
{
    IGNORE_PARAMETER(numCalls);
    if (0 != vec->size)
    {
        struct iterator_emulator* it = malloc(sizeof(struct pico_vector_iterator));
        it->count = (uint8_t) vec->size;
        it->data = (void*) it; /*just to have some data*/
        return (struct pico_vector_iterator*) it;
    } else {
        return NULL;
    }
}

struct pico_vector_iterator* pico_vector_iterator_next_stub(struct pico_vector_iterator* iterator, int numCalls)
{
    struct iterator_emulator* it;
    IGNORE_PARAMETER(numCalls);
    it = (struct iterator_emulator*) iterator;
    if (it->count<=1)
    {
        free(it);
        return NULL;
    } else
    {
        (it->count)--;
        return (struct pico_vector_iterator*) it;
    }
}

int pico_socket_write_stub(struct pico_socket* s, const void* buff, int len, int numCalls)
{
    IGNORE_PARAMETER(s);
    IGNORE_PARAMETER(buff);
    IGNORE_PARAMETER(len);
    IGNORE_PARAMETER(numCalls);
    return 0;
}

int pico_socket_write_stub_fail(struct pico_socket* s, const void* buff, int len, int numCalls)
{
    IGNORE_PARAMETER(s);
    IGNORE_PARAMETER(buff);
    IGNORE_PARAMETER(len);
    IGNORE_PARAMETER(numCalls);
    return -1;
}


