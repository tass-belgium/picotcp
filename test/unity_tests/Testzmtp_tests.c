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
    IGNORE_PARAMETER(numCalls);
    TEST_ASSERT_EQUAL(e_pico_s, a_pico_s);
    TEST_ASSERT_EQUAL(e_buf, a_buf);
    TEST_ASSERT_EQUAL_INT(e_len, a_len);
    TEST_ASSERT_EQUAL_MEMORY(e_data, a_buf, e_len);

    return e_len;
}

/* alternative function for pico_socket_write_cb to prevent expect_greeting of changing e_pico_s */
struct pico_socket* e_pico_s_greeting;
int e_len_greeting;
void* e_data_greeting;
int pico_socket_write_greeting_cb(struct pico_socket* a_pico_s, const void* a_buf, int a_len, int numCalls)
{
    IGNORE_PARAMETER(numCalls);
    TEST_ASSERT_EQUAL_PTR(e_pico_s_greeting, a_pico_s);
    TEST_ASSERT_EQUAL_INT(e_len_greeting, a_len);
    TEST_ASSERT_EQUAL_MEMORY(e_data_greeting, a_buf, e_len);

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
    TEST_ASSERT_EQUAL(e_buf, a_buf);
    TEST_ASSERT_EQUAL(e_len, a_len);
    memcpy(a_buf, read_data, (size_t)e_len);
    return e_len;
}

struct pico_socket* pico_socket_accept_cb(struct pico_socket* pico_s, struct pico_ip4* orig, uint16_t* port)
{
    IGNORE_PARAMETER(orig);
    IGNORE_PARAMETER(port);
    TEST_ASSERT_EQUAL_PTR(e_pico_s, pico_s);
    return e_new_pico_s;
}

void test_check_signature(void)
{
    struct zmtp_socket *zmtp_s;
    struct pico_socket *pico_s;
    void* a_buf;
    uint8_t signature[10] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f};

    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    zmtp_s->sock = pico_s;

    e_len = 10;
    a_buf = calloc(1, (size_t)e_len);
    e_buf = a_buf;
    e_pico_s = pico_s;
    read_data = calloc(1, (size_t)e_len);

    /* Good signatures */
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0 ,check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_SIGNATURE, zmtp_s->state);

    signature[8] = 0x01;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0 ,check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_SIGNATURE, zmtp_s->state);

   /* Bad signatures */
    signature[8] = 0x00;
    signature[0] = 0xfe;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1 ,check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_SND_GREETING, zmtp_s->state);

    signature[0] = 0xff;
    signature[9] = 0x8f;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1, check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_SND_GREETING, zmtp_s->state);

    signature[9] = 0x7f;
    signature[4] = 0x90;
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    memcpy(read_data, signature, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1, check_signature(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_SND_GREETING, zmtp_s->state);


    free(zmtp_s);
    free(pico_s);
    free(a_buf);
    free(read_data);
}

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
    void* a_buf;
    uint8_t identity[2] = {0x00, 0x00};


    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    zmtp_s->sock = pico_s;

    e_len = 2;
    a_buf = calloc(1, (size_t)e_len);
    e_buf = a_buf;
    e_pico_s = pico_s;
    read_data = calloc(1, (size_t)e_len);

    /* Empty identity */
    zmtp_s->state = ZMTP_ST_RCVD_TYPE;
    memcpy(read_data, identity, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(0, check_identity(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RDY, zmtp_s->state);

    /* Bad identity flag */
    identity[0] = 0x03;
    zmtp_s->state = ZMTP_ST_RCVD_TYPE;
    memcpy(read_data, identity, (size_t)e_len);
    pico_mem_zalloc_ExpectAndReturn((size_t)e_len, a_buf);
    pico_mem_free_Expect(e_buf);
    pico_socket_read_StubWithCallback(&pico_socket_read_cb);
    TEST_ASSERT_EQUAL(-1, check_identity(zmtp_s));
    TEST_ASSERT_EQUAL(ZMTP_ST_RCVD_TYPE, zmtp_s->state);


    free(pico_s);
    free(zmtp_s);
    free(a_buf);
    free(read_data);
}

void test_zmtp_socket_accept(void)
{
    struct zmtp_socket* zmtp_s;
    struct zmtp_socket* new_zmtp_s;
    struct pico_socket* pico_s;
    struct pico_socket* new_pico_s;

    zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    new_zmtp_s = calloc(1,sizeof(struct zmtp_socket));
    pico_s = calloc(1,sizeof(struct pico_socket));

    zmtp_s->zmq_cb = &zmq_cb_mock;
    zmtp_s->sock = pico_s;
    zmtp_s->type = ZMTP_TYPE_PUB;
    
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), new_zmtp_s);
    e_pico_s = zmtp_s->sock;
    e_new_pico_s = new_pico_s;
    pico_socket_accept_StubWithCallback(&pico_socket_accept_cb);
    pico_tree_insert_IgnoreAndReturn(NULL);

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
}

void test_zmtp_tcp_cb(void)
{
    uint16_t ev;
    struct zmtp_socket* zmtp_s;
    struct pico_socket* pico_s;

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


    TEST_IGNORE();
    /* 
    event: signature available
    expected: read signature if greeting was send
    */
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    ev = PICO_SOCK_EV_RD;
    map_tcp_to_zmtp(zmtp_s);
    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_SIGNATURE, zmtp_s->state);

    /*
    event: revision available
    expected: read revision
    */
    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    ev = PICO_SOCK_EV_RD;
    map_tcp_to_zmtp(zmtp_s);
    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_REVISION, zmtp_s->state);

    /*
    event: socket type available
    expected: read socket type
    */
    zmtp_s->state = ZMTP_ST_RCVD_REVISION;
    ev = PICO_SOCK_EV_RD;
    map_tcp_to_zmtp(zmtp_s);
    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_TYPE, zmtp_s->state);


    /*
    event: empty identity frame available
    expected: read identity length
    */
    zmtp_s->state = ZMTP_ST_RCVD_TYPE;
    ev = PICO_SOCK_EV_RD;
    map_tcp_to_zmtp(zmtp_s);
    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RDY, zmtp_s->state);


    /*
    event: signature and revision availble
    expected: read both
    */
    zmtp_s->state = ZMTP_ST_SND_GREETING;
    ev = PICO_SOCK_EV_RD;
    map_tcp_to_zmtp(zmtp_s);
    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_REVISION, zmtp_s->state);


    /*
    event: revision and type available
    expected: read both
    */
    zmtp_s->state = ZMTP_ST_RCVD_SIGNATURE;
    ev = PICO_SOCK_EV_RD;
    map_tcp_to_zmtp(zmtp_s);
    zmtp_tcp_cb(ev, zmtp_s->sock);
    TEST_ASSERT_EQUAL_UINT8(ZMTP_ST_RCVD_TYPE, zmtp_s->state);



    free(zmtp_s);
    free(pico_s);
}


void test_zmtp_socket_send_1msg_0char(void)
{
/*
    mocking variables
    void* aBytestream: actual bytestream, used as return value of the mocked pico_zalloc
    
    expected variables
    void* eBytestream: expected bytestream, 
    int eBytestreamLen: expected bytestream length
*/

    /* mocking variables */

    /* expected variables */
    void* eBytestream;
    size_t eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    struct pico_vector* out_buff;
    struct pico_socket* pico_s;
    uint8_t*  sendbuffer;
    struct pico_vector_iterator* it;
    struct pico_vector_iterator* prevIt;
    struct pico_vector_iterator* buffIt;

    struct zmtp_frame_t* frame1;
    struct zmtp_frame_t* frame2;

    size_t msg1Len;
    uint8_t* msg1;
    
    uint8_t i;
    uint8_t* bytestreamPtr;

    it = calloc(1, sizeof(struct pico_vector_iterator));
    prevIt = calloc(1, sizeof(struct pico_vector_iterator));
    buffIt = calloc(1, sizeof(struct pico_vector_iterator));
    sendbuffer = calloc(1, (size_t) 255);
    out_buff = calloc(1, sizeof(struct pico_vector));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    vec = calloc(1, sizeof(struct pico_vector));

    zmtp_s->sock = pico_s;
    zmtp_s->out_buff = out_buff;
    zmtp_s->state = ZMTP_ST_RDY;

    frame1 = calloc(1, sizeof(struct zmtp_frame_t));
    frame2 = calloc(1, sizeof(struct zmtp_frame_t));

    /* vec 1 msg, 0 char */
    msg1Len = 0;
    eBytestreamLen = 2 + msg1Len;
    msg1 = (uint8_t*)calloc(1, msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;

    eBytestream = calloc(1, eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[1] = 0; 

    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }

    pico_mem_zalloc_IgnoreAndReturn(sendbuffer);/* buffer to copy the to send frame with header*/
    it->data = (void*) frame1;
    pico_vector_begin_ExpectAndReturn(vec, it);
    pico_mem_zalloc_IgnoreAndReturn(prevIt);/* buffer to copy the to send frame with header*/
    pico_vector_begin_ExpectAndReturn(out_buff, NULL); /* if out_buff is NULL, we will directly try to send the existing messages */
    pico_vector_iterator_next_ExpectAndReturn(it, NULL);
    pico_socket_write_ExpectAndReturn(zmtp_s->sock, sendbuffer, (int)eBytestreamLen, 0); /* expect pointer to sendbuff but content of eBytestream */
    pico_vector_iterator_next_ExpectAndReturn(prevIt, NULL);
    
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, sendbuffer, eBytestreamLen);

    free(msg1);
    free(eBytestream);
}

//
void test_zmtp_socket_send_1msg_1char(void)
{
    /* expected variables */
    void* eBytestream;
    int eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    struct pico_vector* out_buff;
    struct pico_socket* pico_s;
    uint8_t*  sendbuffer;
    struct pico_vector_iterator* it;
    struct pico_vector_iterator* prevIt;
    struct pico_vector_iterator* buffIt;

    struct zmtp_frame_t* frame1;
    struct zmtp_frame_t* frame2;

    size_t msg1Len;
    size_t msg2Len;
    uint8_t* msg1;
    uint8_t* msg2;
    
    uint8_t i;
    uint8_t* bytestreamPtr;

    it = calloc(1, sizeof(struct pico_vector_iterator));
    prevIt = calloc(1, sizeof(struct pico_vector_iterator));
    buffIt = calloc(1, sizeof(struct pico_vector_iterator));
    sendbuffer = calloc(1, (size_t) 255);
    out_buff = calloc(1, sizeof(struct pico_vector));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    vec = calloc(1, sizeof(struct pico_vector));

    zmtp_s->sock = pico_s;
    zmtp_s->out_buff = out_buff;
    zmtp_s->state = ZMTP_ST_RDY;

    frame1 = calloc(1, sizeof(struct zmtp_frame_t));
    frame2 = calloc(1, sizeof(struct zmtp_frame_t));

    /* vec 1 msg, 0 char */
    msg1Len = 1;
    eBytestreamLen = 2 + msg1Len;
    msg1 = (uint8_t*)calloc(1, msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;

    eBytestream = calloc(1, eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[1] = (uint8_t) msg1Len; 

    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }

    pico_mem_zalloc_IgnoreAndReturn(sendbuffer);/* buffer to copy the to send frame with header*/
    it->data = (void*) frame1;
    pico_vector_begin_ExpectAndReturn(vec, it);
    pico_mem_zalloc_IgnoreAndReturn(prevIt);/* buffer to copy the to send frame with header*/
    pico_vector_begin_ExpectAndReturn(out_buff, NULL); /* if out_buff is NULL, we will directly try to send the existing messages */
    pico_vector_iterator_next_ExpectAndReturn(it, NULL);
    pico_socket_write_ExpectAndReturn(zmtp_s->sock, sendbuffer, eBytestreamLen, 0); /* expect pointer to sendbuff but content of eBytestream */
    pico_vector_iterator_next_ExpectAndReturn(prevIt, NULL);
    
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, sendbuffer, eBytestreamLen);

    free(msg1);
    free(eBytestream);
}

//    msg1Len = 255;
void test_zmtp_socket_send_1msg_255char(void)
{
    /* expected variables */
    void* eBytestream;
    int eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    struct pico_vector* out_buff;
    struct pico_socket* pico_s;
    uint8_t*  sendbuffer;
    struct pico_vector_iterator* it;
    struct pico_vector_iterator* prevIt;
    struct pico_vector_iterator* buffIt;

    it = calloc(1, sizeof(struct pico_vector_iterator));
    prevIt = calloc(1, sizeof(struct pico_vector_iterator));
    buffIt = calloc(1, sizeof(struct pico_vector_iterator));
    sendbuffer = calloc(1, (size_t) 255);
    out_buff = calloc(1, sizeof(struct pico_vector));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    vec = calloc(1, sizeof(struct pico_vector));

    zmtp_s->sock = pico_s;
    zmtp_s->out_buff = out_buff;
    zmtp_s->state = ZMTP_ST_RDY;

    struct zmtp_frame_t* frame1;
    struct zmtp_frame_t* frame2;
    frame1 = calloc(1, sizeof(struct zmtp_frame_t));
    frame2 = calloc(1, sizeof(struct zmtp_frame_t));
    size_t msg1Len;
    size_t msg2Len;
    uint8_t* msg1;
    uint8_t* msg2;
    
    uint8_t i;
    uint8_t* bytestreamPtr;

    /* vec 1 msg, 255 char */
    msg1Len = 255;
    eBytestreamLen = 2 + msg1Len;
    msg1 = (uint8_t*)calloc(1, msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;

    eBytestream = calloc(1, eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[1] = (uint8_t) msg1Len; 

    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }

    pico_mem_zalloc_IgnoreAndReturn(sendbuffer);/* buffer to copy the to send frame with header*/
    it->data = (void*) frame1;
    pico_vector_begin_ExpectAndReturn(vec, it);
    pico_mem_zalloc_IgnoreAndReturn(prevIt);/* buffer to copy the to send frame with header*/
    pico_vector_begin_ExpectAndReturn(out_buff, NULL); /* if out_buff is NULL, we will directly try to send the existing messages */
    pico_vector_iterator_next_ExpectAndReturn(it, NULL);
    pico_socket_write_ExpectAndReturn(zmtp_s->sock, sendbuffer, eBytestreamLen, 0); /* expect pointer to sendbuff but content of eBytestream */
    pico_vector_iterator_next_ExpectAndReturn(prevIt, NULL);
    
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, sendbuffer, eBytestreamLen);

    free(msg1);
    free(eBytestream);
}

//    //vec 1 msg, 256 char
void test_zmtp_socket_send_1msg_256char(void)
{
    TEST_IGNORE();
    /* expected variables */
    void* eBytestream;
    int eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    struct pico_vector* out_buff;
    struct pico_socket* pico_s;
    uint8_t*  sendbuffer;
    struct pico_vector_iterator* it;
    struct pico_vector_iterator* prevIt;
    struct pico_vector_iterator* buffIt;

    it = calloc(1, sizeof(struct pico_vector_iterator));
    prevIt = calloc(1, sizeof(struct pico_vector_iterator));
    buffIt = calloc(1, sizeof(struct pico_vector_iterator));
    sendbuffer = calloc(1, (size_t) 255);
    out_buff = calloc(1, sizeof(struct pico_vector));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    vec = calloc(1, sizeof(struct pico_vector));

    zmtp_s->sock = pico_s;
    zmtp_s->out_buff = out_buff;
    zmtp_s->state = ZMTP_ST_RDY;

    struct zmtp_frame_t* frame1;
    struct zmtp_frame_t* frame2;
    frame1 = calloc(1, sizeof(struct zmtp_frame_t));
    frame2 = calloc(1, sizeof(struct zmtp_frame_t));
    size_t msg1Len;
    size_t msg2Len;
    uint8_t* msg1;
    uint8_t* msg2;
    
    uint8_t i;
    uint8_t* bytestreamPtr;

    msg1Len = 256;
    eBytestreamLen = 9 + msg1Len;
    msg1 = (uint8_t*)calloc(1, msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;
    eBytestream = calloc(1, eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 2; /* final-long */
    ((uint8_t*)eBytestream)[7] = 1; /* 256 in 8 bytes: 0 0 0 0 0 0 1 0 */
    ((uint8_t*)eBytestream)[8] = 0; 

    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
        *bytestreamPtr = msg1[i];
    }

    pico_mem_zalloc_IgnoreAndReturn(sendbuffer);/* buffer to copy the to send frame with header*/
    it->data = (void*) frame1;
    pico_vector_begin_ExpectAndReturn(vec, it);
    pico_mem_zalloc_IgnoreAndReturn(prevIt);/* buffer to copy the to send frame with header*/
    pico_vector_begin_ExpectAndReturn(out_buff, NULL); /* if out_buff is NULL, we will directly try to send the existing messages */
    pico_vector_iterator_next_ExpectAndReturn(it, NULL);
    pico_socket_write_ExpectAndReturn(zmtp_s->sock, sendbuffer, eBytestreamLen, 0); /* expect pointer to sendbuff but content of eBytestream */
    pico_vector_iterator_next_ExpectAndReturn(prevIt, NULL);
    
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, sendbuffer, eBytestreamLen);

    free(msg1);
    free(eBytestream);
}

void test_zmtp_socket_send_1msg_600char(void)
{
    TEST_IGNORE();/* expected variables */
    void* eBytestream;
    int eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    struct pico_vector* out_buff;
    struct pico_socket* pico_s;
    uint8_t*  sendbuffer;
    struct pico_vector_iterator* it;
    struct pico_vector_iterator* prevIt;
    struct pico_vector_iterator* buffIt;

    it = calloc(1, sizeof(struct pico_vector_iterator));
    prevIt = calloc(1, sizeof(struct pico_vector_iterator));
    buffIt = calloc(1, sizeof(struct pico_vector_iterator));
    sendbuffer = calloc(1, (size_t) 255);
    out_buff = calloc(1, sizeof(struct pico_vector));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    vec = calloc(1, sizeof(struct pico_vector));

    zmtp_s->sock = pico_s;
    zmtp_s->out_buff = out_buff;
    zmtp_s->state = ZMTP_ST_RDY;

    struct zmtp_frame_t* frame1;
    struct zmtp_frame_t* frame2;
    frame1 = calloc(1, sizeof(struct zmtp_frame_t));
    frame2 = calloc(1, sizeof(struct zmtp_frame_t));
    size_t msg1Len;
    size_t msg2Len;
    uint8_t* msg1;
    uint8_t* msg2;
    
    uint8_t i;
    uint8_t* bytestreamPtr;

    msg1Len = 600;
    eBytestreamLen = 9 + msg1Len;
    msg1 = (uint8_t*)calloc(1,msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-long */
    ((uint8_t*)eBytestream)[7] = 2; /* 600 in 8 bytes: 0 0 0 0 0 0 2 88 */
    ((uint8_t*)eBytestream)[8] = 88; /* 512 + 88 */
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
        *bytestreamPtr = msg1[i];
    }

    pico_mem_zalloc_IgnoreAndReturn(sendbuffer);/* buffer to copy the to send frame with header*/
    it->data = (void*) frame1;
    pico_vector_begin_ExpectAndReturn(vec, it);
    pico_mem_zalloc_IgnoreAndReturn(prevIt);/* buffer to copy the to send frame with header*/
    pico_vector_begin_ExpectAndReturn(out_buff, NULL); /* if out_buff is NULL, we will directly try to send the existing messages */
    pico_vector_iterator_next_ExpectAndReturn(it, NULL);
    pico_socket_write_ExpectAndReturn(zmtp_s->sock, sendbuffer, eBytestreamLen, 0); /* expect pointer to sendbuff but content of eBytestream */
    pico_vector_iterator_next_ExpectAndReturn(prevIt, NULL);
    
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, sendbuffer, eBytestreamLen);

    free(msg1);
    free(eBytestream);
}

void test_zmtp_socket_send_2msg_0char_0char(void)
{
    TEST_IGNORE();
    /* expected variables */
    void* eBytestream;
    int eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    struct pico_vector* out_buff;
    struct pico_socket* pico_s;
    uint8_t*  sendbuffer;
    struct pico_vector_iterator* it;
    struct pico_vector_iterator* it2;
    struct pico_vector_iterator* prevIt;
    struct pico_vector_iterator* buffIt;

    it = calloc(1, sizeof(struct pico_vector_iterator));
    it2 = calloc(1, sizeof(struct pico_vector_iterator));
    prevIt = calloc(1, sizeof(struct pico_vector_iterator));
    buffIt = calloc(1, sizeof(struct pico_vector_iterator));
    sendbuffer = calloc(1, (size_t) 255);
    out_buff = calloc(1, sizeof(struct pico_vector));
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    vec = calloc(1, sizeof(struct pico_vector));

    zmtp_s->sock = pico_s;
    zmtp_s->out_buff = out_buff;
    zmtp_s->state = ZMTP_ST_RDY;

    struct zmtp_frame_t* frame1;
    struct zmtp_frame_t* frame2;
    frame1 = calloc(1, sizeof(struct zmtp_frame_t));
    frame2 = calloc(1, sizeof(struct zmtp_frame_t));
    size_t msg1Len;
    size_t msg2Len;
    uint8_t* msg1;
    uint8_t* msg2;
    
    uint8_t i;
    uint8_t* bytestreamPtr;

    msg1Len = 0;
    msg2Len = 0;
    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
    msg1 = (uint8_t*)calloc(1,msg1Len);
    msg2 = (uint8_t*)calloc(1,msg2Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    for(i = 0; i < msg2Len; i++)
        msg2[i] = i;
    frame1->len = msg1Len;
    frame1->buf = msg1;
    frame2->len = msg2Len;
    frame2->buf = msg2;
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
    ((uint8_t*)eBytestream)[1] = 0; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }
    ((uint8_t*)eBytestream)[msg1Len+2+0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[msg1Len+2+1] = 0; 
    for(i = 0; i < msg2Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2 + msg1Len + 2;
        *bytestreamPtr = msg2[i];
    }

    pico_mem_zalloc_IgnoreAndReturn(sendbuffer);/* buffer to copy the to send frame with header*/
    it->data = (void*) frame1;
    pico_vector_begin_ExpectAndReturn(vec, it);
    pico_mem_zalloc_IgnoreAndReturn(prevIt);/* buffer to copy the to send frame with header*/
    pico_vector_begin_ExpectAndReturn(out_buff, NULL); /* if out_buff is NULL, we will directly try to send the existing messages */
    pico_vector_iterator_next_ExpectAndReturn(it, it2);
    pico_socket_write_ExpectAndReturn(zmtp_s->sock, sendbuffer, eBytestreamLen, 0); /* expect pointer to sendbuff but content of eBytestream */
    pico_vector_iterator_next_ExpectAndReturn(prevIt, it);
    /*second message*/
    pico_vector_iterator_next_ExpectAndReturn(it2, it2);
    pico_socket_write_ExpectAndReturn(zmtp_s->sock, sendbuffer, eBytestreamLen, 0); /* expect pointer to sendbuff but content of eBytestream */
    pico_vector_iterator_next_ExpectAndReturn(prevIt, it);
    
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    pico_mem_free_Ignore();
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, sendbuffer, eBytestreamLen);

    free(msg1);
    free(eBytestream);
}
//    msg1Len = 0;
//    msg2Len = 0;
//    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
//    msg1 = (uint8_t*)calloc(1,msg1Len);
//    msg2 = (uint8_t*)calloc(1,msg2Len);
//    for(i = 0; i < msg1Len; i++)
//        msg1[i] = i; 
//    for(i = 0; i < msg2Len; i++)
//        msg2[i] = i;
//    frame1->len = msg1Len;
//    frame1->buf = msg1;
//    frame2->len = msg2Len;
//    frame2->buf = msg2;
//    eBytestream = calloc(1,eBytestreamLen);
//    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
//    ((uint8_t*)eBytestream)[1] = 0; 
//    for(i = 0; i < msg1Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
//        *bytestreamPtr = msg1[i];
//    }
//    ((uint8_t*)eBytestream)[msg1Len+2+0] = 0; /* final-short */
//    ((uint8_t*)eBytestream)[msg1Len+2+1] = 0; 
//    for(i = 0; i < msg2Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2 + msg1Len + 2;
//        *bytestreamPtr = msg2[i];
//    }
//    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
//    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
//    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
//    
//    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
//    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);
//
//    free(msg1);
//    free(msg2);
//    free(aBytestream);
//    free(eBytestream);
//
//
//    //vec 2 msg, 0 char, 1 char
//    msg1Len = 0;
//    msg2Len = 1;
//    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
//    msg1 = (uint8_t*)calloc(1,msg1Len);
//    msg2 = (uint8_t*)calloc(1,msg2Len);
//    for(i = 0; i < msg1Len; i++)
//        msg1[i] = i; 
//    for(i = 0; i < msg2Len; i++)
//        msg2[i] = i;
//    frame1->len = msg1Len;
//    frame1->buf = msg1;
//    frame2->len = msg2Len;
//    frame2->buf = msg2;
//    aBytestream = calloc(1,eBytestreamLen);
//    eBytestream = calloc(1,eBytestreamLen);
//    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
//    ((uint8_t*)eBytestream)[1] = 0; 
//    for(i = 0; i < msg1Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
//        *bytestreamPtr = msg1[i];
//    }
//    ((uint8_t*)eBytestream)[msg1Len+2+0] = 0; /* final-short */
//    ((uint8_t*)eBytestream)[msg1Len+2+1] = 1; 
//    for(i = 0; i < msg2Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2 + msg1Len + 2;
//        *bytestreamPtr = msg2[i];
//    }
//    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
//    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
//    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
//    
//    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
//    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);
//
//    free(msg1);
//    free(msg2);
//    free(aBytestream);
//    free(eBytestream);
//
//
//    //vec 2 msg, 1 char, 0 char
//    msg1Len = 1;
//    msg2Len = 0;
//    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
//    msg1 = (uint8_t*)calloc(1,msg1Len);
//    msg2 = (uint8_t*)calloc(1,msg2Len);
//    for(i = 0; i < msg1Len; i++)
//        msg1[i] = i; 
//    for(i = 0; i < msg2Len; i++)
//        msg2[i] = i;
//    frame1->len = msg1Len;
//    frame1->buf = msg1;
//    frame2->len = msg2Len;
//    frame2->buf = msg2;
//    aBytestream = calloc(1,eBytestreamLen);
//    eBytestream = calloc(1,eBytestreamLen);
//    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
//    ((uint8_t*)eBytestream)[1] = 1; 
//    for(i = 0; i < msg1Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
//        *bytestreamPtr = msg1[i];
//    }
//    ((uint8_t*)eBytestream)[msg1Len+2+0] = 0; /* final-short */
//    ((uint8_t*)eBytestream)[msg1Len+2+1] = 0; 
//    for(i = 0; i < msg2Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2 + msg1Len + 2;
//        *bytestreamPtr = msg2[i];
//    }
//    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
//    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
//    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
//    
//    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
//    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);
//
//    free(msg1);
//    free(msg2);
//    free(aBytestream);
//    free(eBytestream);
//
//
//    //vec 2 msg, 255 char, 255 char
//    msg1Len = 255;
//    msg2Len = 255;
//    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
//    msg1 = (uint8_t*)calloc(1,msg1Len);
//    msg2 = (uint8_t*)calloc(1,msg2Len);
//    for(i = 0; i < msg1Len; i++)
//        msg1[i] = i; 
//    for(i = 0; i < msg2Len; i++)
//        msg2[i] = i;
//    frame1->len = msg1Len;
//    frame1->buf = msg1;
//    frame2->len = msg2Len;
//    frame2->buf = msg2;
//    aBytestream = calloc(1,eBytestreamLen);
//    eBytestream = calloc(1,eBytestreamLen);
//    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
//    ((uint8_t*)eBytestream)[1] = 255; 
//    for(i = 0; i < msg1Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
//        *bytestreamPtr = msg1[i];
//    }
//    ((uint8_t*)eBytestream)[msg1Len+2+0] = 0; /* final-short */
//    ((uint8_t*)eBytestream)[msg1Len+2+1] = 255; 
//    for(i = 0; i < msg2Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 2 + msg1Len + 2;
//        *bytestreamPtr = msg2[i];
//    }
//    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
//    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
//    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
//    
//    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
//    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);
//
//    free(msg1);
//    free(msg2);
//    free(aBytestream);
//    free(eBytestream);
//
//
//    //vec 2 msg, 256 char, 255 char
//    msg1Len = 256;
//    msg2Len = 255;
//    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
//    msg1 = (uint8_t*)calloc(1,msg1Len);
//    msg2 = (uint8_t*)calloc(1,msg2Len);
//    for(i = 0; i < msg1Len; i++)
//        msg1[i] = i; 
//    for(i = 0; i < msg2Len; i++)
//        msg2[i] = i;
//    frame1->len = msg1Len;
//    frame1->buf = msg1;
//    frame2->len = msg2Len;
//    frame2->buf = msg2;
//    aBytestream = calloc(1,eBytestreamLen);
//    eBytestream = calloc(1,eBytestreamLen);
//    ((uint8_t*)eBytestream)[0] = 3; /* more-long */
//    ((uint8_t*)eBytestream)[7] = 1; 
//    for(i = 0; i < msg1Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
//        *bytestreamPtr = msg1[i];
//    }
//    ((uint8_t*)eBytestream)[msg1Len+9+0] = 0; /* final-short */
//    ((uint8_t*)eBytestream)[msg1Len+9+1] = 255; 
//    for(i = 0; i < msg2Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 9 + msg1Len + 2;
//        *bytestreamPtr = msg2[i];
//    }
//    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
//    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
//    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
//    
//    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
//    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);
//
//    free(msg1);
//    free(msg2);
//    free(aBytestream);
//    free(eBytestream);
//
//
//    //vec 2 msg, 600 char, 255 char
//    msg1Len = 600;
//    msg2Len = 255;
//    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
//    msg1 = (uint8_t*)calloc(1,msg1Len);
//    msg2 = (uint8_t*)calloc(1,msg2Len);
//    for(i = 0; i < msg1Len; i++)
//        msg1[i] = i; 
//    for(i = 0; i < msg2Len; i++)
//        msg2[i] = i;
//    frame1->len = msg1Len;
//    frame1->buf = msg1;
//    frame2->len = msg2Len;
//    frame2->buf = msg2;
//    aBytestream = calloc(1,eBytestreamLen);
//    eBytestream = calloc(1,eBytestreamLen);
//    ((uint8_t*)eBytestream)[0] = 3; /* more-long */
//    ((uint8_t*)eBytestream)[7] = 2; 
//    ((uint8_t*)eBytestream)[8] = 88; 
//    for(i = 0; i < msg1Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
//        *bytestreamPtr = msg1[i];
//    }
//    ((uint8_t*)eBytestream)[msg1Len+9+0] = 0; /* final-short */
//    ((uint8_t*)eBytestream)[msg1Len+9+1] = 255; 
//    for(i = 0; i < msg2Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 9 + msg1Len + 2;
//        *bytestreamPtr = msg2[i];
//    }
//    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
//    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
//    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
//    
//    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
//    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);
//
//    free(msg1);
//    free(msg2);
//    free(aBytestream);
//    free(eBytestream);
//
//
//    //vec 2 msg, 600 char, 256 char
//    msg1Len = 600;
//    msg2Len = 256;
//    eBytestreamLen = (2 + msg1Len) + (2 + msg2Len);
//    msg1 = (uint8_t*)calloc(1,msg1Len);
//    msg2 = (uint8_t*)calloc(1,msg2Len);
//    for(i = 0; i < msg1Len; i++)
//        msg1[i] = i; 
//    for(i = 0; i < msg2Len; i++)
//        msg2[i] = i;
//    frame1->len = msg1Len;
//    frame1->buf = msg1;
//    frame2->len = msg2Len;
//    frame2->buf = msg2;
//    aBytestream = calloc(1,eBytestreamLen);
//    eBytestream = calloc(1,eBytestreamLen);
//    ((uint8_t*)eBytestream)[0] = 3; /* more-long */
//    ((uint8_t*)eBytestream)[7] = 2; 
//    ((uint8_t*)eBytestream)[8] = 88; 
//    for(i = 0; i < msg1Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
//        *bytestreamPtr = msg1[i];
//    }
//    ((uint8_t*)eBytestream)[msg1Len+9+0] = 2; /* final-long */
//    ((uint8_t*)eBytestream)[msg1Len+9+7] = 1; 
//    for(i = 0; i < msg2Len; i++)
//    {
//        bytestreamPtr = (uint8_t*)eBytestream + i + 9 + msg1Len + 9;
//        *bytestreamPtr = msg2[i];
//    }
//    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
//    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
//    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
//    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
//    
//    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
//    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);
//
//    free(msg1);
//    free(msg2);
//    free(aBytestream);
//    free(eBytestream);
//
//    free(frame1);
//    free(frame2);
//}

void dummy_callback(uint16_t ev, struct zmtp_socket*s)
{
    TEST_FAIL();
}

/* set callback_include_count to false! */
int stub_callback1(struct pico_socket* zmtp_s, const void* buf, int len, int numCalls)
{
    uint8_t greeting[14] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x01, ZMTP_TYPE_REQ, 0x00, 0x00};
    int greeting_len = 14;

    TEST_ASSERT_EQUAL_INT(greeting_len, len);
    TEST_ASSERT_EQUAL_MEMORY(greeting, buf, greeting_len);
    
    return 0;
}

void zmtp_socket_callback(uint16_t ev, struct zmtp_socket* s)
{

}

void test_zmtp_socket_connect(void)
{
    TEST_IGNORE();
    /* Only supporting zmtp2.0 (whole greeting send at once) */

    /* Add tests for NULL arguments */ 

    struct zmtp_socket* zmtp_s;
    void* srv_addr;
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
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    zmtp_s->sock = pico_s;
    struct pico_vector* vector = calloc(1, sizeof(struct pico_vector));
    parent = calloc(1, 3); /* dummy size */
    zmtp_s->out_buff = vector;
    /* Test */
    /*----=== Test invalid arguments ===----*/
    /* test type < 0 */
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, -1, parent, &zmtp_socket_callback));

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
    TEST_IGNORE();
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
   TEST_ASSERT_EQUAL_INT(0, zmtp_socket_bind(zmtp_s, NULL, &port));
   
}

void test_zmtp_socket_close(void)
{
    struct zmtp_socket* zmtp_s;
    struct pico_socket* pico_s;
    struct pico_vector* buff;
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    buff = calloc(1, sizeof(struct pico_vector));
    int i = 2;

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
    vec->size--;
    return calloc(1, sizeof(struct pico_vector));
}

int pico_vector_push_back_stub(struct pico_vector* vec, void* data, int numCalls)
{
    vec->size++;
    return 0;
}

struct iterator_emulator {
    int count;
    void* data;
};
struct pico_vector_iterator* pico_vector_begin_stub(const struct pico_vector* vec, int numCalls)
{
    if (0 != vec->size)
    {
        struct iterator_emulator* it = malloc(sizeof(struct pico_vector_iterator));
        it->count = vec->size;
        it->data = (void*) it; /*just to have some data*/
        return (struct pico_vector_iterator*) it;
    } else {
        return NULL;
    }
}

struct pico_vector_iterator* pico_vector_iterator_next_stub(struct pico_vector_iterator* iterator, int numCalls)
{
    struct iterator_emulator* it = (struct iterator_emulator*) iterator;
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
    return 0;
}

int pico_socket_write_stub_fail(struct pico_socket* s, const void* buff, int len, int numCalls)
{
    return -1;
}


void test_zmtp_socket_send2(void)
{
    TEST_IGNORE();
    /*function will be refactored to only send once per message*/
    struct pico_vector* messages;
    struct zmtp_socket* sock;
    struct pico_socket* pico_s;
    uint8_t* sendbuffer = calloc(1, sizeof(255));
    int msgSize = 5;
    pico_s = calloc(1, sizeof(struct pico_vector));
    messages = calloc(1, sizeof(struct pico_vector));
    sock = calloc(1, sizeof(struct zmtp_socket));
    sock->sock = pico_s;
    sock->out_buff = calloc(1, sizeof(struct pico_vector));
    sock->out_buff->size = 0;
    sock->state = ZMTP_ST_IDLE;
    pico_vector_pop_front_StubWithCallback(pico_vector_pop_front_stub);
    pico_vector_push_back_StubWithCallback(pico_vector_push_back_stub);
    pico_vector_begin_StubWithCallback(pico_vector_begin_stub);
    pico_vector_iterator_next_StubWithCallback(pico_vector_iterator_next_stub);
    pico_mem_zalloc_IgnoreAndReturn(sendbuffer);
    pico_mem_free_Ignore();
    messages->size = msgSize; 
    /*  Test if messages are queued if socket state is not ready,
        The vector may not be altered */
    zmtp_socket_send(sock, messages);
    TEST_ASSERT_EQUAL_INT(msgSize, messages->size);
    TEST_ASSERT_EQUAL_INT(msgSize, sock->out_buff->size);
    
}

void test_save2OutBuffer(void)
{
    struct pico_vector* buffer = calloc(1, sizeof(struct pico_vector));
    struct pico_vector_iterator* it = calloc(1, sizeof(struct pico_vector_iterator));
    struct zmtp_frame_t* frame = calloc(1, sizeof(struct zmtp_frame_t));
    struct zmtp_frame_t* emptyFrame = calloc(1, sizeof(struct zmtp_frame_t));
    int datalen = 20;
    void* emptyBuff = calloc(1, (size_t) datalen + 2);
    char data[datalen]; 
    int i;
    for(i=0; i<datalen; i++)
    {
        data[i] = i;
    }
    frame->buf = data;
    frame->len = datalen;

    it->data = frame;
    /*Test Nullpointer handling*/
    TEST_ASSERT_EQUAL_INT(-1, save2OutBuffer(NULL, it));
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_frame_t), NULL);
    TEST_ASSERT_EQUAL_INT(-1, save2OutBuffer(buffer, it));
    
    /*Test final frame (last frame in vector)*/
    pico_mem_zalloc_ExpectAndReturn(sizeof(struct zmtp_frame_t), emptyFrame);
    pico_vector_iterator_next_ExpectAndReturn(it, NULL);
    pico_mem_zalloc_ExpectAndReturn(datalen+2, emptyBuff); 
    pico_vector_push_back_ExpectAndReturn(buffer, emptyFrame, 0);
    TEST_ASSERT_EQUAL_INT(0, save2OutBuffer(buffer, it));
}
