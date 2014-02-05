#include "unity.h"
#include "zmtp_tests.h"
#include "pico_zmtp.h"
#include "Mockpico_socket.h"
#include <stdint.h>
#include "Mockpico_vector.h"
#include "Mockpico_zalloc.h"

volatile pico_err_t pico_err;

void setUp(void)
{
}

void tearDown(void)
{
}

void test_zmtp_tests_NeedToImplement(void)
{
    TEST_IGNORE();
}

void test_zmtp_socket_send(void)
{
/*
    mocking variables
    void* aBytestream: actual bytestream, used as return value of the mocked pico_zalloc
    
    expected variables
    void* eBytestream: expected bytestream, 
    int eBytestreamLen: expected bytestream length
*/

    /* mocking variables */
    void* aBytestream;

    /* expected variables */
    void* eBytestream;
    int eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    struct pico_socket* pico_s;
    zmtp_s->sock = pico_s;

    struct zmtp_frame_t* frame1;
    struct zmtp_frame_t* frame2;
    frame1 = calloc(1, sizeof(struct zmtp_frame_t));
    frame2 = calloc(1, sizeof(struct zmtp_frame_t));
    int msg1Len;
    int msg2Len;
    uint8_t* msg1;
    uint8_t* msg2;
    
    uint8_t i;
    uint8_t* bytestreamPtr;
    

    /* vec 1 msg, 0 char */
    msg1Len = 0;
    eBytestreamLen = 2 + msg1Len;
    msg1 = (uint8_t*)calloc(1,msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[1] = 0; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }

    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0); /* expect pointer to aBytestream but content of eBytestream */
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(aBytestream);
    free(eBytestream);


    //vec 1 msg, 1 char
    msg1Len = 0;
    eBytestreamLen = 2 + msg1Len;
    msg1 = (uint8_t*)calloc(1,msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[1] = 0; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }

    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(aBytestream);
    free(eBytestream);


    //vec 1 msg, 255 char
    msg1Len = 255;
    eBytestreamLen = 2 + msg1Len;
    msg1 = (uint8_t*)calloc(1,msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[1] = 0; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }

    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(aBytestream);
    free(eBytestream);


    //vec 1 msg, 256 char
    msg1Len = 256;
    eBytestreamLen = 9 + msg1Len;
    msg1 = (uint8_t*)calloc(1,msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 2; /* final-long */
    ((uint8_t*)eBytestream)[7] = 1; /* 256 in 8 bytes: 0 0 0 0 0 0 1 0 */
    ((uint8_t*)eBytestream)[8] = 0; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
        *bytestreamPtr = msg1[i];
    }

    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(aBytestream);
    free(eBytestream);


    //vec 1 msg, 600 char
    msg1Len = 600;
    eBytestreamLen = 9 + msg1Len;
    msg1 = (uint8_t*)calloc(1,msg1Len);
    for(i = 0; i < msg1Len; i++)
        msg1[i] = i; 
    frame1->len = msg1Len;
    frame1->buf = msg1;
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 0; /* final-long */
    ((uint8_t*)eBytestream)[7] = 2; /* 600 in 8 bytes: 0 0 0 0 0 0 2 88 */
    ((uint8_t*)eBytestream)[8] = 88; /* 512 + 88 */
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
        *bytestreamPtr = msg1[i];
    }

    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(aBytestream);
    free(eBytestream);


    //vec 2 msg, 0 char, 0 char
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
    aBytestream = calloc(1,eBytestreamLen);
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
    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(msg2);
    free(aBytestream);
    free(eBytestream);


    //vec 2 msg, 0 char, 1 char
    msg1Len = 0;
    msg2Len = 1;
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
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
    ((uint8_t*)eBytestream)[1] = 0; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }
    ((uint8_t*)eBytestream)[msg1Len+2+0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[msg1Len+2+1] = 1; 
    for(i = 0; i < msg2Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2 + msg1Len + 2;
        *bytestreamPtr = msg2[i];
    }
    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(msg2);
    free(aBytestream);
    free(eBytestream);


    //vec 2 msg, 1 char, 0 char
    msg1Len = 1;
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
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
    ((uint8_t*)eBytestream)[1] = 1; 
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
    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(msg2);
    free(aBytestream);
    free(eBytestream);


    //vec 2 msg, 255 char, 255 char
    msg1Len = 255;
    msg2Len = 255;
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
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 1; /* more-short */
    ((uint8_t*)eBytestream)[1] = 255; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2;
        *bytestreamPtr = msg1[i];
    }
    ((uint8_t*)eBytestream)[msg1Len+2+0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[msg1Len+2+1] = 255; 
    for(i = 0; i < msg2Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 2 + msg1Len + 2;
        *bytestreamPtr = msg2[i];
    }
    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(msg2);
    free(aBytestream);
    free(eBytestream);


    //vec 2 msg, 256 char, 255 char
    msg1Len = 256;
    msg2Len = 255;
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
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 3; /* more-long */
    ((uint8_t*)eBytestream)[7] = 1; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
        *bytestreamPtr = msg1[i];
    }
    ((uint8_t*)eBytestream)[msg1Len+9+0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[msg1Len+9+1] = 255; 
    for(i = 0; i < msg2Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9 + msg1Len + 2;
        *bytestreamPtr = msg2[i];
    }
    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(msg2);
    free(aBytestream);
    free(eBytestream);


    //vec 2 msg, 600 char, 255 char
    msg1Len = 600;
    msg2Len = 255;
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
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 3; /* more-long */
    ((uint8_t*)eBytestream)[7] = 2; 
    ((uint8_t*)eBytestream)[8] = 88; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
        *bytestreamPtr = msg1[i];
    }
    ((uint8_t*)eBytestream)[msg1Len+9+0] = 0; /* final-short */
    ((uint8_t*)eBytestream)[msg1Len+9+1] = 255; 
    for(i = 0; i < msg2Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9 + msg1Len + 2;
        *bytestreamPtr = msg2[i];
    }
    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(msg2);
    free(aBytestream);
    free(eBytestream);


    //vec 2 msg, 600 char, 256 char
    msg1Len = 600;
    msg2Len = 256;
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
    aBytestream = calloc(1,eBytestreamLen);
    eBytestream = calloc(1,eBytestreamLen);
    ((uint8_t*)eBytestream)[0] = 3; /* more-long */
    ((uint8_t*)eBytestream)[7] = 2; 
    ((uint8_t*)eBytestream)[8] = 88; 
    for(i = 0; i < msg1Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9;
        *bytestreamPtr = msg1[i];
    }
    ((uint8_t*)eBytestream)[msg1Len+9+0] = 2; /* final-long */
    ((uint8_t*)eBytestream)[msg1Len+9+7] = 1; 
    for(i = 0; i < msg2Len; i++)
    {
        bytestreamPtr = (uint8_t*)eBytestream + i + 9 + msg1Len + 9;
        *bytestreamPtr = msg2[i];
    }
    pico_vector_begin_ExpectAndReturn(vec, (struct pico_vector_iterator*)&frame1);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame1, (struct pico_vector_iterator*)&frame2);
    pico_vector_iterator_next_ExpectAndReturn((struct pico_vector_iterator*)&frame2, NULL);
    pico_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
    pico_socket_send_ExpectAndReturn(zmtp_s->sock, aBytestream, eBytestreamLen, 0);
    
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_send(zmtp_s, vec));
    TEST_ASSERT_EQUAL_MEMORY(eBytestream, aBytestream, eBytestreamLen);

    free(msg1);
    free(msg2);
    free(aBytestream);
    free(eBytestream);

    free(frame1);
    free(frame2);
}


void test_zmtp_socket_connect(void)
{
    struct zmtp_socket* zmtp_s;
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    
    struct pico_socket* pico_s;
    zmtp_s->sock = pico_s;

    void* srv_addr;
    uint16_t remote_port = 1320;

    /* Setup mocking objects */
    pico_socket_connect_ExpectAndReturn(zmtp_s->sock, srv_addr, remote_port, 0);

    /* Tests */
    TEST_ASSERT_EQUAL_INT(0, zmtp_socket_connect(zmtp_s, srv_addr, remote_port));
}
