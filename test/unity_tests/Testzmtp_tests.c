#include "unity.h"
#include "zmtp_tests.h"
#include "pico_zmtp.c"
#include "Mockpico_socket.h"
#include <stdint.h>
#include "Mockpico_vector.h"
#include "Mockpico_mm.h"

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
    TEST_IGNORE();
/*
    mocking variables
    void* aBytestream: actual bytestream, used as return value of the mocked pico_mem_zalloc
    
    expected variables
    void* eBytestream: expected bytestream, 
    int eBytestreamLen: expected bytestream length
*/

    /* mocking variables */
    void* aBytestream;

    /* expected variables */
    void* eBytestream;
    size_t eBytestreamLen;

    struct pico_vector* vec;
    struct zmtp_socket* zmtp_s;
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    struct pico_socket* pico_s;
    zmtp_s->sock = pico_s;

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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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
    pico_mem_zalloc_ExpectAndReturn(eBytestreamLen, aBytestream);
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

void dummy_callback(uint16_t ev, struct zmtp_socket*s)
{
    TEST_FAIL();
}

/* set callback_include_count to false! */
int stub_callback1(struct pico_socket* s, const void* buf, int len, int numCalls)
{
    uint8_t greeting[14] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x01, ZMTP_TYPE_REQ, 0x00, 0x00};
    int greetingLen = 14;

    TEST_ASSERT_EQUAL_INT(greetingLen, len);
    TEST_ASSERT_EQUAL_MEMORY(greeting, buf, greetingLen);
    TEST_FAIL();
    
    return 0;
}

void zmtp_socket_callback(uint16_t ev, struct zmtp_socket* s)
{

}

void test_zmtp_socket_connect(void)
{
    /* Only supporting zmtp2.0 (whole greeting send at once) */

    /* Add tests for NULL arguments */ 

    struct zmtp_socket* zmtp_s;
    struct pico_socket* pico_s;
    void* srv_addr;
    uint16_t remote_port = 1320;
    uint8_t socket_type = ZMTP_TYPE_REQ;


    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_mem_zalloc_IgnoreAndReturn(NULL);
    /* Setting up zmtp_socket */
    pico_socket_open_ExpectAndReturn(PICO_PROTO_IPV4, PICO_PROTO_TCP, &zmtp_tcp_cb, pico_s);
    zmtp_s = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, socket_type, &zmtp_socket_callback);
    TEST_ASSERT_NOT_NULL(zmtp_s);
    TEST_ASSERT_EQUAL_UINT8(zmtp_s->type, socket_type);

    /*----=== Test valid arguments ===----*/
    /* Setup mocking objects */
    pico_socket_connect_ExpectAndReturn(zmtp_s->sock, srv_addr, remote_port, 0);
    pico_socket_write_StubWithCallback(stub_callback1);

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
    zmtp_s = calloc(1, sizeof(struct zmtp_socket));
    pico_s = calloc(1, sizeof(struct pico_socket));
    /* ---=== Test failing pico_zalloc ===----*/
    //pico_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), NULL);
    //pico_socket_open_IgnoreAndReturn(NULL);
 
    /* Test */
    //TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, &zmtp_socket_callback));
    //TEST_ASSERT_EQUAL_INT(PICO_ERR_ENOMEM, pico_err);     
    /*----=== Test invalid arguments ===----*/
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, -1, &zmtp_socket_callback));
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, ZMTP_TYPE_END, &zmtp_socket_callback));
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, NULL));

    pico_socket_open_ExpectAndReturn(net, proto, &zmtp_tcp_cb, NULL);
    TEST_ASSERT_NULL(zmtp_socket_open(net, proto, type, &zmtp_socket_callback));

    /*----=== Test valid arguments ===----*/
    //pico_zalloc_ExpectAndReturn(sizeof(struct zmtp_socket), zmtp_s);
    pico_socket_open_ExpectAndReturn(net, proto, &zmtp_tcp_cb, pico_s);
    zmtp_ret_s = zmtp_socket_open(net, proto, type, &zmtp_socket_callback); 
    TEST_ASSERT_EQUAL_PTR(pico_s, zmtp_ret_s->sock);
    TEST_ASSERT_EQUAL_INT(ST_SND_IDLE, zmtp_ret_s->snd_state);
    TEST_ASSERT_EQUAL_INT(ST_RCV_IDLE, zmtp_ret_s->rcv_state);

    free(zmtp_s);
    free(pico_s);

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
   TEST_ASSERT_EQUAL_INT(zmtp_socket_bind(NULL, NULL, &port), PICO_ERR_EFAULT);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_bind(zmtp_s, NULL, &port), PICO_ERR_EFAULT);

   /*----=== Test valid arguments ===----*/
   zmtp_s->sock = pico_s;
   pico_socket_bind_IgnoreAndReturn(0);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_bind(zmtp_s, NULL, &port), 0);
   
   free(zmtp_s);
   free(pico_s);
   
}

void test_zmtp_socket_close(void)
{
   struct zmtp_socket* zmtp_s;
   struct pico_socket* pico_s;
   zmtp_s = calloc(1, sizeof(struct zmtp_socket));
   pico_s = calloc(1, sizeof(struct pico_socket));
   /*----=== Test empty sockets ===----*/
   TEST_ASSERT_EQUAL_INT(zmtp_socket_close(NULL), -1);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_close(zmtp_s),-1);

   zmtp_s->sock = pico_s;
   pico_socket_close_IgnoreAndReturn(-1);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_close(zmtp_s), -1);
   /*----=== Test valid arguments ===----*/
   pico_socket_close_IgnoreAndReturn(0);
   TEST_ASSERT_EQUAL_INT(zmtp_socket_close(zmtp_s), 0);

   free(zmtp_s);
   free(pico_s);
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

