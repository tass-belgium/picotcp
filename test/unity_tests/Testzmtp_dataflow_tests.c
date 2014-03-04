#include "unity.h"
#include "Mockpico_mm.h"
#include "pico_vector.h"
#include "pico_zmtp.c"
#include "Mockpico_socket.h"
#include <stdint.h>
#include "Mockpico_tree.h"


volatile pico_err_t pico_err;
#define BLACK 1
struct pico_tree_node LEAF = {
        NULL, /* key */
            &LEAF, &LEAF, &LEAF, /* parent, left,right */
                BLACK, /* color */
};

void* staticWriteBuff = NULL;
size_t staticWrittenLength = 0;
size_t eBytestreamLen = 1000;

void setUp(void)
{
    staticWriteBuff = calloc(1, eBytestreamLen);
}

void tearDown(void)
{
    free(staticWriteBuff);
}

void* pico_mem_zalloc_cb(size_t len, int numCalls)
{
    IGNORE_PARAMETER(numCalls);
    return calloc(1, len);
}

void pico_mem_free_cb(void *ptr, int numCalls)
{
    IGNORE_PARAMETER(numCalls);
    free(ptr);
}

int pico_socket_write_cb(struct pico_socket* s, const void* msgBuffer, int length, int numCalls)
{
    IGNORE_PARAMETER(s);
    IGNORE_PARAMETER(numCalls);
    staticWrittenLength = (size_t)length;
    memcpy(staticWriteBuff, msgBuffer, (size_t)length);
    return length;
}

void test_zmtp_socket_send_1msg_0char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;

    uint8_t expectedBuff[2];
    uint8_t msg[0];
    size_t msgLength = 0;
    size_t byteStreamLength = msgLength + 2;

    expectedBuff[0] = 0;
    expectedBuff[1] = 0;

    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame.buf = &msg;
    frame.len = msgLength;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(staticWriteBuff, expectedBuff, byteStreamLength);

}

void test_zmtp_socket_send_1msg_1char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msgLength = 1;
    size_t byteStreamLength = msgLength + 2;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg[msgLength];
    expectedBuff[0] = 0;
    expectedBuff[1] = 1;

    //data:
    expectedBuff[2] = 0xff;
    msg[0] = 0xff;

    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame.buf = &msg;
    frame.len = msgLength;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}

void test_zmtp_socket_send_1msg_255char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msgLength = 255;
    size_t byteStreamLength = msgLength + 2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg[msgLength];
    expectedBuff[0] = 0x00;
    expectedBuff[1] = (uint8_t)msgLength;

    //data:
    for(i=0; i<(int)msgLength; i++)
    {
        msg[i] = (uint8_t) i;
        expectedBuff[2+i] = (uint8_t) i;
    }

    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame.buf = &msg;
    frame.len = msgLength;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}

void test_zmtp_socket_send_1msg_256char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msgLength = 256;
    size_t byteStreamLength = msgLength + 9;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg[msgLength];
    expectedBuff[0] = 0x02;
    expectedBuff[1] = 0;
    expectedBuff[2] = 0;
    expectedBuff[3] = 0;
    expectedBuff[4] = 0;
    expectedBuff[5] = 0;
    expectedBuff[6] = 0;
    expectedBuff[7] = 0x01;
    expectedBuff[8] = 0;

    //data:
    for(i=0; i<(int)msgLength; i++)
    {
        msg[i] = (uint8_t) i;
        expectedBuff[9+i] = (uint8_t) i;
    }

    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame.buf = &msg;
    frame.len = msgLength;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}


void test_zmtp_socket_send_1msg_600char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msgLength = 600;
    size_t byteStreamLength = msgLength + 9;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg[msgLength];
    expectedBuff[0] = 0x02;
    expectedBuff[1] = 0;
    expectedBuff[2] = 0;
    expectedBuff[3] = 0;
    expectedBuff[4] = 0;
    expectedBuff[5] = 0;
    expectedBuff[6] = 0;
    expectedBuff[7] = (msgLength>>8) & 0xff;
    expectedBuff[8] = msgLength & 0xff;

    //data:
    for(i=0; i<(int)msgLength; i++)
    {
        msg[i] = (uint8_t) i;
        expectedBuff[9+i] = (uint8_t) i;
    }

    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame.buf = &msg;
    frame.len = msgLength;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}

void test_zmtp_socket_send_2msg_0char_0char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame1, frame2;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msg1Length = 0;
    size_t msg2Length = 0;
    size_t byteStreamLength = msg1Length + 2 + msg2Length + 2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg1[msg1Length];
    uint8_t msg2[msg2Length];
    expectedBuff[0] = 0x01;
    expectedBuff[1] = 0;
    expectedBuff[2] = 0x00;
    expectedBuff[3] = 0;
    expectedBuff[4] = 0;

    //data:
    for(i=0; i<(int)msg1Length; i++)
    {
        msg1[i] = (uint8_t) i;
        expectedBuff[2+i] = (uint8_t) i;
    }
    for(i=0; i<(int)msg2Length; i++)
    {
        msg2[i] = (uint8_t) i;
        expectedBuff[2+(int)msg1Length+2+i] = (uint8_t) i;
    }


    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame1.buf = &msg1;
    frame2.buf = &msg2;
    frame1.len = msg1Length;
    frame2.len = msg2Length;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame1);
    pico_vector_push_back(&vec, &frame2);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}



void test_zmtp_socket_send_2msg_0char_1char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame1, frame2;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msg1Length = 0;
    size_t msg2Length = 1;
    size_t byteStreamLength = msg1Length + 2 + msg2Length + 2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg1[msg1Length];
    uint8_t msg2[msg2Length];
    expectedBuff[0] = 0x01; //more short
    expectedBuff[1] = 0; //length msg1
    expectedBuff[2] = 0x00; // final short
    expectedBuff[3] = 0x01; //length msg2

    //data:
    for(i=0; i<(int)msg1Length; i++)
    {
        msg1[i] = (uint8_t) i;
        expectedBuff[2+i] = (uint8_t) i;
    }
    for(i=0; i<(int)msg2Length; i++)
    {
        msg2[i] = (uint8_t) i;
        expectedBuff[2+(int)msg1Length+2+i] = (uint8_t) i;
    }


    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame1.buf = &msg1;
    frame2.buf = &msg2;
    frame1.len = msg1Length;
    frame2.len = msg2Length;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame1);
    pico_vector_push_back(&vec, &frame2);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}


void test_zmtp_socket_send_2msg_1char_0char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame1, frame2;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msg1Length = 1;
    size_t msg2Length = 0;
    size_t byteStreamLength = msg1Length + 2 + msg2Length + 2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg1[msg1Length];
    uint8_t msg2[msg2Length];
    expectedBuff[0] = 0x01; //more short
    expectedBuff[1] = 0x01; //length msg1
    expectedBuff[2] = 0x00; // final short
    expectedBuff[3] = 0x00; //length msg2

    //data:
    for(i=0; i<(int)msg1Length; i++)
    {
        msg1[i] = (uint8_t) i;
        expectedBuff[2+i] = (uint8_t) i;
    }
    for(i=0; i<(int)msg2Length; i++)
    {
        msg2[i] = (uint8_t) i;
        expectedBuff[2+(int)msg1Length+2+i] = (uint8_t) i;
    }


    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame1.buf = &msg1;
    frame2.buf = &msg2;
    frame1.len = msg1Length;
    frame2.len = msg2Length;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame1);
    pico_vector_push_back(&vec, &frame2);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}




void test_zmtp_socket_send_2msg_255char_255char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame1, frame2;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msg1Length = 255;
    size_t msg2Length = 255;
    size_t byteStreamLength = msg1Length + 2 + msg2Length + 2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg1[msg1Length];
    uint8_t msg2[msg2Length];
    expectedBuff[0] = 0x01; //more short
    expectedBuff[1] = 0xff; //length msg1
    expectedBuff[(int)msg1Length +2 +0] = 0x00; // final short
    expectedBuff[(int)msg1Length +2 +1] = 0xff; //length msg2

    //data:
    for(i=0; i<(int)msg1Length; i++)
    {
        msg1[i] = (uint8_t) i;
        expectedBuff[2+i] = (uint8_t) i;
    }
    for(i=0; i<(int)msg2Length; i++)
    {
        msg2[i] = (uint8_t) i;
        expectedBuff[2+(int)msg1Length+2+i] = (uint8_t) i;
    }


    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame1.buf = &msg1;
    frame2.buf = &msg2;
    frame1.len = msg1Length;
    frame2.len = msg2Length;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame1);
    pico_vector_push_back(&vec, &frame2);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}

void test_zmtp_socket_send_2msg_256char_255char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame1, frame2;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msg1Length = 256;
    size_t msg2Length = 255;
    size_t headerLen1 = 9;
    size_t headerLen2 = 2;
    size_t byteStreamLength = msg1Length + headerLen1 + msg2Length + headerLen2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg1[msg1Length];
    uint8_t msg2[msg2Length];
    for(i=0; i<(int)headerLen1; i++)
    {
        expectedBuff[i] = 0x00;
    }
    for(i=0; i<(int)headerLen2; i++)
    {
        expectedBuff[(int)(msg1Length + headerLen1) + i] = 0x00;
    }
    expectedBuff[0] = 0x03; //more long
    expectedBuff[7] = 0x01; //length msg1
    expectedBuff[8] = 0x00; //length msg1
    expectedBuff[(int)(msg1Length + headerLen1) +0] = 0x00; // final short
    expectedBuff[(int)(msg1Length + headerLen1) +1] = 0xff; //length msg2

    //data:
    for(i=0; i<(int)msg1Length; i++)
    {
        msg1[i] = (uint8_t) i;
        expectedBuff[(int)headerLen1+i] = (uint8_t) i;
    }
    for(i=0; i<(int)msg2Length; i++)
    {
        msg2[i] = (uint8_t) i;
        expectedBuff[(int)(msg1Length + headerLen1 + headerLen2) + i] = (uint8_t) i;
    }


    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame1.buf = &msg1;
    frame2.buf = &msg2;
    frame1.len = msg1Length;
    frame2.len = msg2Length;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame1);
    pico_vector_push_back(&vec, &frame2);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}


void test_zmtp_socket_send_2msg_600char_255char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame1, frame2;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msg1Length = 600;
    size_t msg2Length = 255;
    size_t headerLen1 = 9;
    size_t headerLen2 = 2;
    size_t byteStreamLength = msg1Length + headerLen1 + msg2Length + headerLen2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg1[msg1Length];
    uint8_t msg2[msg2Length];
    for(i=0; i<(int)headerLen1; i++)
    {
        expectedBuff[i] = 0x00;
    }
    for(i=0; i<(int)headerLen2; i++)
    {
        expectedBuff[(int)(msg1Length + headerLen1) + i] = 0x00;
    }
    expectedBuff[0] = 0x03; //more long
    expectedBuff[7] = 0x02; //length msg1
    expectedBuff[8] = 0x58; //length msg1
    expectedBuff[(int)(msg1Length + headerLen1 +0)] = 0x00; // final short
    expectedBuff[(int)(msg1Length + headerLen1 +1)] = 0xff; //length msg2

    //data:
    for(i=0; i<(int)msg1Length; i++)
    {
        msg1[i] = (uint8_t) i;
        expectedBuff[(int)headerLen1+i] = (uint8_t) i;
    }
    for(i=0; i<(int)msg2Length; i++)
    {
        msg2[i] = (uint8_t) i;
        expectedBuff[(int)(msg1Length + headerLen1 + headerLen2) + i] = (uint8_t) i;
    }


    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame1.buf = &msg1;
    frame2.buf = &msg2;
    frame1.len = msg1Length;
    frame2.len = msg2Length;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame1);
    pico_vector_push_back(&vec, &frame2);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}


void test_zmtp_socket_send_2msg_600char_256char(void)
{
    struct pico_vector vec;
    struct zmtp_frame_t frame1, frame2;
    struct zmtp_socket z_sock;
    struct pico_socket p_sock;
    struct pico_vector sock_buf;
    size_t msg1Length = 600;
    size_t msg2Length = 256;
    size_t headerLen1 = 9;
    size_t headerLen2 = 9;
    size_t byteStreamLength = msg1Length + headerLen1 + msg2Length + headerLen2;
    int i;

    uint8_t expectedBuff[byteStreamLength];
    uint8_t msg1[msg1Length];
    uint8_t msg2[msg2Length];
    for(i=0; i<(int)headerLen1; i++)
    {
        expectedBuff[i] = 0x00;
    }
    for(i=0; i<(int)headerLen2; i++)
    {
        expectedBuff[(int)(msg1Length + headerLen1) + i] = 0x00;
    }
    expectedBuff[0] = 0x03; //more long
    expectedBuff[7] = 0x02; //length msg1
    expectedBuff[8] = 0x58; //length msg1
    expectedBuff[(int)(msg1Length + headerLen1) +0] = 0x02; //final long
    expectedBuff[(int)(msg1Length + headerLen1) +7] = 0x01; //length msg2
    expectedBuff[(int)(msg1Length + headerLen1) +8] = 0x00; //length msg2

    //data:
    for(i=0; i<(int)msg1Length; i++)
    {
        msg1[i] = (uint8_t) i;
        expectedBuff[(int)headerLen1+i] = (uint8_t) i;
    }
    for(i=0; i<(int)msg2Length; i++)
    {
        msg2[i] = (uint8_t) i;
        expectedBuff[(int)(msg1Length + headerLen1 + headerLen2) + i] = (uint8_t) i;
    }


    pico_mem_zalloc_StubWithCallback(&pico_mem_zalloc_cb);
    pico_mem_free_StubWithCallback(&pico_mem_free_cb);
    pico_socket_write_StubWithCallback(&pico_socket_write_cb);

    frame1.buf = &msg1;
    frame2.buf = &msg2;
    frame1.len = msg1Length;
    frame2.len = msg2Length;
    pico_vector_init(&vec, 5, sizeof(struct zmtp_frame_t));

    pico_vector_push_back(&vec, &frame1);
    pico_vector_push_back(&vec, &frame2);

    z_sock.sock = &p_sock;
    z_sock.out_buff = &sock_buf;
    z_sock.state = ZMTP_ST_RDY;
    
    zmtp_socket_send(&z_sock, &vec);
    TEST_ASSERT_EQUAL_INT(byteStreamLength, staticWrittenLength);
    TEST_ASSERT_EQUAL_MEMORY(expectedBuff, staticWriteBuff, byteStreamLength);

}

