#include "unity.h"
#include "zmtp_tests.h"
#include "pico_zmtp.h"
#include "Mockpico_socket.h"

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
