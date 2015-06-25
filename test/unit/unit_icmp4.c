
#include "pico_icmp4.h"
#define NUM_PING 1
int ping_test_var = 0;

void cb_ping(struct pico_icmp4_stats *s)
{
    char host[30];
    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
        if (s->seq == NUM_PING) {
            ping_test_var++;
        }

        fail_if (s->seq > NUM_PING);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
        exit(1);
    }
}

START_TEST (test_icmp4_ping)
{
    struct pico_ip4 local = {
        0
    };
    struct pico_ip4 remote = {
        0
    };
    struct pico_ip4 netmask = {
        0
    };
    struct mock_device *mock = NULL;
    char local_address[] = {
        "192.168.1.102"
    };
    char remote_address[] = {
        "192.168.1.103"
    };
    uint16_t interval = 1000;
    uint16_t timeout  = 5000;
    uint8_t size  = 48;

    int bufferlen = 80;
    uint8_t buffer[bufferlen];
    int len;
    uint8_t temp_buf[4];
    printf("*********************** starting %s * \n", __func__);

    pico_string_to_ipv4(local_address, &(local.addr));
    pico_string_to_ipv4("255.255.255.0", &(netmask.addr));

    pico_string_to_ipv4(remote_address, &(remote.addr));
    pico_string_to_ipv4("255.255.255.0", &(netmask.addr));

    pico_stack_init();

    mock = pico_mock_create(NULL);
    fail_if(mock == NULL, "No device created");

    pico_ipv4_link_add(mock->dev, local, netmask);

    fail_if(pico_icmp4_ping(local_address, NUM_PING, interval, timeout, size, cb_ping) < 0);
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    fail_if(ping_test_var != 1);

    pico_icmp4_ping(remote_address, NUM_PING, interval, timeout, size, cb_ping);
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    /* get the packet from the mock_device */
    memset(buffer, 0, bufferlen);
    len = pico_mock_network_read(mock, buffer, bufferlen);
    fail_if(len < 20);
    /* inspect it */
    fail_unless(mock_ip_protocol(mock, buffer, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer, len) == 8);
    fail_unless(mock_icmp_code(mock, buffer, len) == 0);
    fail_unless(pico_checksum(buffer + 20, len - 20) == 0);

    /* cobble up a reply */
    buffer[20] = 0; /* type 0 : reply */
    memcpy(temp_buf, buffer + 12, 4);
    memcpy(buffer + 12, buffer + 16, 4);
    memcpy(buffer + 16, temp_buf, 4);

    /* using the mock-device because otherwise I have to put everything in a pico_frame correctly myself. */
    pico_mock_network_write(mock, buffer, len);
    /* check if it is received */
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    fail_unless(ping_test_var == 2);

    /* repeat but make it an invalid reply... */

    pico_icmp4_ping(remote_address, NUM_PING, interval, timeout, size, cb_ping);
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    /* get the packet from the mock_device */
    memset(buffer, 0, bufferlen);
    len = pico_mock_network_read(mock, buffer, bufferlen);
    /* inspect it */
    fail_unless(mock_ip_protocol(mock, buffer, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer, len) == 8);
    fail_unless(mock_icmp_code(mock, buffer, len) == 0);
    fail_unless(pico_checksum(buffer + 20, len - 20) == 0);

    /* cobble up a reply */
    buffer[20] = 0; /* type 0 : reply */
    memcpy(temp_buf, buffer + 12, 4);
    memcpy(buffer + 12, buffer + 16, 4);
    memcpy(buffer + 16, temp_buf, 4);
    buffer[26] = ~buffer[26]; /* flip some bits in the sequence number, to see if the packet gets ignored properly */

    /* using the mock-device because otherwise I have to put everything in a pico_frame correctly myself. */
    pico_mock_network_write(mock, buffer, len);
    /* check if it is received */
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    fail_unless(ping_test_var == 2);
}
END_TEST


START_TEST (test_icmp4_incoming_ping)
{
    int bufferlen = 76;
    uint8_t buffer[76] = {
        0x45, 0x00, 0x00, 0x4c,
        0x91, 0xc3, 0x40, 0x00,
        0x40, 0x01, 0x24, 0xd0,
        0xc0, 0xa8, 0x01, 0x66,
        0xc0, 0xa8, 0x01, 0x64,
        0x08, 0x00, 0x66, 0x3c,
        0x91, 0xc2, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    int buffer2len = 76;
    int len;
    int cntr = 0;
    uint8_t buffer2[bufferlen];
    struct pico_ip4 local = {
        .addr = long_be(0xc0a80164)
    };
    struct pico_ip4 netmask = {
        .addr = long_be(0xffffff00)
    };
    struct mock_device*mock;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) buffer;
    printf("*********************** starting %s * \n", __func__);

    pico_stack_init();

    mock = pico_mock_create(NULL);
    fail_if(mock == NULL, "No device created");

    pico_ipv4_link_add(mock->dev, local, netmask);

    hdr->crc = 0;
    hdr->crc = short_be(pico_checksum(hdr, PICO_SIZE_IP4HDR));
    pico_mock_network_write(mock, buffer, bufferlen);
    /* check if it is received */
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();


    len = pico_mock_network_read(mock, buffer2, buffer2len);
    /* inspect it */

    while(cntr < len) {
        printf("0x%02x ", buffer2[cntr]);
        cntr++;
        if(cntr % 4 == 0)
            printf("\n");
    }
    fail_unless(len == buffer2len, "ping reply lenght does not match, expected len: %d, got: %d", buffer2len, len);
    fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer2, len) == 0);
    fail_unless(mock_icmp_code(mock, buffer2, len) == 0);
    fail_unless(pico_checksum(buffer2 + 20, len - 20) == 0);

}
END_TEST

START_TEST (test_icmp4_unreachable_send)
{
    struct pico_ip4 local = {
        .addr = long_be(0x0a280064)
    };
    struct pico_ip4 netmask = {
        .addr = long_be(0xffffff00)
    };
    struct mock_device*mock;
    int len = 0;
    int bufferlen = 80;
    uint8_t buffer2[bufferlen];

    uint8_t buffer[32] = {
        0x45, 0x00, 0x00, 0x20,  0x91, 0xc0, 0x40, 0x00,
        0x40, 0x11, 0x94, 0xb4,  0x0a, 0x28, 0x00, 0x05,
        0x0a, 0x28, 0x00, 0x04,  0x15, 0xb3, 0x15, 0xb3,
        0x00, 0x0c, 0x00, 0x00,  'e', 'l', 'l', 'o'
    };

    /* fake packet with bad upper-layer-protocol */
    uint8_t buffer3[20] = {
        0x45, 0x00, 0x00, 0x14,  0x91, 0xc0, 0x40, 0x00,
        0x40, 0xff, 0x94, 0xb4,  0x0a, 0x28, 0x00, 0x05,
        0x0a, 0x28, 0x00, 0x04
    };

    struct pico_frame*f = PICO_ZALLOC(sizeof(struct pico_frame));
    uint8_t nullbuf[8] = {};
    printf("*********************** starting %s * \n", __func__);

    f->net_hdr = buffer;
    f->buffer = buffer;

    pico_stack_init();

    mock = pico_mock_create(NULL);
    fail_if(mock == NULL, "No device created");

    pico_ipv4_link_add(mock->dev, local, netmask);


    fail_if(pico_icmp4_dest_unreachable(f));
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    len = pico_mock_network_read(mock, buffer2, bufferlen);

    fail_unless(len == 56, "len is indeed %d\n", len);
    fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer2, len) == 3); /* destination unreachable */
    fail_unless(mock_icmp_code(mock, buffer2, len) == 1); /* host unreachable */
    fail_unless(pico_checksum(buffer2 + 20, len - 20) == 0);


    fail_if(pico_icmp4_port_unreachable(f));
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    len = pico_mock_network_read(mock, buffer2, bufferlen);

    fail_unless(len == 56);
    fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer2, len) == 3); /* destination unreachable */
    fail_unless(mock_icmp_code(mock, buffer2, len) == 3); /* port unreachable */
    fail_unless(pico_checksum(buffer2 + 20, len - 20) == 0);


    fail_if(pico_icmp4_proto_unreachable(f));
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    len = pico_mock_network_read(mock, buffer2, bufferlen);

    fail_unless(len == 56);
    fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer2, len) == 3); /* destination unreachable */
    fail_unless(mock_icmp_code(mock, buffer2, len) == 2); /* proto unreachable */
    fail_unless(pico_checksum(buffer2 + 20, len - 20) == 0);


    fail_if(pico_icmp4_ttl_expired(f));
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    len = pico_mock_network_read(mock, buffer2, bufferlen);

    fail_unless(len == 56);
    fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer2, len) == 11); /* ttl expired */
    fail_unless(mock_icmp_code(mock, buffer2, len) == 0);
    fail_unless(pico_checksum(buffer2 + 20, len - 20) == 0);

    f->net_hdr = buffer3;
    f->buffer = buffer3;

    fail_if(pico_icmp4_proto_unreachable(f));
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    len = pico_mock_network_read(mock, buffer2, bufferlen);

    fail_unless(len == 48); /* Buffer 3 is shorter, reply is shorter too... */
    fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer2, len) == 3); /* destination unreachable */
    fail_unless(mock_icmp_code(mock, buffer2, len) == 2); /* proto unreachable */
    fail_unless(pico_checksum(buffer2 + 20, len - 20) == 0);

#ifdef NOPE
    /* I don't know what was the intention, but the buffer is shorter than 48 bytes... */
    fail_if(memcmp(buffer + 48, nullbuf, 8) == 0); /* there was no data */
#endif
}
END_TEST

int icmp4_socket_unreach_status = 0;
void icmp4_unreach_socket_cb(uint16_t ev, struct pico_socket *s)
{
    IGNORE_PARAMETER(s);

    if (ev == PICO_SOCK_EV_ERR) {
        icmp4_socket_unreach_status = 1;
    }
}

START_TEST (test_icmp4_unreachable_recv)
{
    struct pico_ip4 local = {
        .addr = long_be(0x0a280064)
    };
    struct pico_ip4 remote = {
        .addr = long_be(0x0a280065)
    };
    struct pico_ip4 netmask = {
        .addr = long_be(0xffffff00)
    };
    struct mock_device*mock;
    struct pico_socket*sock;
    uint16_t port = short_be(7777);

    /* put a host unreachable in the queue, run a few stack ticks */
    uint8_t buffer[] = {
        0x45, 0x00, 0x00, 0x20,
        0x91, 0xc0, 0x40, 0x00,
        0x40, 0x01, 0x94, 0xb4,
        0x0a, 0x28, 0x00, 0x65,
        0x0a, 0x28, 0x00, 0x64,
        0x03, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) buffer;

    printf("*********************** starting %s * \n", __func__);
    pico_stack_init();

    mock = pico_mock_create(NULL);
    fail_if(mock == NULL, "No device created");

    pico_ipv4_link_add(mock->dev, local, netmask);

    /* open a socket */
    sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &icmp4_unreach_socket_cb);
    fail_if(sock == NULL);
    fail_if(pico_socket_bind(sock, &local, &port));
    pico_socket_connect(sock, &remote, port);
    pico_socket_write(sock, "fooo", 4);
    /* see if my callback was called with the proper code */

    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    /* filling in the IP header and first 8 bytes */
    hdr->crc = 0;
    hdr->crc = short_be(pico_checksum(hdr, PICO_SIZE_IP4HDR));
    printf("read %d bytes\n", pico_mock_network_read(mock, buffer + 28, 28));

    printf("wrote %d bytes\n", pico_mock_network_write(mock, buffer, 56));
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    fail_unless(icmp4_socket_unreach_status == 1);
}
END_TEST
