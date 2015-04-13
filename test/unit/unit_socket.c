
int pico_aodv_init(void)
{
    return 0;
}
START_TEST (test_socket)
{
    int ret = 0;
    uint16_t port_be = 0, porta, proto, port_got;
    char buf[] = "test";
    struct pico_socket *sk_tcp, *sk_udp, *s, *sl, *sa;
    struct pico_device *dev;
    struct pico_ip4 inaddr_dst, inaddr_link, inaddr_incorrect, inaddr_uni, inaddr_null, netmask, orig, inaddr_got;

    int getnodelay = -1;
    int nodelay = -1;
    int count = 0;

    uint32_t getsocket_buffer = 0;
    uint32_t socket_buffer = 0;

    pico_stack_init();

    printf("START SOCKET TEST\n");

    pico_string_to_ipv4("224.7.7.7", &inaddr_dst.addr);
    pico_string_to_ipv4("10.40.0.2", &inaddr_link.addr);
    pico_string_to_ipv4("224.8.8.8", &inaddr_incorrect.addr);
    pico_string_to_ipv4("0.0.0.0", &inaddr_null.addr);
    pico_string_to_ipv4("10.40.0.3", &inaddr_uni.addr);

    dev = pico_null_create("dummy");
    netmask.addr = long_be(0xFFFF0000);
    ret = pico_ipv4_link_add(dev, inaddr_link, netmask);
    fail_if(ret < 0, "socket> error adding link");


    /* socket_open passing wrong parameters */
    s = pico_socket_open(PICO_PROTO_IPV4, 99, NULL);
    fail_if(s != NULL, "Error got socket wrong parameters");

    s = pico_socket_open(PICO_PROTO_IPV4, -109, NULL);
    fail_if(s != NULL, "Error got socket");

    s = pico_socket_open(99, PICO_PROTO_UDP, NULL);
    fail_if(s != NULL, "Error got socket");

    s = pico_socket_open(-99, PICO_PROTO_UDP, NULL);
    fail_if(s != NULL, "Error got socket");


    sk_tcp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, NULL);
    fail_if(sk_tcp == NULL, "socket> tcp socket open failed");


    port_be = short_be(5555);
    /* socket_bind passing wrong parameters */
    ret = pico_socket_bind(NULL, &inaddr_link, &port_be);
    fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
    ret = pico_socket_bind(sk_tcp, NULL, &port_be);
    fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
    ret = pico_socket_bind(sk_tcp, &inaddr_link, NULL);
    fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
    /* socket_getname passing wrong parameters */
    ret = pico_socket_getname(NULL, &inaddr_link, &port_be, &proto);
    fail_if(ret == 0, "socket> tcp socket getname with wrong parameter");
    ret = pico_socket_getname(sk_tcp, NULL, &port_be, &proto);
    fail_if(ret == 0, "socket> tcp socket getname with wrong parameter");
    ret = pico_socket_getname(sk_tcp, &inaddr_link, NULL, &proto);
    fail_if(ret == 0, "socket> tcp socket getname with wrong parameter");
    ret = pico_socket_getname(sk_tcp, &inaddr_link, &port_be, NULL);
    fail_if(ret == 0, "socket> tcp socket getname with wrong parameter");
    /* socket_bind passing correct parameters */
    ret = pico_socket_bind(sk_tcp, &inaddr_link, &port_be);
    fail_if(ret < 0, "socket> tcp socket bind failed");
    count = pico_count_sockets(PICO_PROTO_TCP);
    printf("Count: %d\n", count);
    fail_unless(count == 1);
    count = pico_count_sockets(0);
    printf("Count: %d\n", count);
    fail_unless(count == 1);

    sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
    fail_if(sk_udp == NULL, "socket> udp socket open failed");

    port_be = short_be(5555);
    ret = pico_socket_bind(sk_udp, &inaddr_link, &port_be);
    fail_if(ret < 0, "socket> udp socket bind failed");

    fail_if (pico_count_sockets(PICO_PROTO_UDP) != 1);
    fail_if (pico_count_sockets(0) != 2);


    ret = pico_socket_getname(sk_udp, &inaddr_got, &port_got, &proto);
    fail_if(ret < 0, "socket> udp socket getname failed");
    fail_if(inaddr_got.addr != inaddr_link.addr, "Getname: Address is different");
    fail_if(port_be != port_got, "Getname: Port is different");
    fail_if(proto != PICO_PROTO_IPV4, "Getname: proto is wrong");

    /* socket_close passing wrong parameter */
    ret = pico_socket_close(NULL);
    fail_if(ret == 0, "Error socket close with wrong parameters");


    /* socket_connect passing wrong parameters */
    ret = pico_socket_connect(sk_udp, NULL, port_be);
    fail_if(ret == 0, "Error socket connect with wrong parameters");
    ret = pico_socket_connect(NULL, &inaddr_dst, port_be);
    fail_if(ret == 0, "Error socket connect with wrong parameters");

    /* socket_connect passing correct parameters */
    ret = pico_socket_connect(sk_udp, &inaddr_dst, port_be);
    fail_if(ret < 0, "Error socket connect");
    ret = pico_socket_connect(sk_tcp, &inaddr_dst, port_be);
    fail_if(ret < 0, "Error socket connect");


    /* testing listening socket */
    sl = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, NULL);
    fail_if(sl == NULL, "socket> tcp socket open failed");
    port_be = short_be(6666);
    ret = pico_socket_bind(sl, &inaddr_link, &port_be);
    fail_if(ret < 0, "socket> tcp socket bind failed");
    /* socket_listen passing wrong parameters */
    ret = pico_socket_listen(sl, 0);
    fail_if(ret == 0, "Error socket tcp socket listen done, wrong parameter");
    ret = pico_socket_listen(NULL, 10);
    fail_if(ret == 0, "Error socket tcp socket listen done, wrong parameter");
    /* socket_listen passing correct parameters */
    ret = pico_socket_listen(sl, 10);
    fail_if(ret < 0, "socket> tcp socket listen failed: %s", strerror(pico_err));

    /* socket_accept passing wrong parameters */
    sa = pico_socket_accept(sl, &orig, NULL);
    fail_if(sa != NULL, "Error socket tcp socket accept wrong argument");
    sa = pico_socket_accept(sl, NULL, &porta);
    fail_if(sa != NULL, "Error socket tcp socket accept wrong argument");
    /* socket_accept passing correct parameters */
    sa = pico_socket_accept(sl, &orig, &porta);
    fail_if(sa == NULL && pico_err != PICO_ERR_EAGAIN, "socket> tcp socket accept failed: %s", strerror(pico_err));

    ret = pico_socket_close(sl);
    fail_if(ret < 0, "socket> tcp socket close failed: %s\n", strerror(pico_err));


    /* testing socket read/write */
    /* socket_write passing wrong parameters */
    ret = pico_socket_write(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
    ret = pico_socket_write(sk_tcp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
    ret = pico_socket_write(sk_tcp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket write succeeded, wrong argument\n");
    /* socket_write passing correct parameters */
    ret = pico_socket_write(sk_tcp, (void *)buf, sizeof(buf));
    fail_if(ret < 0, "socket> tcp socket write failed: %s\n", strerror(pico_err));
    /* socket_read passing wrong parameters */
    ret = pico_socket_read(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
    ret = pico_socket_read(sk_tcp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
    ret = pico_socket_read(sk_tcp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket read succeeded, wrong argument\n");
    /* socket_read passing correct parameters */
    ret = pico_socket_read(sk_tcp, (void *)buf, sizeof(buf));
    fail_if(ret < 0, "socket> tcp socket read failed, ret = %d: %s\n", ret, strerror(pico_err)); /* tcp_recv returns 0 when no frame !? */


    /* send/recv */
    /* socket_send passing wrong parameters */
    ret = pico_socket_send(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
    ret = pico_socket_send(sk_tcp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
    ret = pico_socket_send(sk_tcp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket send succeeded, wrong argument\n");
    /* socket_write passing correct parameters */
    ret = pico_socket_send(sk_tcp, (void *)buf, sizeof(buf));
    fail_if(ret <= 0, "socket> tcp socket send failed: %s\n", strerror(pico_err));
    /* socket_recv passing wrong parameters */
    ret = pico_socket_recv(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
    ret = pico_socket_recv(sk_tcp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
    ret = pico_socket_recv(sk_tcp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket recv succeeded, wrong argument\n");
    /* socket_recv passing correct parameters */
    ret = pico_socket_recv(sk_tcp, (void *)buf, sizeof(buf));
    fail_if(ret < 0, "socket> tcp socket recv failed, ret = %d: %s\n", ret, strerror(pico_err)); /* tcp_recv returns 0 when no frame !? */


    /* sendto/recvfrom */
    /* socket_sendto passing wrong parameters */
    ret = pico_socket_sendto(NULL, (void *)buf, sizeof(buf), &inaddr_dst, port_be);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_tcp, NULL, sizeof(buf), &inaddr_dst, port_be);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_tcp, (void *)buf, 0, &inaddr_dst, port_be);
    fail_if(ret > 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_tcp, (void *)buf, sizeof(buf), NULL, port_be);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_tcp, (void *)buf, sizeof(buf), &inaddr_dst, -120);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    /* socket_write passing correct parameters */
    ret = pico_socket_sendto(sk_tcp, (void *)buf, sizeof(buf), &inaddr_dst, short_be(5555));
    fail_if(ret <= 0, "socket> udp socket sendto failed, ret = %d: %s\n", ret, strerror(pico_err));
    /* socket_recvfrom passing wrong parameters */
    ret = pico_socket_recvfrom(NULL, (void *)buf, sizeof(buf), &orig, &porta);
    fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
    ret = pico_socket_recvfrom(sk_tcp, NULL, sizeof(buf), &orig, &porta);
    fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
    ret = pico_socket_recvfrom(sk_tcp, (void *)buf, 0, &orig, &porta);
    fail_if(ret > 0, "Error socket recvfrom succeeded, wrong argument\n");
    ret = pico_socket_recvfrom(sk_tcp, (void *)buf, sizeof(buf), NULL, &porta);
    fail_if(ret > 0, "Error socket recvfrom succeeded, wrong argument\n");
    ret = pico_socket_recvfrom(sk_tcp, (void *)buf, sizeof(buf), &orig, NULL);
    fail_if(ret > 0, "Error socket recvfrom succeeded, wrong argument\n");
    /* socket_recvfrom passing correct parameters */
    ret = pico_socket_recvfrom(sk_tcp, (void *)buf, sizeof(buf), &orig, &porta);
    fail_if(ret != 0, "socket> tcp socket recvfrom failed, ret = %d: %s\n", ret, strerror(pico_err)); /* tcp_recv returns -1 when no frame !? */


    /* testing socket read/write */
    /* socket_write passing wrong parameters */
    ret = pico_socket_write(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
    ret = pico_socket_write(sk_udp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
    ret = pico_socket_write(sk_udp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket write succeeded, wrong argument\n");
    /* socket_write passing correct parameters */
    ret = pico_socket_write(sk_udp, (void *)buf, sizeof(buf));
    fail_if(ret < 0, "socket> tcp socket write failed: %s\n", strerror(pico_err));
    /* socket_read passing wrong parameters */
    ret = pico_socket_read(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
    ret = pico_socket_read(sk_udp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
    ret = pico_socket_read(sk_udp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket read succeeded, wrong argument\n");
    ret = pico_socket_read(sk_udp, (void *)buf, 0xFFFF + 1);
    fail_if(ret >= 0, "Error socket read succeeded while len was > 0xFFFF");
    /* socket_read passing correct parameters */
    ret = pico_socket_read(sk_udp, (void *)buf, sizeof(buf));
    fail_if(ret != 0, "socket> udp socket read failed, ret = %d: %s\n", ret, strerror(pico_err));


    /* send/recv */
    /* socket_send passing wrong parameters */
    ret = pico_socket_send(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
    ret = pico_socket_send(sk_udp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
    ret = pico_socket_send(sk_udp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket send succeeded, wrong argument\n");
    /* socket_write passing correct parameters */
    ret = pico_socket_send(sk_udp, (void *)buf, sizeof(buf));
    fail_if(ret <= 0, "socket> tcp socket send failed: %s\n", strerror(pico_err));
    /* socket_recv passing wrong parameters */
    ret = pico_socket_recv(NULL, (void *)buf, sizeof(buf));
    fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
    ret = pico_socket_recv(sk_udp, NULL, sizeof(buf));
    fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
    ret = pico_socket_recv(sk_udp, (void *)buf, 0);
    fail_if(ret > 0, "Error socket recv succeeded, wrong argument\n");
    ret = pico_socket_recv(sk_udp, (void *)buf, 0xFFFF + 1);
    fail_if(ret >= 0, "Error socket recv succeeded while len was > 0xFFFF");
    /* socket_recv passing correct parameters */
    ret = pico_socket_recv(sk_udp, (void *)buf, sizeof(buf));
    fail_if(ret != 0, "socket> udp socket recv failed, ret = %d: %s\n", ret, strerror(pico_err));


    /* sendto/recvfrom */
    /* socket_sendto passing wrong parameters */
    ret = pico_socket_sendto(NULL, (void *)buf, sizeof(buf), &inaddr_dst, port_be);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_udp, NULL, sizeof(buf), &inaddr_dst, port_be);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_udp, (void *)buf, 0, &inaddr_dst, port_be);
    fail_if(ret > 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_udp, (void *)buf, sizeof(buf), NULL, port_be);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    ret = pico_socket_sendto(sk_udp, (void *)buf, sizeof(buf), &inaddr_dst, -120);
    fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
    /* socket_write passing correct parameters */
    ret = pico_socket_sendto(sk_udp, (void *)buf, sizeof(buf), &inaddr_dst, short_be(5555));
    fail_if(ret <= 0, "socket> udp socket sendto failed, ret = %d: %s\n", ret, strerror(pico_err));
    /* socket_recvfrom passing wrong parameters */
    ret = pico_socket_recvfrom(NULL, (void *)buf, sizeof(buf), &orig, &porta);
    fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
    ret = pico_socket_recvfrom(sk_udp, NULL, sizeof(buf), &orig, &porta);
    fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
    ret = pico_socket_recvfrom(sk_udp, (void *)buf, 0xFFFF + 1, &orig, &porta);
    fail_if(ret >= 0, "Error socket recvfrom succeeded while len was > 0xFFFF");
    /* socket_recvfrom passing correct parameters */
    ret = pico_socket_recvfrom(sk_udp, (void *)buf, 0, &orig, &porta);
    fail_if(ret != 0, "socket> udp socket recvfrom failed, ret = %d: %s\n", ret, strerror(pico_err));
    ret = pico_socket_recvfrom(sk_udp, (void *)buf, sizeof(buf), &orig, &porta);
    fail_if(ret != 0, "socket> udp socket recvfrom failed, ret = %d: %s\n", ret, strerror(pico_err));

    /* temporary fix, until Nagle problems are analyzed and fixed */
    {
        nodelay = 0;
        ret = pico_socket_setoption(sk_tcp, PICO_TCP_NODELAY, &nodelay);
    }

    /* setoption/getoption */
    ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed (err = %s)\n", strerror(pico_err));
    fail_if(getnodelay != 0, "socket> socket_setoption: default PICO_TCP_NODELAY != 0 (nagle disabled by default)\n");

    nodelay = 1;
    ret = pico_socket_setoption(sk_tcp, PICO_TCP_NODELAY, &nodelay);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_TCP_NODELAY failed\n");
    ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed\n");
    fail_if(getnodelay == 0, "socket> socket_setoption: PICO_TCP_NODELAY is off (expected: on!)\n");

    nodelay = 0;
    ret = pico_socket_setoption(sk_tcp, PICO_TCP_NODELAY, &nodelay);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_TCP_NODELAY failed\n");
    ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed\n");
    fail_if(getnodelay != 0, "socket> socket_setoption: PICO_TCP_NODELAY is on (expected: off!)\n");


    /* Set/get recv buffer (TCP) */
    ret = pico_socket_getoption(sk_tcp, PICO_SOCKET_OPT_RCVBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    fail_if(getsocket_buffer != PICO_DEFAULT_SOCKETQ,
            "socket> socket_setoption: default PICO_SOCKET_OPT_SNDBUF != DEFAULT\n");

    socket_buffer = PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_tcp, PICO_SOCKET_OPT_RCVBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    ret = pico_socket_getoption(sk_tcp, PICO_SOCKET_OPT_RCVBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_RCVBUF is != than expected\n");

    socket_buffer = 2 * PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_tcp, PICO_SOCKET_OPT_RCVBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    ret = pico_socket_getoption(sk_tcp, PICO_SOCKET_OPT_RCVBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_RCVBUF is != than expected\n");

    /* Set/get send buffer (TCP) */
    ret = pico_socket_getoption(sk_tcp, PICO_SOCKET_OPT_SNDBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    fail_if(getsocket_buffer != PICO_DEFAULT_SOCKETQ,
            "socket> socket_setoption: default PICO_SOCKET_OPT_SNDBUF != DEFAULT got: %d exp: %d\n", getsocket_buffer, PICO_DEFAULT_SOCKETQ);

    socket_buffer = PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_tcp, PICO_SOCKET_OPT_SNDBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    ret = pico_socket_getoption(sk_tcp, PICO_SOCKET_OPT_SNDBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_SNDBUF is != than expected\n");

    socket_buffer = 2 * PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_tcp, PICO_SOCKET_OPT_SNDBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    ret = pico_socket_getoption(sk_tcp, PICO_SOCKET_OPT_SNDBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_SNDBUF is != than expected\n");

    /* Set/get recv buffer (UDP) */
    ret = pico_socket_getoption(sk_udp, PICO_SOCKET_OPT_RCVBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    fail_if(getsocket_buffer != PICO_DEFAULT_SOCKETQ,
            "socket> socket_setoption: default PICO_SOCKET_OPT_SNDBUF != DEFAULT\n");

    socket_buffer = PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_udp, PICO_SOCKET_OPT_RCVBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    ret = pico_socket_getoption(sk_udp, PICO_SOCKET_OPT_RCVBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_RCVBUF is != than expected\n");

    socket_buffer = 2 * PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_udp, PICO_SOCKET_OPT_RCVBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    ret = pico_socket_getoption(sk_udp, PICO_SOCKET_OPT_RCVBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_RCVBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_RCVBUF is != than expected\n");

    /* Set/get send buffer (UDP) */
    ret = pico_socket_getoption(sk_udp, PICO_SOCKET_OPT_SNDBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    fail_if(getsocket_buffer != PICO_DEFAULT_SOCKETQ,
            "socket> socket_setoption: default PICO_SOCKET_OPT_SNDBUF != DEFAULT\n");

    socket_buffer = PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_udp, PICO_SOCKET_OPT_SNDBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    ret = pico_socket_getoption(sk_udp, PICO_SOCKET_OPT_SNDBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_SNDBUF is != than expected\n");

    socket_buffer = 2 * PICO_DEFAULT_SOCKETQ;
    ret = pico_socket_setoption(sk_udp, PICO_SOCKET_OPT_SNDBUF, &socket_buffer);
    fail_if(ret < 0, "socket> socket_setoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    ret = pico_socket_getoption(sk_udp, PICO_SOCKET_OPT_SNDBUF, &getsocket_buffer);
    fail_if(ret < 0, "socket> socket_getoption: supported PICO_SOCKET_OPT_SNDBUF failed\n");
    fail_if(getsocket_buffer != socket_buffer, "UDP socket> socket_setoption: PICO_SOCKET_OPT_SNDBUF is != than expected\n");

    /* Close sockets, eventually. */
    ret = pico_socket_close(sk_tcp);
    fail_if(ret < 0, "socket> tcp socket close failed: %s\n", strerror(pico_err));
    ret = pico_socket_close(sk_udp);
    fail_if(ret < 0, "socket> udp socket close failed: %s\n", strerror(pico_err));
}
END_TEST

#ifdef PICO_SUPPORT_CRC_FAULTY_UNIT_TEST
START_TEST (test_crc_check)
{
    uint8_t buffer[64] = {
        0x45, 0x00, 0x00, 0x40,                  /* start of IP hdr */
        0x91, 0xc3, 0x40, 0x00,
        0x40, 0x11, 0x24, 0xcf,                  /* last 2 bytes are CRC */
        0xc0, 0xa8, 0x01, 0x66,
        0xc0, 0xa8, 0x01, 0x64,                  /* end of IP hdr */
        0x15, 0xb3, 0x1F, 0x90,                  /* start of UDP/TCP hdr */
        0x00, 0x2c, 0x27, 0x22,                  /* end of UDP hdr */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x0b, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,                  /* end of TCP hdr */
        0x01, 0x23, 0x45, 0x67,                  /* start of data */
        0x89, 0xab, 0xcd, 0xef,
        0xc0, 0xca, 0xc0, 0x1a
    };
    struct pico_frame *f = NULL;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) buffer;
    struct pico_udp_hdr *udp_hdr = NULL;
    struct pico_tcp_hdr *tcp_hdr = NULL;
    uint32_t *f_usage_count = NULL;
    uint8_t *f_buffer = NULL;
    int ret = -1;

    printf("START CRC TEST\n");
    pico_stack_init();

    /* IPv4 CRC unit tests */
    /* Allocated memory will not be freed when pico_ipv4_crc_check fails */
    f = calloc(1, sizeof(struct pico_frame));
    f_usage_count = calloc(1, sizeof(uint32_t));
    f_buffer = calloc(1, sizeof(uint8_t));
    f->net_hdr = buffer;
    f->net_len = PICO_SIZE_IP4HDR;
    f->transport_hdr = buffer + PICO_SIZE_IP4HDR;
    f->transport_len = sizeof(buffer) - PICO_SIZE_IP4HDR;
    f->usage_count = f_usage_count;
    f->buffer = f_buffer;
    *(f->usage_count) = 512;

    hdr->crc = 0;
    printf(">>>>>>>>>>>>>>>>>>>>> CRC VALUE = %X\n", pico_checksum(hdr, PICO_SIZE_IP4HDR));
    hdr->crc = short_be(0x24CF); /* Make check pass */
    ret = pico_ipv4_crc_check(f);
    fail_if(ret == 0, "correct IPv4 checksum got rejected\n");
    hdr->crc = short_be(0x8899); /* Make check fail */
    ret = pico_ipv4_crc_check(f);
    fail_if(ret == 1, "incorrect IPv4 checksum got accepted\n");

    /* UDP CRC unit tests */
    /* Allocated memory will be freed when pico_transport_crc_check fails */
    f = calloc(1, sizeof(struct pico_frame));
    f_usage_count = calloc(1, sizeof(uint32_t));
    f_buffer = calloc(1, sizeof(uint8_t));
    f->net_hdr = buffer;
    f->transport_hdr = buffer + PICO_SIZE_IP4HDR;
    f->transport_len = sizeof(buffer) - PICO_SIZE_IP4HDR;
    f->usage_count = f_usage_count;
    f->buffer = f_buffer;
    *(f->usage_count) = 1;
    hdr->proto = 0x11; /* UDP */
    hdr->crc = short_be(0x24cf); /* Set IPv4 CRC correct */
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;

    /* udp_hdr->crc = 0; */
    /* printf(">>>>>>>>>>>>>>>>>>>>> UDP CRC VALUE = %X\n", pico_udp_checksum_ipv4(f)); */
    ret = pico_transport_crc_check(f);
    fail_if(ret == 0, "correct UDP checksum got rejected\n");
    udp_hdr->crc = 0;
    ret = pico_transport_crc_check(f);
    fail_if(ret == 0, "UDP checksum of 0 did not get ignored\n");
    udp_hdr->crc = short_be(0x8899); /* Make check fail */
    ret = pico_transport_crc_check(f);
    fail_if(ret == 1, "incorrect UDP checksum got accepted\n");

    /* TCP CRC unit tests */
    /* Allocated memory will be freed when pico_transport_crc_check fails */
    f = calloc(1, sizeof(struct pico_frame));
    f_usage_count = calloc(1, sizeof(uint32_t));
    f_buffer = calloc(1, sizeof(uint8_t));
    f->net_hdr = buffer;
    f->transport_hdr = buffer + PICO_SIZE_IP4HDR;
    f->transport_len = sizeof(buffer) - PICO_SIZE_IP4HDR;
    f->usage_count = f_usage_count;
    f->buffer = f_buffer;
    *(f->usage_count) = 1;
    hdr->proto = 0x06; /* TCP */
    hdr->crc = short_be(0x24cf); /* Set IPv4 CRC correct */
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    tcp_hdr->seq = long_be(0x002c2722); /* Set sequence number correct */

    /* tcp_hdr = 0; */
    /* printf(">>>>>>>>>>>>>>>>>>>>> TCP CRC VALUE = %X\n", pico_tcp_checksum_ipv4(f)); */
    tcp_hdr->crc = short_be(0x0016); /* Set correct TCP CRC */
    ret = pico_transport_crc_check(f);
    fail_if(ret == 0, "correct TCP checksum got rejected\n");
    tcp_hdr->crc = short_be(0x8899); /* Make check fail */
    ret = pico_transport_crc_check(f);
    fail_if(ret == 1, "incorrect TCP checksum got accepted\n");
}
END_TEST
#endif
