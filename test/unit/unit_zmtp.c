void test_zmtp_socket_open();
void test_zmtp_bind();


START_TEST (test_zmtp)
{
  test_zmtp_socket_open();
  //test_zmtp_bind();
}
END_TEST

void empty_cb(uint16_t ev, struct zmtp_socket* s)
{

}
void test_zmtp_bind()
{
  struct zmtp_socket * sock;
  int8_t ret;
  uint16_t port_be;
  struct pico_ip4 inaddr_link;

  sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMQ_TYPE_PUBLISHER, &empty_cb);
  if (sock == NULL)
  {
    fail("zmtp_bind: unable to initiate zmtp_socket");
  } else {
    
    pico_string_to_ipv4("10.40.0.2", &inaddr_link.addr);
    port_be = short_be(5555);
    /* socket_bind passing wrong parameters */
    ret = zmtp_socket_bind(NULL, &inaddr_link, &port_be);
    fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
    /*ret = zmtp_socket_bind(sock, NULL, &port_be);
    fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
    ret = zmtp_socket_bind(sock, &inaddr_link, NULL);
    fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
    /* socket_bind passing correct parameters */
    /*ret = zmtp_socket_bind(sock, &inaddr_link, &port_be);
      fail_if(ret < 0, "socket> tcp socket bind failed");*/
    //pico_free(sock);
    
  }
  
}
void test_zmtp_socket_open()
{
  struct zmtp_socket * sock;
  //test invalid arguments
  printf("test zmtp socket\n\n");
  sock = zmtp_socket_open(5, PICO_PROTO_TCP, ZMQ_TYPE_PUBLISHER, &empty_cb);
  fail_if(sock != NULL, "test_zmtp_socket failed on invalid first argument");
  sock = zmtp_socket_open(PICO_PROTO_IPV4, NULL, ZMQ_TYPE_SUBSCRIBER, &empty_cb);
  fail_if(sock != NULL, "test_zmtp_socket should fail on nulled protocol");
  sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, NULL, &empty_cb);
  fail_if(sock != NULL, "test_zmtp_socket should fail on nulled type");
  sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMQ_TYPE_PUBLISHER, NULL );
  fail_if(sock != NULL, "test_zmtp_socket should fail on null wakeup");

  printf("test valid");
  //test valid arguments
  sock = zmtp_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, ZMQ_TYPE_SUBSCRIBER, &empty_cb);
  fail_if(sock == NULL, "test_zmtp_socket failed on valid arguments");
}
