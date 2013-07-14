/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Daniele Lacamera
*********************************************************************/

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

 
volatile enum zmq_hshake_state {
  ST_LISTEN = 0,
  ST_CONNECTED,
  ST_SIGNATURE,
  ST_VERSION,
  ST_GREETING,
  ST_RDY
};

struct __attribute__((packed)) zmq_msg {
    uint8_t flags;
    uint8_t len;
    char    txt[0];
};

struct zmtp_socket {
  struct pico_socket *sock;
  enum zmq_hshake_state state;
  void (*ready)(struct zmtp_socket *z);
};

static int ztmp_socket_cmp(void *ka, void *kb)
{
  struct ztmp_socket *a = ka;
  struct ztmp_socket *b = kb;
  if (a->sock < b->sock)
    return -1;
  if (b->sock < a->sock)
    return 1;
  return 0;
}

PICO_TREE_DECLARE(ztmp_sockets, ztmp_socket_cmp);

void zmq_send(struct zmtp_socket *s, char *txt, int len)
{
    struct zmq_msg msg;
    msg.flags = 4;
    msg.len = (uint8_t) len;
    memcpy(msg.txt, txt, len);
    zmtp_socket_write(s, &msg, len + 2);
}

static void hs_connected(struct zmtp_socket *s)
{
  uint8_t my_ver[2] = {3u, 0};
  uint8_t my_signature[10] =  {0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0x7f};
  uint8_t my_greeting[52] = {'N','U','L','L', 0};
  zmtp_socket_write(s, my_signature, 10);
  zmtp_socket_write(s, my_ver, 2);
  zmtp_socket_write(s, my_greeting, 52);
  Handshake_state = ST_SIGNATURE;
  remaining_hs_bytes = 64;
  conn_led = 1;
}
 
static void hs_signature(struct zmtp_socket *s)
{
  uint8_t incoming[20];
  int ret;
  
  ret = zmtp_socket_read(s, incoming, 10);
  if (ret < 10) {
    printf("Received invalid signature\n");
    zmtp_socket_close(s);
    Handshake_state = ST_LISTEN;
    conn_led = 0;
    return;
  }
  if (incoming[0] != 0xFF) {
    printf("Received invalid signature\n");
    zmtp_socket_close(s);
    Handshake_state = ST_LISTEN;
    conn_led = 0;
    return;
  }
  printf("Valid signature received. len = %d, first byte: %02x\n", ret, incoming[0]);
  remaining_hs_bytes -= ret;
  Handshake_state = ST_VERSION;
}
 
static void hs_version(struct zmtp_socket *s)
{
  uint8_t incoming[20];
  int ret;
  ret = zmtp_socket_read(s, incoming, 2);
  if (ret < 0) {
    printf("Cannot exchange valid version information. Read returned -1\n");
    zmtp_socket_close(s);
    Handshake_state = ST_LISTEN;
    conn_led = 0;
    return;
  }
  if (ret == 0)
     return;
    
  remaining_hs_bytes -= ret;
  if (incoming[0] != 3) {
    printf("Version %d.x not supported by this publisher\n", incoming[0]);
    zmtp_socket_close(s);
    Handshake_state = ST_LISTEN;
    conn_led = 0;
    return;
  }
  printf("Subscriber is using version 3. Good!\n");
  Handshake_state = ST_GREETING;
}
 
static void hs_greeting(struct zmtp_socket *s)
{
  uint8_t incoming[64];
  int ret;
  ret = zmtp_socket_read(s, incoming, 64);
  printf("zmtp_socket_read in greeting returned %d\n", ret);    
  if (ret == 0)
   return;  
  if (ret < 0) {
    printf("Cannot retrieve valid greeting\n");
    zmtp_socket_close(s);
    Handshake_state = ST_LISTEN;
    conn_led = 0;
    return;
  }
  printf("Paired. Sending Ready.\n");
  Handshake_state = ST_RDY;
  zmq_send(s, "READY   ", 8);
  
}
 
static void hs_rdy(struct zmtp_socket *s)
{
    int ret;
    uint8_t incoming[258];
    ret = zmtp_socket_read(s, incoming, 258);
    printf("Got %d bytes from subscriber whilst in rdy state.\n", ret);
}
 
static void(*hs_cb[])(struct zmtp_socket *) = {
    NULL,
    hs_connected,
    hs_signature,
    hs_version,
    hs_greeting,
    hs_rdy
};
 
void cb_tcp0mq(uint16_t ev, struct pico_socket *s)
{
  struct pico_ip4 orig;
  uint16_t port;
  char peer[30];
 
  if (ev & PICO_SOCK_EV_RD) {
    if (hs_cb[Handshake_state])
      hs_cb[Handshake_state](s);
  }
 
  if (ev & PICO_SOCK_EV_CONN) { 
    struct pico_socket *z;
    z = pico_socket_accept(s, &orig, &port);
    pico_ipv4_to_string(peer, orig.addr);
    printf("tcp0mq> Connection requested by %s:%d.\n", peer, short_be(port));
    if (Handshake_state == ST_LISTEN) {
        printf("tcp0mq> Accepted connection!\n");
        conn_led = 1;
        zmq_sock = z;
        Handshake_state = ST_CONNECTED;
    } else {
        printf("tcp0mq> Server busy, connection rejected\n");
        pico_socket_close(z);
    }
  }
 
  if (ev & PICO_SOCK_EV_FIN) {
    printf("tcp0mq> Connection closed.\n");
    Handshake_state = ST_LISTEN;
    conn_led = 0;
  }
 
  if (ev & PICO_SOCK_EV_ERR) {
    printf("tcp0mq> Socket Error received: %s. Bailing out.\n", strerror(pico_err));
    printf("tcp0mq> Connection closed.\n");
    Handshake_state = ST_LISTEN;
    conn_led = 0;
  }
 
  if (ev & PICO_SOCK_EV_CLOSE) {
    printf("tcp0mq> event close\n");
    pico_socket_close(s);
    Handshake_state = ST_LISTEN;
    conn_led = 0;
  }
 
  if (ev & PICO_SOCK_EV_WR) {
    /* TODO: manage pending data */
  }
}

struct pico_socket *ztmp_producer(uint16_t _port, void (*cb)(struct zmtp_socket *z))
{
  struct pico_socket *s;
  struct pico_ipv4 inaddr_any = {0};
  uint16_t port = short_be(port);
  struct zmtp_producer *z = NULL;
  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcp0mq);
  if (!s)
    return NULL;
 
  dbg("zmtp_producer: BIND\n");
  if (pico_socket_bind(s, &inaddr_any, &port)!= 0) {
    printf("zmtp producer: BIND failed\n");
    return NULL;
  }
  if (pico_socket_listen(s, 40) != 0) {
    printf("zmtp producer: LISTEN failed\n");
    return NULL;
  }
  dbg("zmtp_producer: Active and bound to local port %d\n", short_be(port));

  z = pico_zalloc(sizeof(struct ztmp_producer));
  if (!z) {
    pico_socket_close(s);
    pico_err = PICO_ERR_ENOMEM;
    return NULL;
  }
  z->sock = s;
  z->state = ST_LISTEN;
  z->ready = cb;
  return z;
}

