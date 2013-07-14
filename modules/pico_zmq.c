/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Daniele Lacamera
*********************************************************************/

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_zmq.h"

 
enum zmq_hshake_state {
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

struct zmq_socket {
  struct pico_socket *sock;
  enum zmq_hshake_state state;
  void (*ready)(struct zmq_socket *z);
};

static int zmq_socket_cmp(void *ka, void *kb)
{
  struct zmq_socket *a = ka;
  struct zmq_socket *b = kb;
  if (a->sock < b->sock)
    return -1;
  if (b->sock < a->sock)
    return 1;
  return 0;
}


PICO_TREE_DECLARE(zmq_sockets, zmq_socket_cmp);
static inline struct zmq_socket *ZMTP(struct pico_socket *s)
{
  struct zmq_socket tst = { .sock = s };
  return (pico_tree_findKey(&zmq_sockets, &tst));
}


static void hs_connected(struct zmq_socket *z)
{
  uint8_t my_ver[2] = {3u, 0};
  uint8_t my_signature[10] =  {0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0x7f};
  uint8_t my_greeting[52] = {'N','U','L','L', 0};
  pico_socket_write(z->sock, my_signature, 10);
  pico_socket_write(z->sock, my_ver, 2);
  pico_socket_write(z->sock, my_greeting, 52);
  z->state = ST_SIGNATURE;
}
 
static void hs_signature(struct zmq_socket *z)
{
  uint8_t incoming[20];
  int ret;
  
  ret = pico_socket_read(z->sock, incoming, 10);
  if (ret < 10) {
    printf("Received invalid signature\n");
    pico_socket_close(z->sock);
    z->state = ST_LISTEN;
    return;
  }
  if (incoming[0] != 0xFF) {
    printf("Received invalid signature\n");
    pico_socket_close(z->sock);
    z->state = ST_LISTEN;
    return;
  }
  printf("Valid signature received. len = %d, first byte: %02x\n", ret, incoming[0]);
  z->state = ST_VERSION;
}
 
static void hs_version(struct zmq_socket *z)
{
  uint8_t incoming[20];
  int ret;
  ret = pico_socket_read(z->sock, incoming, 2);
  if (ret < 0) {
    printf("Cannot exchange valid version information. Read returned -1\n");
    pico_socket_close(z->sock);
    z->state = ST_LISTEN;
    return;
  }
  if (ret == 0)
     return;
    
  if (incoming[0] != 3) {
    printf("Version %d.x not supported by this publisher\n", incoming[0]);
    pico_socket_close(z->sock);
    z->state = ST_LISTEN;
    return;
  }
  printf("Subscriber is using version 3. Good!\n");
  z->state = ST_GREETING;
}
 
static void hs_greeting(struct zmq_socket *z)
{
  uint8_t incoming[64];
  int ret;
  ret = pico_socket_read(z->sock, incoming, 64);
  printf("zmq_socket_read in greeting returned %d\n", ret);    
  if (ret == 0)
   return;  
  if (ret < 0) {
    printf("Cannot retrieve valid greeting\n");
    pico_socket_close(z->sock);
    z->state = ST_LISTEN;
    return;
  }
  printf("Paired. Sending Ready.\n");
  z->state = ST_RDY;
  zmq_send(z, "READY   ", 8);
  
}
 
static void hs_rdy(struct zmq_socket *z)
{
    int ret;
    uint8_t incoming[258];
    ret = pico_socket_read(z->sock, incoming, 258);
    printf("Got %d bytes from subscriber whilst in rdy state.\n", ret);
}
 
static void(*hs_cb[])(struct zmq_socket *) = {
    NULL,
    hs_connected,
    hs_signature,
    hs_version,
    hs_greeting,
    hs_rdy
};
 
static void cb_tcp0mq(uint16_t ev, struct pico_socket *s)
{
  struct pico_ip4 orig;
  uint16_t port;
  char peer[30];
  struct zmq_socket *z = ZMTP(s);
 
  if (ev & PICO_SOCK_EV_RD) {
    if (hs_cb[z->state])
      hs_cb[z->state](z);
  }
 
  if (ev & PICO_SOCK_EV_CONN) { 
    struct pico_socket *z_a;
    z_a = pico_socket_accept(s, &orig, &port);
    pico_ipv4_to_string(peer, orig.addr);
    printf("tcp0mq> Connection requested by %s:%d.\n", peer, short_be(port));
    if (z->state == ST_LISTEN) {
        printf("tcp0mq> Accepted connection!\n");
        pico_tree_insert(&zmq_sockets, z_a);
        z_a->state = ST_CONNECTED;
        hs_connected(z_a);
    } else {
        printf("tcp0mq> Server busy, connection rejected\n");
        pico_socket_close(z_a);
    }
  }
 
  if (ev & PICO_SOCK_EV_FIN) {
    printf("tcp0mq> Connection closed.\n");
  }
 
  if (ev & PICO_SOCK_EV_ERR) {
    printf("tcp0mq> Socket Error received: %s. Bailing out.\n", strerror(pico_err));
    printf("tcp0mq> Connection closed.\n");
  }
 
  if (ev & PICO_SOCK_EV_CLOSE) {
    printf("tcp0mq> event close\n");
    pico_socket_close(s);
  }
 
  if (ev & PICO_SOCK_EV_WR) {
    if (z->ready)
      z->ready(z);
  }
}

ZMQ zmq_producer(uint16_t _port, void (*cb)(ZMQ z))
{
  struct pico_socket *s;
  struct pico_ip4 inaddr_any = {0};
  uint16_t port = short_be(_port);
  struct zmq_socket *z = NULL;
  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcp0mq);
  if (!s)
    return NULL;
 
  dbg("zmq_producer: BIND\n");
  if (pico_socket_bind(s, &inaddr_any, &port)!= 0) {
    printf("zmq producer: BIND failed\n");
    return NULL;
  }
  if (pico_socket_listen(s, 40) != 0) {
    printf("zmq producer: LISTEN failed\n");
    return NULL;
  }
  dbg("zmq_producer: Active and bound to local port %d\n", short_be(port));

  z = pico_zalloc(sizeof(struct zmq_socket));
  if (!z) {
    pico_socket_close(s);
    pico_err = PICO_ERR_ENOMEM;
    return NULL;
  }
  z->sock = s;
  z->state = ST_LISTEN;
  z->ready = cb;
  pico_tree_insert(&zmq_sockets, z);
  return z;
}

int zmq_send(struct zmq_socket *z, char *txt, int len)
{
    struct zmq_msg msg;
    msg.flags = 4;
    msg.len = (uint8_t) len;
    memcpy(msg.txt, txt, len);
    return pico_socket_write(z->sock, &msg, len + 2);
}
