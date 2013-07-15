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

#define MY_VERSION 1u

 
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

struct zmq_socket;

struct zmq_connector {
  struct pico_socket *sock;
  enum zmq_hshake_state state;
  struct zmq_socket *parent;
  struct zmq_connector *next;
};

struct zmq_socket {
  struct pico_socket *sock;
  void (*ready)(struct zmq_socket *z);
  enum zmq_hshake_state state;
  struct zmq_connector *subs;
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

static inline struct zmq_connector *find_subscriber(struct pico_socket *s)
{
  struct zmq_socket *search;
  struct pico_tree_node *idx;
  struct zmq_connector *el;
  pico_tree_foreach(idx, &zmq_sockets) {
    search = idx->keyValue;
    el = search->subs;
    while(el) {
      if (el->sock == s)
        return el;
      el = el->next;
    }
  }
  return NULL;
}


static void connector_add(struct zmq_socket *z, struct zmq_connector *zc)
{
  zc->next = z->subs;
  z->subs = zc;
  zc->parent = z;
  dbg("Added connector %p, sock is %p\n", zc, zc->sock);
}

static void connector_del(struct zmq_connector *zc)
{
  struct zmq_socket *z = zc->parent;
  if(z) {
    struct zmq_connector *el = z->subs, *prev = NULL;
    while(el) {
      if (el == zc) {
        if (prev)
          prev->next = zc->next;
        else
          z->subs = zc->next;;
        break;
      }
      prev = el;
      el = el->next;
    }
  }
  pico_socket_close(zc->sock);
  pico_free(zc);
}


static void hs_connected(struct zmq_connector *z)
{
  uint8_t my_ver[2] = {MY_VERSION, 0};
  uint8_t my_signature[10] =  {0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0x7f};
  uint8_t my_greeting[52] = {'N','U','L','L', 0};
  pico_socket_write(z->sock, my_signature, 10);
  pico_socket_write(z->sock, my_ver, 2);
  if (MY_VERSION > 2)
    pico_socket_write(z->sock, my_greeting, 52);
  z->state = ST_SIGNATURE;
}
 
static void hs_signature(struct zmq_connector *z)
{
  uint8_t incoming[20];
  int ret;
  
  ret = pico_socket_read(z->sock, incoming, 10);
  if (ret < 10) {
    dbg("Received invalid signature\n");
    connector_del(z);
    return;
  }
  if (incoming[0] != 0xFF) {
    dbg("Received invalid signature\n");
    connector_del(z);
    return;
  }
  dbg("Valid signature received. len = %d, first byte: %02x\n", ret, incoming[0]);
  z->state = ST_VERSION;
}
 
static void hs_version(struct zmq_connector *z)
{
  uint8_t incoming[20];
  int ret;
  ret = pico_socket_read(z->sock, incoming, 2);
  if (ret < 0) {
    dbg("Cannot exchange valid version information. Read returned -1\n");
    connector_del(z);
    return;
  }
  if (ret == 0)
     return;
/* Version check?    
  if (incoming[0] != 3) {
    dbg("Version %d.x not supported by this publisher\n", incoming[0]);
    connector_del(z);
    return;
  }
  dbg("Subscriber is using version 3. Good!\n");
*/
  dbg("Subscriber is using version %d. Good!\n", incoming[0]);
  if (incoming[0] == 3)
    z->state = ST_GREETING;
  else
    z->state = ST_RDY;
}
 
static void hs_greeting(struct zmq_connector *z)
{
  uint8_t incoming[64];
  int ret;
  ret = pico_socket_read(z->sock, incoming, 64);
  dbg("zmq_socket_read in greeting returned %d\n", ret);    
  if (ret == 0)
   return;  
  if (ret < 0) {
    dbg("Cannot retrieve valid greeting\n");
    connector_del(z);
    return;
  }
  dbg("Paired. Sending Ready.\n");
  z->state = ST_RDY;
  pico_socket_write(z->sock, "READY   ",8);
}

static void hs_rdy(struct zmq_connector *z)
{
    int ret;
    uint8_t incoming[258];
    ret = pico_socket_read(z->sock, incoming, 258);
    dbg("Got %d bytes from subscriber whilst in rdy state.\n", ret);
}
 
static void(*hs_cb[])(struct zmq_connector *) = {
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
  struct zmq_connector *z_a, *zc;
  struct zmq_socket *z = ZMTP(s);
  
  /* Accepting new subscribers... */
  if (z) {
    if (ev & PICO_SOCK_EV_CONN) { 
      z_a = pico_zalloc(sizeof(struct zmq_socket));
      if (z_a == NULL)
        return;
      
      z_a->sock = pico_socket_accept(s, &orig, &port);
      pico_ipv4_to_string(peer, orig.addr);
      dbg("tcp0mq> Connection requested by %s:%d.\n", peer, short_be(port));
      if (z->state == ST_LISTEN) {
          dbg("tcp0mq> Accepted connection! New subscriber.\n");
          connector_add(z, z_a);
          z_a->state = ST_CONNECTED;
          hs_connected(z_a);
      } else {
          dbg("tcp0mq> Server busy, connection rejected\n");
          pico_socket_close(z_a->sock);
      }
    }
    return;
  }

  zc = find_subscriber(s);
  if (!zc) {
    dbg("Cannot find subscriber!\n");
    return;
  }


  if (ev & PICO_SOCK_EV_RD) {
    if (hs_cb[zc->state])
      hs_cb[zc->state](zc);
  }
 
 
  if (ev & PICO_SOCK_EV_FIN) {
    dbg("tcp0mq> Connection closed.\n");
    connector_del(zc);
  }
 
  if (ev & PICO_SOCK_EV_ERR) {
    dbg("tcp0mq> Socket Error received: %s. Bailing out.\n", strerror(pico_err));
    connector_del(zc);
  }
 
  if (ev & PICO_SOCK_EV_CLOSE) {
    dbg("tcp0mq> event close\n");
    connector_del(zc);
  }
 
  if (ev & PICO_SOCK_EV_WR) {
  /* TODO: implement a counter to wake up parent when all subscribers are ready */
  //  if (z->ready)
  //    z->ready(z);
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
    dbg("zmq producer: BIND failed\n");
    return NULL;
  }
  if (pico_socket_listen(s, 40) != 0) {
    dbg("zmq producer: LISTEN failed\n");
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
  z->subs = NULL;
  pico_tree_insert(&zmq_sockets, z);
  dbg("zmq producer created.\n");
  return z;
}

int zmq_send(struct zmq_socket *z, char *txt, int len)
{
    struct zmq_msg *msg;
    struct zmq_connector *c = z->subs;
    int ret = 0;

    if (!c) 
      return 0; /* Need at least one subscriber */
  
    msg = pico_zalloc(len + 2);
    msg->flags = 4;
    msg->len = (uint8_t) len;
    memcpy(msg->txt, txt, len);

    while (c) {
      if ((ST_RDY == c->state) && (pico_socket_write(c->sock, msg, len + 2) > 0))
        ret++;
      c = c->next;
    }
    pico_free(msg);
    return ret;
}
