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

 
enum zmq_state {
  ST_OPEN = 0,
  ST_CONNECTED,
  ST_SIGNATURE,
  ST_VERSION,
  ST_GREETING,
  ST_RDY,
  ST_BUSY
};

enum zmq_role {
  ROLE_NONE = 0,
  ROLE_PUBLISHER,
  ROLE_SUBSCRIBER
};

struct __attribute__((packed)) zmq_msg {
   uint8_t flags;
    uint8_t len;
    char    txt[0];
};

struct zmq_socket;

struct zmq_connector {
  struct pico_socket *sock;
  enum zmq_state state;
  ZMQ parent;
  enum zmq_role role;
  uint8_t bytes_received;
  struct zmq_connector *next;
};

struct zmq_socket {
  struct pico_socket *sock;
  void (*ready)(ZMQ z);
  enum zmq_state state;
  struct zmq_connector *subs;
  enum zmq_role role;
};

static int zmq_socket_cmp(void *ka, void *kb)
{
  ZMQ a = ka;
  ZMQ b = kb;
  if (a->sock < b->sock)
    return -1;
  if (b->sock < a->sock)
    return 1;
  return 0;
}
PICO_TREE_DECLARE(zmq_sockets, zmq_socket_cmp);

static inline ZMQ ZMTP(struct pico_socket *s)
{
  struct zmq_socket tst = { .sock = s };
  return (pico_tree_findKey(&zmq_sockets, &tst));
}

static inline struct zmq_connector *find_subscriber(struct pico_socket *s)
{
  ZMQ search;
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


static void zmq_connector_add(ZMQ z, struct zmq_connector *zc)
{
  zc->next = z->subs;
  z->subs = zc;
  zc->parent = z;
  dbg("Added connector %p, sock is %p\n", zc, zc->sock);
}

static void zmq_connector_del(struct zmq_connector *zc)
{
  ZMQ z = zc->parent;
  if(z) {
    struct zmq_connector *el = z->subs, *prev = NULL;      /* el = pointer to linked list */
    while(el) {
      if (el == zc) {               /* did we find the connector that we want to delete? */
        if (prev)                   /* was there a previous list item? */
          prev->next = zc->next;    /* link the linked list again */
        else
          z->subs = zc->next;       /* we were at the beginning of the list */
        break;
      }
      prev = el;
      el = el->next;
    }
  }
  pico_socket_close(zc->sock);
  pico_free(zc);
}

static void zmq_check_state(ZMQ z) 
{
  struct zmq_connector *c = z->subs;
  enum zmq_state default_state, option_state;
  if ((z->state != ST_RDY) && (z->state != ST_BUSY))
    return;
  if (z->role == ROLE_SUBSCRIBER) {
    default_state = ST_RDY;
    option_state = ST_BUSY;
  } else {
    default_state = ST_BUSY;
    option_state = ST_RDY;
  }
  z->state = default_state;
  while(c) {
    if (c->state == option_state) {
      z->state = option_state;
      return;
    }
    c = c->next;
  }
}


static void zmq_hs_connected(struct zmq_connector *z)
{
  /* v2 signature */
  uint8_t my_signature[14] =  {0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0x7f, 1, 1, 0, 0};

//  uint8_t my_ver[2] = {MY_VERSION, 0};
//  uint8_t my_greeting[52] = {'N','U','L','L', 0};

  pico_socket_write(z->sock, my_signature, 14);
//  pico_socket_write(z->sock, my_ver, 2);

//  if (MY_VERSION > 2)
//    pico_socket_write(z->sock, my_greeting, 52);

  z->state = ST_SIGNATURE;
//  z->state = ST_RDY;
}
 
static void zmq_hs_signature(struct zmq_connector *zc)
{
  uint8_t incoming[20];
  int ret;
  
  ret = pico_socket_read(zc->sock, incoming, 14);
  if (zc->bytes_received == 0 && ret > 0 &&  incoming[0] != 0xFF) {
    //dbg("Received invalid signature: [0]!=0xFF\n");
    zmq_connector_del(zc);
  }
  zc->bytes_received = (uint8_t)(zc->bytes_received + ret);
  if (zc->bytes_received < 14) {
    //dbg("Waiting for the rest of the sig - got %u bytes\n",zc->bytes_received);
    return;
  }

  //dbg("Valid signature received. len = %d, first byte: %02x\n", ret, incoming[0]);
  zc->state = ST_RDY;
}
 
static void zmq_hs_version(struct zmq_connector *zc)
{
  uint8_t incoming[20];
  int ret;
  ret = pico_socket_read(zc->sock, incoming, 2);
  if (ret < 0) {
    dbg("Cannot exchange valid version information. Read returned -1\n");
    zmq_connector_del(zc);
    return;
  }
  if (ret == 0)
     return;
/* Version check?    
  if (incoming[0] != 3) {
    dbg("Version %d.x not supported by this publisher\n", incoming[0]);
    zmq_connector_del(zc);
    return;
  }
  dbg("Subscriber is using version 3. Good!\n");
*/
  dbg("Subscriber is using version %d. Good!\n", incoming[0]);
  if (incoming[0] == 3)
    zc->state = ST_GREETING;
  else
    zc->state = ST_RDY;
}
 
static void zmq_hs_greeting(struct zmq_connector *zc)
{
  uint8_t incoming[64];
  int ret;
  ret = pico_socket_read(zc->sock, incoming, 64);
  dbg("zmq_socket_read in greeting returned %d\n", ret);    
  if (ret == 0)
   return;  
  if (ret < 0) {
    dbg("Cannot retrieve valid greeting\n");
    zmq_connector_del(zc);
    return;
  }
  zc->state = ST_RDY;
  zmq_check_state(zc->parent);
  dbg("Paired. Sending Ready.\n");
  pico_socket_write(zc->sock, "READY   ",8);
}

static void zmq_hs_rdy(struct zmq_connector *zc)
{
    int ret;
    uint8_t incoming[258];
    if (zc->role == ROLE_SUBSCRIBER)
      return;
    ret = pico_socket_read(zc->sock, incoming, 258);
    dbg("Got %d bytes from subscriber whilst in rdy state.\n", ret);
}

static void zmq_hs_busy(struct zmq_connector *zc)
{
  int was_busy = 0;
  if (zc->parent->state == ST_BUSY)
    was_busy = 1;
  zmq_check_state(zc->parent);
  if (was_busy && (zc->parent->state == ST_RDY) && zc->parent->ready)
    zc->parent->ready(zc->parent);
}
 
static void(*zmq_hs_cb[])(struct zmq_connector *) = {
    NULL,
    zmq_hs_connected,
    zmq_hs_signature,
    zmq_hs_version,
    zmq_hs_greeting,
    zmq_hs_rdy,
    zmq_hs_busy
};


static void cb_tcp0mq(uint16_t ev, struct pico_socket *s)
{
  struct pico_ip4 orig;
  uint16_t port;
  char peer[30];
  struct zmq_connector *z_a, *zc;
  ZMQ z = ZMTP(s);
  
  /* Publisher. Accepting new subscribers */
  if (z) {
    if (ev & PICO_SOCK_EV_CONN) { 
      z_a = pico_zalloc(sizeof(struct zmq_socket));
      if (z_a == NULL)
        return;
      
      z_a->sock = pico_socket_accept(s, &orig, &port);
      pico_ipv4_to_string(peer, orig.addr);
      dbg("tcp0mq> Connection requested by %s:%u.\n", peer, short_be(port));
      if (z->state == ST_OPEN) {
          dbg("tcp0mq> Accepted connection! New subscriber on sock %p.\n",z_a->sock);
          zmq_connector_add(z, z_a);
          z_a->role = ROLE_PUBLISHER;
          z_a->state = ST_CONNECTED;
          zmq_hs_connected(z_a);
      } else {
          dbg("tcp0mq> Server busy, connection rejected\n");
          pico_socket_close(z_a->sock);
      }
    }
    return;
  }

  zc = find_subscriber(s);
  if (!zc) {
    dbg("Cannot find subscriber with socket %p, ev = %d!\n", s, ev);
//    pico_socket_close(s);
    return;
  }

  if ((ev & PICO_SOCK_EV_CONN) && zc->role == ROLE_SUBSCRIBER && zc->state == ST_OPEN)
  {
     zc->state = ST_CONNECTED;
     zmq_hs_connected(zc);
  }


  if (ev & PICO_SOCK_EV_RD) {
    if (zmq_hs_cb[zc->state])
      zmq_hs_cb[zc->state](zc);
  }

  if ((ev & PICO_SOCK_EV_WR) && zc->parent && (zc->parent->role == ROLE_PUBLISHER) && (zc->state == ST_BUSY)) {
    if (zmq_hs_cb[zc->state])
      zmq_hs_cb[zc->state](zc);
  }
 
 
  if (ev & PICO_SOCK_EV_FIN) {
    dbg("tcp0mq> Connection closed.\n");
    zmq_connector_del(zc);
  }
 
  if (ev & PICO_SOCK_EV_ERR) {
    dbg("tcp0mq> Socket Error received: %s. Bailing out.\n", strerror(pico_err));
    zmq_connector_del(zc);
  }
 
  if (ev & PICO_SOCK_EV_CLOSE) {
    dbg("tcp0mq> event close\n");
    zmq_connector_del(zc);
  }
 
}

ZMQ zmq_subscriber(void (*cb)(ZMQ z))
{
  ZMQ z = pico_zalloc(sizeof(struct zmq_socket));
  if (!z) {
    pico_err = PICO_ERR_ENOMEM;
    return NULL;
  }
  z->state = ST_BUSY;
  z->ready = cb;
  z->role = ROLE_SUBSCRIBER;
  pico_tree_insert(&zmq_sockets, z);
  return z;
}

int zmq_connect(ZMQ z, char *address, uint16_t port) 
{
  struct pico_ip4 ip = {0};
  struct zmq_connector *z_c;
  uint8_t sockopts = 1;
  if (pico_string_to_ipv4(address, &ip.addr) < 0) {
    dbg("FIXME!! I need to synchronize with the dns client to get to my publisher :(\n");
    return -1;
  }

  z_c = pico_zalloc(sizeof(struct zmq_connector));
  if (!z_c)
    return -1;
  z_c->role = ROLE_SUBSCRIBER;
  z_c->state = ST_OPEN;
  z_c->sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcp0mq);
  if (!z_c->sock) {
    pico_free(z_c);
    return -1;
  }
  pico_socket_setoption(z_c->sock, PICO_TCP_NODELAY, &sockopts);
  if (pico_socket_connect(z_c->sock, &ip, short_be(port)) < 0)
    return -1;
  zmq_connector_add(z, z_c);
  return 0;
}

ZMQ zmq_publisher(uint16_t _port, void (*cb)(ZMQ z))
{
  struct pico_socket *s;
  struct pico_ip4 inaddr_any = {0};
  uint8_t sockopts = 1;
  uint16_t port = short_be(_port);
  ZMQ z = NULL;
  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcp0mq);
  if (!s)
    return NULL;
 
  pico_socket_setoption(s, PICO_TCP_NODELAY, &sockopts);

  dbg("zmq_publisher: BIND\n");
  if (pico_socket_bind(s, &inaddr_any, &port)!= 0) {
    dbg("zmq publisher: BIND failed\n");
    return NULL;
  }
  if (pico_socket_listen(s, 2) != 0) {
    dbg("zmq publisher: LISTEN failed\n");
    return NULL;
  }
  dbg("zmq_publisher: Active and bound to local port %d\n", short_be(port));

  z = pico_zalloc(sizeof(struct zmq_socket));
  if (!z) {
    pico_socket_close(s);
    pico_err = PICO_ERR_ENOMEM;
    return NULL;
  }
  z->sock = s;
  z->state = ST_OPEN;
  z->ready = cb;
  z->role = ROLE_PUBLISHER;
  z->subs = NULL;
  pico_tree_insert(&zmq_sockets, z);
  dbg("zmq publisher created.\n");
  return z;
}

int zmq_send(ZMQ z, char *txt, int len)
{
    struct zmq_msg *msg;
    struct zmq_connector *c = z->subs;
    int ret = 0;

    if (!c) 
    {
        dbg("no subscribers, bailing out\n");
        return 0; /* Need at least one subscriber */
    }
    msg = pico_zalloc((size_t)(len + 2));
    msg->flags = 4;
    msg->len = (uint8_t) len;
    memcpy(msg->txt, txt,(size_t) len);

    while (c) {
      dbg("write to %u\n",c->state);
      if ((ST_RDY == c->state) && (pico_socket_write(c->sock, msg, len + 2) > 0))
        ret++;
      c = c->next;
    }
    pico_free(msg);
    return ret;
}

int zmq_recv(ZMQ z, char *txt)
{
  int ret;
  struct zmq_msg msg;
  struct zmq_connector *nxt, *c = z->subs;
  if (z->state != ST_RDY)
    return 0;
  while (c) {
    nxt = c->next;
    ret = pico_socket_read(c->sock, &msg, 2);
    if (ret < 0) {
      dbg("Error reading!\n");
      zmq_connector_del(c);
    } else if (ret < 2) {
      c->state = ST_BUSY;
    } else {
      return pico_socket_read(c->sock, txt, msg.len);
    }
    c = nxt;
  }
  zmq_check_state(z);
  return 0;
}

void zmq_close(ZMQ z)
{
  struct zmq_connector *nxt, *c = z->subs;
  while(c) {
    nxt = c->next;
    zmq_connector_del(c);
    c = nxt;
  }
  pico_socket_close(z->sock);
  pico_free(z); 
}
