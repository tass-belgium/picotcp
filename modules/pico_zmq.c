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

#define ZMQ_FLAG_MORE_FRAMES 0x01
#define ZMQ_FLAG_LONG_MESSAGE 0x02

#define ZMQ_FRAME_SHORT_LEN 1
#define ZMQ_FRAME_LONG_LEN 8


enum zmq_state {
    ST_OPEN = 0,
    ST_CONNECTED,
    ST_SIGNATURE,
    ST_VERSION,
    ST_GREETING,
    ST_RDY,
    ST_BUSY
};

enum zmq_read_state {
    ST_RD_FLAG = 0,
    ST_RD_LEN,
    ST_RD_BUF,
    ST_RD_RDY
};

enum zmq_role {
    ROLE_NONE = 0,
    ROLE_PUBLISHER,
    ROLE_SUBSCRIBER
};

struct zmq_msg {
    uint8_t flags;
    uint64_t len;
    uint8_t *buf;
};

struct zmq_socket;

struct zmq_connector {
    struct pico_socket *sock;
    enum zmq_state state;
    ZMQ parent;
    enum zmq_role role;
    uint8_t signature[20];
    uint16_t bytes_received;
    struct zmq_connector *next;
    enum zmq_read_state read_state;
    struct zmq_msg msg_read;
};

struct zmq_socket {
    struct pico_socket *sock;
    void (*ready)(ZMQ z);
    enum zmq_state state;
    struct zmq_connector *subs;
    enum zmq_role role;
};

static void print_role(enum zmq_role r)
{
    switch(r)
    {
        case ROLE_NONE:
            dbg("Role is: No Role\n");
            break;

        case ROLE_PUBLISHER:
            dbg("Role is: Publisher\n");
            break;

        case ROLE_SUBSCRIBER:
            dbg("Role is: Subscriber\n");
            break;
    }
}

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
    struct zmq_socket tst = {
        .sock = s
    };
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
        struct zmq_connector *el = z->subs, *prev = NULL;  /* el = pointer to linked list */
        while(el) {
            if (el == zc) {         /* did we find the connector that we want to delete? */
                if (prev)           /* was there a previous list item? */
                    prev->next = zc->next; /* link the linked list again */
                else
                    z->subs = zc->next; /* we were at the beginning of the list */

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


static void zmq_hs_connected(struct zmq_connector *zc)
{
    ZMQ z = zc->parent;
    /* v2 signature */
    uint8_t my_signature[17] =  {
        0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0x7f, /* The actual V2 signature */
        1,                                  /* Protocol version V2.0 */
        0,                                  /* Socket type */
        0, 0,                               /* Identity fields, not used */
        0, 1, 1                             /* Subs only: SUBSCRIBE msg */
    };
    dbg("Connected - Sending signature\n");
    print_role(z->role);
    /* Set the actual socket type */
    my_signature[11] = z->role;

    if(z->role == ROLE_SUBSCRIBER)
        pico_socket_write(zc->sock, my_signature, 17);
    else
        pico_socket_write(zc->sock, my_signature, 14);

    zc->bytes_received = 0;
    zc->read_state = ST_RD_FLAG;
    zc->state = ST_SIGNATURE;
}

static void zmq_hs_signature(struct zmq_connector *zc)
{
    int ret;
    int req_size = 0;
    ZMQ z = zc->parent;
    dbg("Signature handler called\n");
    if(z->role == ROLE_SUBSCRIBER)
        req_size = 14;
    else
        req_size = 17;

    dbg("Going to read from socket %d bytes\n", req_size);
    ret = pico_socket_read(zc->sock, (zc->signature + zc->bytes_received), (req_size - zc->bytes_received));
    dbg("Read %d bytes from socket\n", ret);
    if (ret < 0) {
        dbg("Socket error\n");
        zmq_connector_del(zc);
        return;
    }

    zc->bytes_received += ret;

    if(zc->bytes_received == req_size)
    {
        if (zc->signature[0] != 0xFF || zc->signature[9] != 0x7F)
        {
            dbg("Received invalid signature - closing connection\n");
            zmq_connector_del(zc);
            return;
        }

        /* If we're a publisher we need to double check */
        if(z->role == ROLE_PUBLISHER)
        {
            if(zc->signature[11] != ROLE_SUBSCRIBER)
            {
                dbg("A non subscriber is trying to connect to us publishers\n");
                zmq_connector_del(zc);
                return;
            }
            if(zc->signature[16] != 0x01)
            {
                dbg("This subscriber is not interested in subscribing\n");
                zmq_connector_del(zc);
                return;
            }
        }

        dbg("State is ready\n");
        zc->bytes_received = 0;
        zc->state = ST_RDY;
    }
    return;
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
    pico_socket_write(zc->sock, "READY   ", 8);
}

static void zmq_hs_rdy(struct zmq_connector *zc)
{
    int ret;
    ZMQ z = zc->parent;
    uint8_t incoming[258];
    if (zc->role == ROLE_SUBSCRIBER)
    {
        if(ST_RD_FLAG == zc->read_state)
        {
            ret = pico_socket_read(zc->sock, &zc->msg_read.flags, 1);
            if(ret < 0)
            {
                goto sock_err;
            }
            else if (1 == ret)
            {
                zc->read_state = ST_RD_LEN;
                zc->bytes_received = 0;
                dbg("Flags read %x\n", zc->msg_read.flags);
            }
        }

        if(ST_RD_LEN == zc->read_state)
        {
            if(zc->msg_read.flags & ZMQ_FLAG_LONG_MESSAGE)
            {
                ret = pico_socket_read(zc->sock, (&zc->msg_read.len + zc->bytes_received), (ZMQ_FRAME_LONG_LEN - zc->bytes_received));
                if(ret < 0)
                {
                    goto sock_err;
                }
                zc->bytes_received += ret;

                dbg("Reading length, bytes received %d\n", ret);

                /* Full 8 bytes length received */
                if(ZMQ_FRAME_LONG_LEN == zc->bytes_received)
                {
                    /* Go from big endian to system endian*/
                    zc->msg_read.len = long_long_be(zc->msg_read.len);

                    if(zc->msg_read.len >= 1L<<16)
                    {
                        dbg("We cannot handle more than 65 536 bytes length\n");
                    }
                    dbg("Length2 is %llu\n", zc->msg_read.len);
                    zc->read_state = ST_RD_BUF;
                    zc->bytes_received = 0;
                    zc->msg_read.buf = pico_zalloc((uint16_t)zc->msg_read.len);
                    if(!zc->msg_read.buf)
                    {
                        dbg("No more memory :(\n");
                        return;
                    }
                }
            }
            else
            {
                uint8_t short_len;
                ret = pico_socket_read(zc->sock, &short_len, 1);
                if(ret < 0)
                {
                    goto sock_err;
                }
                else if (1 == ret)
                {
                    dbg("Short length is %u\n", short_len);
                    zc->msg_read.len = (uint64_t)short_len;
                    dbg("Length is %llu\n", zc->msg_read.len);
                    zc->read_state = ST_RD_BUF;
                    zc->bytes_received = 0;
                    zc->msg_read.buf = pico_zalloc((uint16_t)zc->msg_read.len);
                    if(!zc->msg_read.buf)
                    {
                        dbg("No more memory :(\n");
                        return;
                    }
                }
            }
        }

        if(ST_RD_BUF == zc->read_state)
        {
            ret = pico_socket_read(zc->sock, (zc->msg_read.buf + zc->bytes_received), (zc->msg_read.len - zc->bytes_received));
            if(ret < 0)
            {
                goto sock_err;
            }
            zc->bytes_received += ret;

            /* Full length received */
            if(zc->msg_read.len == zc->bytes_received)
            {
                zc->read_state = ST_RD_RDY;
                /* Callback */
                dbg("Calling ZMQ cb\n");
                z->ready(z);
            }
        }
        return;
    }

    ret = pico_socket_read(zc->sock, incoming, 258);
    dbg("Got %d bytes from subscriber whilst in rdy state.\n", ret);

sock_err:
    dbg("Error reading!\n");
    zmq_connector_del(zc);
    return;
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

static void (*zmq_hs_cb[])(struct zmq_connector *) = {
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
                dbg("tcp0mq> Accepted connection! New subscriber on sock %p.\n", z_a->sock);
                zmq_connector_add(z, z_a);
                z_a->role = ROLE_SUBSCRIBER;
                dbg("Received new connection\n");
                print_role(z_a->role);
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
/*    pico_socket_close(s); */
        return;
    }

    if ((ev & PICO_SOCK_EV_CONN) && zc->role == ROLE_SUBSCRIBER && zc->state == ST_OPEN)
    {
        dbg("Socket %p is set to connected\n", s);
        zc->state = ST_CONNECTED;
        zmq_hs_connected(zc);
    }


    if (ev & PICO_SOCK_EV_RD) {
        dbg("Socket %p Can be read \n", s);
        if (zmq_hs_cb[zc->state])
            zmq_hs_cb[zc->state](zc);
    }


    if ((ev & PICO_SOCK_EV_WR) && zc->parent && (zc->parent->role == ROLE_PUBLISHER) && (zc->state == ST_BUSY)) {
        dbg("Socket %p Can be written to \n", s);
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
    struct pico_ip4 ip = {
        0
    };
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

    z->state = ST_RDY;
    zmq_connector_add(z, z_c);
    return 0;
}

ZMQ zmq_publisher(uint16_t _port, void (*cb)(ZMQ z))
{
    struct pico_socket *s;
    struct pico_ip4 inaddr_any = {
        0
    };
    uint8_t sockopts = 1;
    uint16_t port = short_be(_port);
    ZMQ z = NULL;
    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcp0mq);
    if (!s)
        return NULL;

    pico_socket_setoption(s, PICO_TCP_NODELAY, &sockopts);

    dbg("zmq_publisher: BIND\n");
    if (pico_socket_bind(s, &inaddr_any, &port) != 0) {
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
    uint8_t *buffer;
    struct zmq_connector *c = z->subs;
    uint16_t len_int = (uint16_t) len;
    uint64_t _len = (uint64_t)len_int, _len_be;
    uint16_t total_size;
    int ret = 0;

    if (!c)
    {
        dbg("no subscribers, bailing out\n");
        return 0; /* Need at least one subscriber */
    }
    if(len_int > 255)
    {
        total_size = len_int + ZMQ_FRAME_LONG_LEN + 1;
        buffer = pico_zalloc((size_t)(total_size));
        buffer[0] = 0x02;
        _len_be = long_long_be(_len);
        memcpy(&buffer[1], &_len_be, sizeof(_len_be));
        memcpy(&buffer[9], txt, len_int);

    }
    else
    {
        total_size = len_int + ZMQ_FRAME_SHORT_LEN + 1;
        buffer = pico_zalloc((size_t)(len_int + ZMQ_FRAME_SHORT_LEN + 1));
        buffer[0] = 0x00;
        buffer[1] = (uint8_t) len_int;
        memcpy(&buffer[2], txt, len_int);
    }

    while (c) {
        dbg("write to %u\n", c->state);
        if ((ST_RDY == c->state) && (pico_socket_write(c->sock, buffer, total_size) > 0))
            ret++;

        c = c->next;
    }
    pico_free(buffer);
    return ret;
}

int zmq_recv(ZMQ z, char *txt)
{
    uint16_t ret;
    struct zmq_connector *nxt, *c = z->subs;
    if (z->state != ST_RDY)
    {
        dbg("State is not ready\n");
        return 0;
    }

    while (c) {
        nxt = c->next;

        if(ST_RD_RDY == c->read_state)
        {
            ret = (uint16_t) c->msg_read.len;
            memcpy(txt, c->msg_read.buf, ret);

            /* Cleanup object */
            free(c->msg_read.buf);
            c->msg_read.len = 0;
            c->bytes_received = 0;
            c->read_state = ST_RD_FLAG;
            return ret;
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
