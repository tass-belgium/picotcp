/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Jelle De Vleeschouwer
 *********************************************************************/

/*
 * For testing purposes. pico_dev_radio_manager allows simulating a mesh
 * network for smoke tests. I previously used geomess, but that's another
 * dependency to add then. Then @danielinux wrote the pico_dev_radiotest but
 * that required adding a multicast route on the host which in its turn
 * required 'sudo'. So I wrote a small simulator which doesn't require sudo.
 *   - Jelle
 */

#include "pico_dev_radiotest.h"
#include "pico_addressing.h"
#include "pico_dev_tap.h"
#include "pico_802154.h"
#include "pico_device.h"
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_dev_radio_mgr.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>

#ifdef DEBUG_RADIOTEST
#define RADIO_DBG       dbg
#else
#define RADIO_DBG(...)  do { } while (0)
#endif

#define LISTENING_PORT  7777
#define MESSAGE_MTU     150
#define EVER            (;;)

struct socket {
    int s;
    uint8_t mgr;
    uint8_t id;
    uint8_t area0;
    uint8_t area1;
};

/* Compare two application sockets */
static int
pico_radio_mgr_sock_cmp(void *a, void *b)
{
    struct socket *sa = a, *sb = b;
    return (int)(sa->id - sb->id);
}

PICO_TREE_DECLARE(Sockets, pico_radio_mgr_sock_cmp);

/* Insert a new socket in the tree */
static int
pico_radio_mgr_socket_insert(int socket, uint8_t id, uint8_t area0, uint8_t area1, uint8_t mgr)
{
    struct socket *s = PICO_ZALLOC(sizeof(struct socket));
    if (s) {
        s->area0 = area0;
        s->area1 = area1;
        s->s = socket;
        s->mgr = mgr;
        s->id = id;
        if (!pico_tree_insert(&Sockets, s))
            return 0;
        PICO_FREE(s);
    }
    return -1;
}

/* Gather an array of poll descriptors with all sockets */
static struct pollfd *
pico_radio_mgr_socket_all(int *n)
{
    struct pico_tree_node *i = NULL;
    struct socket *key = NULL;
    struct pollfd *fds = NULL;
    int j = 1;
    *n = 0;

    /* Retrieve all sockets */
    pico_tree_foreach(i, &Sockets) {
        (*n)++;
    }

    /* Create array from tree */
    fds = PICO_ZALLOC(sizeof(struct pollfd) * (size_t)*n);
    if (fds) {
        /* Put every socket in array */
        pico_tree_foreach(i, &Sockets) {
            if (i && (key = i->keyValue)) {
                if (!key->id) {
                    fds[0].fd = key->s;
                    fds[0].events = POLLIN;
                } else {
                    fds[j].fd = key->s;
                    fds[j].events = POLLIN | POLLHUP;
                    j++;
                }
            }
        }
    }

    return fds;
}

/* Get connection socket that belongs to a particular node */
static struct socket *
pico_radio_mgr_socket_node(uint8_t id)
{
    struct socket test = { 0, 0, id };
    return pico_tree_findKey(&Sockets, &test);
}

/* Handle POLLHUP event */
static int
pico_radio_mgr_socket_hup(int socket)
{
    struct pico_tree_node *i = NULL;
    struct socket *key = NULL;

    pico_tree_foreach(i, &Sockets) {
        key = i->keyValue;
        if (key && key->s == socket) {
            pico_tree_delete(&Sockets, key);
            RADIO_DBG("Radio %d detached from network\n", key->id);
            PICO_FREE(key);
            close(socket);
            return 0;
        }
    }
    return -1;
}

/* Receive's an 'Hello'-message from the node that contains the id, the inserts
 * an entry in the Sockets-tree */
static int
pico_radio_mgr_welcome(int socket)
{
    int ret_len = sizeof(uint8_t);
    uint8_t id = 0, area0, area1;

    errno = 0;
    while ((ret_len = recv(socket, &id, (size_t)ret_len, 0)) != 1) {
        if (errno && EINTR != errno)
            goto hup;
    }
    while ((ret_len = recv(socket, &area0, (size_t)ret_len, 0)) != 1) {
        if (errno && EINTR != errno)
            goto hup;
    }
    while ((ret_len = recv(socket, &area1, (size_t)ret_len, 0)) != 1) {
        if (errno && EINTR != errno)
            goto hup;
    }

    if (id <= 0) { // Node's can't have ID '0'.
        RADIO_DBG("Invalid socket\n");
        close(socket);
        return -1;
    }

    RADIO_DBG("Connected to node %u in area %u and %u on socket %d.\n", id, area0, area1, socket);
    if (pico_radio_mgr_socket_insert(socket, id, area0, area1, 0)) {
        RADIO_DBG("Failed inserting new socket\n");
        close(socket);
        return -1;
    }

    return 0;
hup:
    RADIO_DBG("recv() failed with error: %s\n", strerror(errno));
    close(socket);
    return -1;
}

/* Accepts a new TCP connection request */
static int
pico_radio_mgr_accept(int socket)
{
    unsigned int len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int s = accept(socket, (struct sockaddr *)&addr, &len);
    if (s < 0) {
        RADIO_DBG("Failed accepting connection\n");
        return s;
    } else if (!s) {
        RADIO_DBG("accept() returned file descriptor '%d'\n", s);
        return s;
    }
    return pico_radio_mgr_welcome(s);
}

/* Start listening for TCP connection requests on 'LISTENING_PORT' */
static int
pico_radio_mgr_listen(void)
{
    struct sockaddr_in addr;
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int ret = 0, yes = 1;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTENING_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    ret = bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (ret < 0) {
        RADIO_DBG("Failed binding socket to address: %s\n", strerror(ret));
        return -1;
    }

    ret = listen(s, 5);
    if (ret < 0) {
        RADIO_DBG("Failed start listening\n");
        return -1;
    }

    /* Also insert server socket in tree for polling */
    if (pico_radio_mgr_socket_insert(s, 0, 0, 0, 1)) {
        close(s);
        return -1;
    }

    dbg("Started listening on port %d\n", LISTENING_PORT);
    return s;
}

/* Distribute received frame over all the areas where the node is attached to */
static void
pico_radio_mgr_distribute(uint8_t *buf, int len, uint8_t id)
{
    struct socket *node = pico_radio_mgr_socket_node(id);
    uint8_t area0 = 0, area1 = 0, ar0 = 0, ar1 = 0, phy = (uint8_t)len;
    struct pico_tree_node *i = NULL;
    struct socket *key = NULL;
    if (node) {
        RADIO_DBG("Received frame from node '%d' of '%d' bytes\n", id, len);
        area0 = node->area0;
        area1 = node->area1;
    } else {
        RADIO_DBG("Received frame from node not connected to network, weird..\n");
        return;
    }

    pico_tree_foreach(i, &Sockets) {
        key = i->keyValue;
        if (key && key->id != id && key->id) { // Do not sent to ourselves or manager
            ar0 = key->area0;
            ar1 = key->area1;
            if (area0 == ar0 || area0 == ar1 || (area1 && (area1 == ar0 || area1 == ar1))) {
                len = (int)sendto(key->s, &phy, (size_t)1, 0, NULL, 0);
                if (len != 1) return;
                len = (int)sendto(key->s, buf, (size_t)phy, 0, NULL, 0);
                if (len == (int)phy)
                    RADIO_DBG("Forwarded from '%u' of %d bytes sent to '%u'\n", id, len, key->id);
            }
        }
    }
}

/* Process poll-events */
static void
pico_radio_mgr_process(struct pollfd *fds, int n)
{
    uint8_t buf[MESSAGE_MTU] = { 0 }, node = 0, phy = 0;
    int i = 0, ret_len = 0;
    short event = 0;

    for (i = 0; i < n; i++) {
        event = fds[i].revents;
        if (event && (event & POLLIN)) { // POLLIN
            if (!i) {
                /* Accept a new connection */
                pico_radio_mgr_accept(fds[i].fd);
                continue;
            }

            /* Read from node  */
            ret_len = (int)recv(fds[i].fd, &phy, (size_t)1, 0);
            if (ret_len <= 0)
                goto hup;
            ret_len = (int)recv(fds[i].fd, buf, (size_t)phy, 0);
            if (ret_len <= 0 || ret_len != phy)
                goto hup;
            node = buf[ret_len - 2];
            pico_radio_mgr_distribute(buf, ret_len, node);
        } else if (event && (event & POLLHUP)) {
            goto hup;
        }
    }

    return;
hup:
    pico_radio_mgr_socket_hup(fds[i].fd);
}

static void
pico_radio_mgr_quit(int signum)
{
    struct pico_tree_node *i = NULL, *tmp = NULL;
    struct socket *key = NULL;
    IGNORE_PARAMETER(signum);

    dbg("Closing all sockets...");
    pico_tree_foreach_safe(i, &Sockets, tmp) {
        key = i->keyValue;
        if (key) {
            pico_tree_delete(&Sockets, key);
            shutdown(key->s, SHUT_RDWR);
            PICO_FREE(key);
        }
    }
    dbg("done.\n");
    exit(0);
}

/* Create and start a radio-manager instance */
int
pico_radio_mgr_start(void)
{
    int server = pico_radio_mgr_listen();
    struct pollfd *fds = NULL;
    nfds_t n = 0;
    int ret = 0;
    if (server < 0)
        return -1;

    signal(SIGQUIT, pico_radio_mgr_quit);

    for EVER {
        if (fds)
            PICO_FREE(fds);
        fds = pico_radio_mgr_socket_all((int *)&n);
        errno = 0;
        ret = poll(fds, n, 1);
        if (errno != EINTR && ret < 0) {
            RADIO_DBG("Socket error: %s\n", strerror(ret));
            return ret;
        } else if (!ret) {
            continue;
        }
        pico_radio_mgr_process(fds, (int)n);
    }
}
