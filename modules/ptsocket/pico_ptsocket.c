/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/
#include "pico_ptsocket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_stack.h"
#include <pthread.h>
#define PT_MAX_SOCKETS 255

#define ptsock_dbg(...) do {} while(0)

static struct pico_socket *pico_posix_sockets[PT_MAX_SOCKETS] = {};

static inline int NEW_SOCK(void)
{
    int i = 0;
    while(pico_posix_sockets[i]) {
        i++;
        if (i > PT_MAX_SOCKETS)
            return -1;
    }
    return i;
}

#define GET_SOCK(i) pico_posix_sockets[i]

static pthread_mutex_t Stack_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_mutex[PT_MAX_SOCKETS] = {};
#define GlobalLock() pthread_mutex_lock(&Stack_lock)
#define GlobalUnlock() pthread_mutex_unlock(&Stack_lock)
#define Lock(i) pthread_mutex_lock(&s_mutex[i])
#define Unlock(i) pthread_mutex_unlock(&s_mutex[i])

#ifdef PICO_SUPPORT_IPV4
#define IS_SOCK_IPV4(s) ((s->net == &pico_proto_ipv4))
#else
#define IS_SOCK_IPV4(s) (0)
#endif
#ifdef PICO_SUPPORT_IPV6
#define IS_SOCK_IPV6(s) ((s->net == &pico_proto_ipv6))
#else
#define IS_SOCK_IPV6(s) (0)
#endif


struct sockaddr_emu_ipv4 {
    uint16_t family;          /* AF_INET */
    uint16_t port;
    struct pico_ip4 addr;
};

struct sockaddr_emu_ipv6 {
    uint16_t family;           /* AF_INET6 */
    uint16_t port;             /* Transport layer port # */
    uint32_t flowinfo;         /* IPv6 flow information */
    struct pico_ip6 addr;      /* IPv6 address */
    uint32_t scope_id;         /* scope id (new in RFC2553) */
};

static void wakeup(uint16_t ev, struct pico_socket *s)
{
    ptsock_dbg("Unlocking %d\n", s->id);
    if ((ev & PICO_SOCK_EV_CLOSE) || (ev & PICO_SOCK_EV_FIN))
        pico_err = PICO_ERR_ESHUTDOWN;

    Unlock(s->id);
}


int pico_ptsocket(int domain, int type, int __attribute__((unused)) protocol)
{
    int sockfd = -1;
    uint16_t net, proto;

    GlobalLock();
    switch(domain) {
    case AF_INET:
        net = PICO_PROTO_IPV4;
        break;
    case AF_INET6:
        net = PICO_PROTO_IPV6;
        break;
    default:
        pico_err = PICO_ERR_EINVAL;
        goto err;
    }
    switch(type) {
    case SOCK_STREAM:
        proto = PICO_PROTO_TCP;
        break;
    case SOCK_DGRAM:
        proto = PICO_PROTO_UDP;
        break;
    default:
        pico_err = PICO_ERR_EINVAL;
        goto err;
    }

    sockfd = NEW_SOCK();
    if (sockfd >= 0) {
        pico_posix_sockets[sockfd] = pico_socket_open(net, proto, wakeup);
        if (!pico_posix_sockets[sockfd])
            goto err;

        pico_posix_sockets[sockfd]->id = sockfd;
    } else {
        pico_err = PICO_ERR_EBUSY;
        return -1;
    }

    pthread_mutex_init(&s_mutex[sockfd], NULL);

err:
    GlobalUnlock();
    ptsock_dbg("Hello, new socket here, idx: %d\n", sockfd);
    return sockfd;
}

int pico_ptbind(int sockfd, void *addr, int __attribute__((unused)) addrlen)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    struct sockaddr_emu_ipv4 *sockaddr4;
    struct sockaddr_emu_ipv6 *sockaddr6;
    int ret = -1;

    char dbg_src[30];

    GlobalLock();
    if (s) {
        if (IS_SOCK_IPV4(s)) {
            sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
            ret = pico_socket_bind(s, &sockaddr4->addr, &sockaddr4->port);
            /* test */
            pico_ipv4_to_string(dbg_src, sockaddr4->addr.addr);
            ptsock_dbg("Socket bound to %s:%d\n", dbg_src, short_be(sockaddr4->port));
        }

        if (IS_SOCK_IPV6(s)) {
            sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
            ret = pico_socket_bind(s, &sockaddr6->addr, &sockaddr6->port);
        }
    }

    GlobalUnlock();
    return ret;
}


int pico_ptconnect(int sockfd, void *addr, int __attribute__((unused)) addrlen)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    struct sockaddr_emu_ipv4 *sockaddr4;
    struct sockaddr_emu_ipv6 *sockaddr6;
    int ret = 0;
    ptsock_dbg("Entering connect\n");

    GlobalLock();
    if (s) {
        if (IS_SOCK_IPV4(s)) {
            sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
            ret = pico_socket_connect(s, &sockaddr4->addr, sockaddr4->port);
            ptsock_dbg("pico_socket_connect returned %d\n", ret);
        }

        if (IS_SOCK_IPV6(s)) {
            sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
            ret = pico_socket_connect(s, &sockaddr6->addr, sockaddr6->port);
        }
    }

    GlobalUnlock();
    if (ret == 0) {
        ptsock_dbg("Connect: suspended\n");
        Lock(sockfd);
        /* Suspend until the next wakeup callback */
        Lock(sockfd);
        if (pico_err == PICO_ERR_ESHUTDOWN)
            return -1;

        ptsock_dbg("Connect: resumed\n");
        Unlock(sockfd);
    }

    ptsock_dbg("Connect: returning %d\n", ret);
    return ret;
}


int pico_ptaccept(int sockfd, void *addr, int __attribute__((unused)) *addrlen)
{
    struct pico_socket *newsock = NULL;
    struct pico_socket *s = GET_SOCK(sockfd);
    struct sockaddr_emu_ipv4 *sockaddr4;
    struct sockaddr_emu_ipv6 *sockaddr6;

    while (!newsock) { /* Not yet available */
        if (s) {
            if (IS_SOCK_IPV4(s)) {
                ptsock_dbg("Accept: IP4\n");
                sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
                newsock = pico_socket_accept(s, &sockaddr4->addr, &sockaddr4->port);
            }

            if (IS_SOCK_IPV6(s)) {
                sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
                newsock = pico_socket_accept(s, &sockaddr6->addr, &sockaddr6->port);
            }
        }

        if (!newsock) {
            if (pico_err == PICO_ERR_EAGAIN) {
                Lock(sockfd);
                ptsock_dbg("Accept: lock!\n");
                Lock(sockfd);
                ptsock_dbg("Accept: unlock!\n");
            } else {
                return -1;
            }
        }
    }
    sockfd = NEW_SOCK();
    if (sockfd >= 0) {
        newsock->id = sockfd;
        pico_posix_sockets[sockfd] = newsock;
    } else {
        pico_err = PICO_ERR_EBUSY;
        return -1;
    }

    return sockfd;
}


int pico_ptlisten(int sockfd, int backlog)
{
    int ret = -1;
    struct pico_socket *s = GET_SOCK(sockfd);
    GlobalLock();
    if (s) {
        ret = pico_socket_listen(s, backlog);
    } else {
        pico_err = PICO_ERR_ENOENT;
    }

    GlobalUnlock();
    return ret;
}


int pico_ptrecvfrom(int sockfd, void *buf, int len, int __attribute__((unused)) flags, void *addr, int *addrlen)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    int ret = -1;
    struct sockaddr_emu_ipv4 *sockaddr4 = NULL;
    struct sockaddr_emu_ipv6 *sockaddr6 = NULL;

    GlobalLock();
    if (!s) {
        pico_err = PICO_ERR_ENOENT;
    } else {
        if (IS_SOCK_IPV4(s)) {
            sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
            if ((addrlen) && (*addrlen != sizeof(struct sockaddr_emu_ipv4))) {
                pico_err = PICO_ERR_EINVAL;
                goto fail;
            }
        } else if (IS_SOCK_IPV6(s)) {
            sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
            if ((addrlen) && (*addrlen != sizeof(struct sockaddr_emu_ipv6))) {
                pico_err = PICO_ERR_EINVAL;
                goto fail;
            }
        } else {
            goto fail;
        }

        ret = 0;
        Lock(sockfd);
        do {
            int r;
            if (IS_SOCK_IPV4(s))
                r = pico_socket_recvfrom(s, buf + ret, len - ret, &sockaddr4->addr, &sockaddr4->port);
            else
                r = pico_socket_recvfrom(s, buf + ret, len - ret, &sockaddr6->addr, &sockaddr6->port);

            if (r < 0) {
                Unlock(sockfd);
                ret = -1;
                break;
            }
            else if (r == 0) {
                Lock(sockfd);
            } else {
                ret += r;
            }
        } while(ret < len);
        Unlock(sockfd);
    }

fail:
    GlobalUnlock();
    return ret;
}


int pico_ptsendto(int sockfd, void *buf, int len, int __attribute__((unused)) flags, void *addr, int addrlen)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    int ret = -1;
    struct sockaddr_emu_ipv4 *sockaddr4 = NULL;
    struct sockaddr_emu_ipv6 *sockaddr6 = NULL;

    GlobalLock();
    if (!s) {
        pico_err = PICO_ERR_ENOENT;
    } else {
        if (IS_SOCK_IPV4(s)) {
            sockaddr4 = (struct sockaddr_emu_ipv4 *) addr;
            if (addrlen != sizeof(struct sockaddr_emu_ipv4)) {
                pico_err = PICO_ERR_EINVAL;
                goto fail;
            }
        } else if (IS_SOCK_IPV6(s)) {
            sockaddr6 = (struct sockaddr_emu_ipv6 *) addr;
            if (addrlen != sizeof(struct sockaddr_emu_ipv6)) {
                pico_err = PICO_ERR_EINVAL;
                goto fail;
            }
        } else {
            goto fail;
        }

        ret = 0;
        Lock(sockfd);
        do {
            int r;
            if (IS_SOCK_IPV4(s))
                r = pico_socket_sendto(s, buf + ret, len - ret, &sockaddr4->addr, sockaddr4->port);
            else
                r = pico_socket_sendto(s, buf + ret, len - ret, &sockaddr6->addr, sockaddr6->port);

            if (r < 0) {
                Unlock(sockfd);
                ret = -1;
                break;
            }
            else if (r == 0) {
                Lock(sockfd);
            } else {
                ret += r;
            }
        } while(ret < len);
        Unlock(sockfd);
    }

fail:
    GlobalUnlock();
    return ret;
}

int pico_ptread(int sockfd, void *buf, int len)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    int tot = 0, r;
    if (!s) {
        pico_err = PICO_ERR_ENOENT;
    } else {
        Lock(sockfd);
        while(tot == 0) {
            r = pico_socket_read(s, buf + tot, len - tot);
            if (r == 0) {
                Lock(sockfd);
                if (pico_err == PICO_ERR_ESHUTDOWN)
                    return -1;
            }
            else if (r > 0)
                tot += r;
            else {
                tot = -1;
                break;
            }
        }
    }

    Unlock(sockfd);
    return tot;
}


int pico_ptwrite(int sockfd, void *buf, int len)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    int tot = 0, r;
    if (!s) {
        pico_err = PICO_ERR_ENOENT;
    } else {
        Lock(sockfd);
        while(tot < len) {
            ptsock_dbg("Writing: from %d: %d\n", sockfd, len - tot);
            r = pico_socket_write(s, buf + tot, len - tot);
            ptsock_dbg("Write returned: %d\n", r);
            if (r == 0) {
                ptsock_dbg("Write: on lock\n");
                Lock(sockfd);
                if (pico_err == PICO_ERR_ESHUTDOWN)
                    return -1;

                ptsock_dbg("Write: unlocked\n");
            } else if (r > 0) {
                tot += r;
                ptsock_dbg("Write: %d/%d\n", tot, len);
            } else {
                tot = -1;
                break;
            }
        }
    }

    return tot;
}


int pico_ptclose(int sockfd)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    int ret = -1;
    if (s) {
        ret = pico_socket_close(s);
        Lock(sockfd);
        Lock(sockfd);
        Unlock(sockfd);
    } else {
        pico_err = PICO_ERR_ENOENT;
        return -1;
    }

    return ret;
}


int pico_ptshutdown(int sockfd, int how)
{
    struct pico_socket *s = GET_SOCK(sockfd);
    int ret = -1;
    if (s) {
        ret = pico_socket_close(s);
        if (how & PICO_SHUT_WR) {
            Lock(sockfd);
            Lock(sockfd);
            Unlock(sockfd);
        }
    } else {
        pico_err = PICO_ERR_ENOENT;
    }

    return ret;
}

static void *pico_ptloop(void __attribute__((unused)) *arg)
{
    while(1) {
        GlobalLock();
        pico_stack_tick();
        GlobalUnlock();
        usleep(10000);
    }
    return 0; /* makes compiler happy. */
}

int pico_ptstart(void)
{
    pthread_t pico_stack_thread;
    pthread_create(&pico_stack_thread, NULL, &pico_ptloop, NULL);
    ptsock_dbg("Thread: created.\n");
    return 0;
}

