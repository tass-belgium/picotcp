#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pico_ipv6.h"
#include "pico_stack.h"
#include "pico_socket.h"
#include "utils.h"

#define DURATION 30

struct iperf_hdr {
    int32_t flags;          /* 0 */
    int32_t numThreads;     /* 1 */
    int32_t mPort;          /* 5001  */
    int32_t bufferlen;      /* 0 */
    int32_t mWinBand;       /* 0 */
    int32_t mAmount;        /* 0xfffffc18 */
};

#define IPERF_PORT 5001
#define MTU 1444
#define SEND_BUF_SIZ (1024 * 2048)

char *cpy_arg(char **dst, char *str);
extern int IPV6_MODE;

static pico_time deadline;

static void panic(void)
{
    for(;; ) ;
}

static char buf[MTU] = {};

static void buf_paint(void)
{
    char paint[11] = "0123456789";
    int i;
    for (i = 0; i < MTU; i++) {
        buf[i] = paint[i % 10];
    }
}

static void send_hdr(struct pico_socket *s)
{
    struct iperf_hdr hdr = {};
    hdr.numThreads = long_be(1);
    hdr.mPort = long_be(5001);
    hdr.mAmount = long_be(0xfffffc18);
    pico_socket_write(s, &hdr, sizeof(hdr));
    deadline = PICO_TIME_MS() + DURATION * 1000;
}

static void iperf_cb(uint16_t ev, struct pico_socket *s)
{
    int r;
    static int end = 0;
    if (ev & PICO_SOCK_EV_CONN) {
        send_hdr(s);
        return;
    }

    if ((!end) && (ev & PICO_SOCK_EV_WR)) {
        if (PICO_TIME_MS() > deadline) {
            pico_socket_close(s);
            if (!pico_timer_add(2000, deferred_exit, NULL)) {
                printf("Failed to start exit timer, exiting now\n");
                exit(1);
            }
            end++;
        }

        pico_socket_write(s, buf, MTU);
    }

    if (!(end) && (ev & (PICO_SOCK_EV_FIN | PICO_SOCK_EV_CLOSE))) {
        if (!pico_timer_add(2000, deferred_exit, NULL)) {
            printf("Failed to start exit timer, exiting now\n");
            exit(1);
        }
        end++;
    }
}

static void iperfc_socket_setup(union pico_address *addr, uint16_t family)
{
    int yes = 1;
    uint16_t send_port = 0;
    struct pico_socket *s = NULL;
    uint32_t bufsize = SEND_BUF_SIZ;
    send_port = short_be(5001);
    s = pico_socket_open(family, PICO_PROTO_TCP, &iperf_cb);
    pico_socket_setoption(s, PICO_SOCKET_OPT_SNDBUF, &bufsize);
    pico_socket_connect(s, addr, send_port);
}

void app_iperfc(char *arg)
{
    struct pico_ip4 my_eth_addr, netmask;
    struct pico_device *pico_dev_eth;
    char *daddr = NULL, *dport = NULL;
    char *nxt = arg;
    uint16_t send_port = 0, listen_port = short_be(5001);
    int i = 0, ret = 0, yes = 1;
    struct pico_socket *s = NULL;
    uint16_t family = PICO_PROTO_IPV4;
    union pico_address dst = {
        .ip4 = {0}, .ip6 = {{0}}
    };
    union pico_address inaddr_any = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&daddr, arg);
        if (daddr) {
            if (!IPV6_MODE)
                pico_string_to_ipv4(daddr, &dst.ip4.addr);

      #ifdef PICO_SUPPORT_IPV6
            else {
                pico_string_to_ipv6(daddr, dst.ip6.addr);
                family = PICO_PROTO_IPV6;
            }
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing dest_addr */
        goto out;
    }

    iperfc_socket_setup(&dst, family);
    return;
out:
    dbg("Error parsing options!\n");
    exit(1);
}

