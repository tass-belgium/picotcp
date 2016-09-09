#include "utils.h"
#include <pico_ipv4.h>
#include <pico_ipv6.h>
#include <pico_socket.h>
/*** START TCP CLIENT ***/
static char *buffer1;
static char *buffer0;

void compare_results(pico_time __attribute__((unused)) now, void __attribute__((unused)) *arg)
{
#ifdef CONSISTENCY_CHECK /* TODO: Enable */
    int i;
    printf("Calculating result.... (%p)\n", buffer1);

    if (memcmp(buffer0, buffer1, TCPSIZ) == 0)
        exit(0);

    for (i = 0; i < TCPSIZ; i++) {
        if (buffer0[i] != buffer1[i]) {
            fprintf(stderr, "Error at byte %d - %c!=%c\n", i, buffer0[i], buffer1[i]);
            exit(115);
        }
    }
#endif
    exit(0);

}

void cb_tcpclient(uint16_t ev, struct pico_socket *s)
{
    static int w_size = 0;
    static int r_size = 0;
    static int closed = 0;
    int r, w;
    static unsigned long count = 0;

    count++;
    picoapp_dbg("tcpclient> wakeup %lu, event %u\n", count, ev);

    if (ev & PICO_SOCK_EV_RD) {
        do {
            r = pico_socket_read(s, buffer1 + r_size, TCPSIZ - r_size);
            if (r > 0) {
                r_size += r;
                picoapp_dbg("SOCKET READ - %d\n", r_size);
            }

            if (r < 0)
                exit(5);
        } while(r > 0);
    }

    if (ev & PICO_SOCK_EV_CONN) {
        printf("Connection established with server.\n");
    }

    if (ev & PICO_SOCK_EV_FIN) {
        printf("Socket closed. Exit normally. \n");
        if (!pico_timer_add(2000, compare_results, NULL)) {
            printf("Failed to start exit timer, exiting now\n");
            exit(1);
        }
    }

    if (ev & PICO_SOCK_EV_ERR) {
        printf("Socket error received: %s. Bailing out.\n", strerror(pico_err));
        exit(1);
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        printf("Socket received close from peer - Wrong case if not all client data sent!\n");
        pico_socket_close(s);
        return;
    }

    if (ev & PICO_SOCK_EV_WR) {
        if (w_size < TCPSIZ) {
            do {
                w = pico_socket_write(s, buffer0 + w_size, TCPSIZ - w_size);
                if (w > 0) {
                    w_size += w;
                    picoapp_dbg("SOCKET WRITTEN - %d\n", w_size);
                    if (w < 0)
                        exit(5);
                }
            } while(w > 0);
        } else {
#ifdef INFINITE_TCPTEST
            w_size = 0;
            return;
#endif
            if (!closed) {
                pico_socket_shutdown(s, PICO_SHUT_WR);
                printf("Called shutdown()\n");
                closed = 1;
            }
        }
    }
}

void app_tcpclient(char *arg)
{
    char *daddr = NULL, *dport = NULL;
    char *nxt = arg;
    uint16_t send_port = 0, listen_port = short_be(5555);
    int i = 0, ret = 0, yes = 1;
    struct pico_socket *s = NULL;
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
            else
                pico_string_to_ipv6(daddr, dst.ip6.addr);
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing dest_addr */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&dport, nxt);
        if (dport && atoi(dport)) {
            send_port = short_be(atoi(dport));
        } else {
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    /* end of argument parsing */

    buffer0 = malloc(TCPSIZ);
    buffer1 = malloc(TCPSIZ);
    printf("Buffer1 (%p)\n", buffer1);
    for (i = 0; i < TCPSIZ; i++) {
        char c = (i % 26) + 'a';
        buffer0[i] = c;
    }
    memset(buffer1, 'a', TCPSIZ);

    printf("Connecting to: %s:%d\n", daddr, short_be(send_port));

    if (!IPV6_MODE)
        s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpclient);
    else
        s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpclient);

    if (!s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        exit(1);
    }

    pico_socket_setoption(s, PICO_TCP_NODELAY, &yes);

    if (!IPV6_MODE)
        ret = pico_socket_bind(s, &inaddr_any.ip4, &listen_port);
    else
        ret = pico_socket_bind(s, &inaddr_any.ip6, &listen_port);

    if (ret < 0) {
        printf("%s: error binding socket to port %u: %s\n", __FUNCTION__, short_be(listen_port), strerror(pico_err));
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_connect(s, &dst.ip4, send_port);
    else
        ret = pico_socket_connect(s, &dst.ip6, send_port);

    if (ret < 0) {
        printf("%s: error connecting to %s:%u: %s\n", __FUNCTION__, daddr, short_be(send_port), strerror(pico_err));
        exit(1);
    }

    return;

out:
    fprintf(stderr, "tcpclient expects the following format: tcpclient:dest_addr:dest_port\n");
    exit(255);
}
/*** END TCP CLIENT ***/
