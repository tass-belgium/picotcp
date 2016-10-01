#include "utils.h"
#include <pico_socket.h>
#include <pico_ipv4.h>
/*** START TCP ECHO ***/
#define BSIZE (1024 * 10)
static char recvbuf[BSIZE];
static int pos = 0, len = 0;
static int flag = 0;

int send_tcpecho(struct pico_socket *s)
{
    int w, ww = 0;
    if (len > pos) {
        do {
            w = pico_socket_write(s, recvbuf + pos, len - pos);
            if (w > 0) {
                pos += w;
                ww += w;
                if (pos >= len) {
                    pos = 0;
                    len = 0;
                }
            }
        } while((w > 0) && (pos < len));
    }

    return ww;
}

void cb_tcpecho(uint16_t ev, struct pico_socket *s)
{
    int r = 0;

    picoapp_dbg("tcpecho> wakeup ev=%u\n", ev);

    if (ev & PICO_SOCK_EV_RD) {
        if (flag & PICO_SOCK_EV_CLOSE)
            printf("SOCKET> EV_RD, FIN RECEIVED\n");

        while (len < BSIZE) {
            r = pico_socket_read(s, recvbuf + len, BSIZE - len);
            if (r > 0) {
                len += r;
                flag &= ~(PICO_SOCK_EV_RD);
            } else {
                flag |= PICO_SOCK_EV_RD;
                break;
            }
        }
        if (flag & PICO_SOCK_EV_WR) {
            flag &= ~PICO_SOCK_EV_WR;
            send_tcpecho(s);
        }
    }

    if (ev & PICO_SOCK_EV_CONN) {
        uint32_t ka_val = 0;
        struct pico_socket *sock_a = {
            0
        };
        struct pico_ip4 orig = {
            0
        };
        uint16_t port = 0;
        char peer[30] = {
            0
        };
        int yes = 1;

        sock_a = pico_socket_accept(s, &orig, &port);
        pico_ipv4_to_string(peer, orig.addr);
        printf("Connection established with %s:%d.\n", peer, short_be(port));
        pico_socket_setoption(sock_a, PICO_TCP_NODELAY, &yes);
        /* Set keepalive options */
        ka_val = 5;
        pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPCNT, &ka_val);
        ka_val = 30000;
        pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPIDLE, &ka_val);
        ka_val = 5000;
        pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPINTVL, &ka_val);
    }

    if (ev & PICO_SOCK_EV_FIN) {
        printf("Socket closed. Exit normally. \n");
        if (!pico_timer_add(2000, deferred_exit, NULL)) {
            printf("Failed to start exit timer, exiting now\n");
            exit(1);
        }
    }

    if (ev & PICO_SOCK_EV_ERR) {
        printf("Socket error received: %s. Bailing out.\n", strerror(pico_err));
        exit(1);
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        printf("Socket received close from peer.\n");
        if (flag & PICO_SOCK_EV_RD) {
            pico_socket_shutdown(s, PICO_SHUT_WR);
            printf("SOCKET> Called shutdown write, ev = %d\n", ev);
        }
    }

    if (ev & PICO_SOCK_EV_WR) {
        r = send_tcpecho(s);
        if (r == 0)
            flag |= PICO_SOCK_EV_WR;
        else
            flag &= (~PICO_SOCK_EV_WR);
    }
}

void app_tcpecho(char *arg)
{
    char *nxt = arg;
    char *lport = NULL;
    uint16_t listen_port = 0;
    int ret = 0, yes = 1;
    struct pico_socket *s = NULL;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } inaddr_any = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            goto out;
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    /* end of argument parsing */

    if (!IPV6_MODE)
        s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpecho);
    else
        s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpecho);

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

    if (pico_socket_listen(s, 40) != 0) {
        printf("%s: error listening on port %u\n", __FUNCTION__, short_be(listen_port));
        exit(1);
    }

    printf("Launching PicoTCP echo server\n");
    return;

out:
    fprintf(stderr, "tcpecho expects the following format: tcpecho:listen_port\n");
    exit(255);
}
/*** END TCP ECHO ***/
