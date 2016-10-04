#include "utils.h"
#include <pico_ipv4.h>
#include <pico_ipv6.h>
#include <pico_socket.h>
/*** START TCP BENCH ***/
#define TCP_BENCH_TX  1
#define TCP_BENCH_RX  2
#define TCP_BENCH_TX_FOREVER 3
static char *buffer1;
static char *buffer0;

int tcpbench_mode = 0;
struct pico_socket *tcpbench_sock = NULL;
static pico_time tcpbench_time_start, tcpbench_time_end;

void cb_tcpbench(uint16_t ev, struct pico_socket *s)
{
    static int closed = 0;
    static unsigned long count = 0;
    uint8_t recvbuf[1500];
    uint16_t port;
    char peer[200];
    /* struct pico_socket *sock_a; */

    static int tcpbench_wr_size = 0;
    static int tcpbench_rd_size = 0;
    int tcpbench_w = 0;
    int tcpbench_r = 0;
    double tcpbench_time = 0;

    count++;

    if (ev & PICO_SOCK_EV_RD) {
        do {
            /* read data, but discard */
            tcpbench_r = pico_socket_read(s, recvbuf, 1500);
            if (tcpbench_r > 0) {
                tcpbench_rd_size += tcpbench_r;
            }
        } while (tcpbench_r > 0);
        if (tcpbench_time_start == 0)
            tcpbench_time_start = PICO_TIME_MS();

        printf("tcpbench_rd_size = %d      \r", tcpbench_rd_size);
    }

    if (ev & PICO_SOCK_EV_CONN) {
        if (!IPV6_MODE) {
            struct pico_ip4 orig;
            if (tcpbench_mode == TCP_BENCH_TX || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
                printf("tcpbench> Connection established with server.\n");
            } else if (tcpbench_mode == TCP_BENCH_RX) {
                /* sock_a = pico_socket_accept(s, &orig, &port); */
                pico_socket_accept(s, &orig, &port);
                pico_ipv4_to_string(peer, orig.addr);
                printf("tcpbench> Connection established with %s:%d.\n", peer, short_be(port));
            }
        } else {
            struct pico_ip6 orig;
            if (tcpbench_mode == TCP_BENCH_TX || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
                printf("tcpbench> Connection established with server.\n");
            } else if (tcpbench_mode == TCP_BENCH_RX) {
                /* sock_a = pico_socket_accept(s, &orig, &port); */
                pico_socket_accept(s, &orig, &port);
#ifdef PICO_SUPPORT_IPV6
                pico_ipv6_to_string(peer, orig.addr);
                printf("tcpbench> Connection established with [%s]:%d.\n", peer, short_be(port));
#endif
            }
        }
    }

    if (ev & PICO_SOCK_EV_FIN) {
        printf("tcpbench> Socket closed. Exit normally. \n");
        if (tcpbench_mode == TCP_BENCH_RX) {
            tcpbench_time_end = PICO_TIME_MS();
            tcpbench_time = (tcpbench_time_end - tcpbench_time_start) / 1000.0; /* get number of seconds */
            printf("tcpbench> received %d bytes in %lf seconds\n", tcpbench_rd_size, tcpbench_time);
            printf("tcpbench> average read throughput %lf kbit/sec\n", ((tcpbench_rd_size * 8.0) / tcpbench_time) / 1000);
            pico_socket_shutdown(s, PICO_SHUT_WR);
            printf("tcpbench> Called shutdown write, ev = %d\n", ev);
        }

        if (!pico_timer_add(5000, deferred_exit, NULL)) {
            printf("tcpbench> Failed to start exit timer, exiting now\n");
            exit(1);
        }
    }

    if (ev & PICO_SOCK_EV_ERR) {
        printf("tcpbench> ---- Socket Error received: %s. Bailing out.\n", strerror(pico_err));
        if (!pico_err == PICO_ERR_ECONNRESET) {
            if (pico_timer_add(5000, deferred_exit, NULL)) {
                printf("tcpbench> Failed to start exit timer, exiting now\n");
                exit(1);
            }
        }
        else {
            printf("tcpbench> ---- Socket Error: '%s'. Was unexpected! Something went wrong.\n", strerror(pico_err));
            exit(2);
        }
    }

    if (ev & PICO_SOCK_EV_CLOSE) {
        printf("tcpbench> event close\n");
        if (tcpbench_mode == TCP_BENCH_RX) {
            pico_socket_close(s);
            printf("tcpbench> Called shutdown write, ev = %d\n", ev);
        } else if (tcpbench_mode == TCP_BENCH_TX || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
            pico_socket_close(s);
            return;
        }
    }

    if (ev & PICO_SOCK_EV_WR) {
        if (((tcpbench_wr_size < TCPSIZ) && (tcpbench_mode == TCP_BENCH_TX)) || tcpbench_mode == TCP_BENCH_TX_FOREVER) {
            do {
                tcpbench_w = pico_socket_write(tcpbench_sock, buffer0 + (tcpbench_wr_size % TCPSIZ), TCPSIZ - (tcpbench_wr_size % TCPSIZ));
                if (tcpbench_w > 0) {
                    tcpbench_wr_size += tcpbench_w;
                    /* printf("tcpbench> SOCKET WRITTEN - %d\n",tcpbench_w); */
                } else {
                    /* printf("pico_socket_write returned %d\n", tcpbench_w); */
                }

                if (tcpbench_time_start == 0)
                    tcpbench_time_start = PICO_TIME_MS();
            } while(tcpbench_w > 0);
            printf("tcpbench_wr_size = %d      \r", tcpbench_wr_size);
        } else {
            if (!closed && tcpbench_mode == TCP_BENCH_TX) {
                tcpbench_time_end = PICO_TIME_MS();
                pico_socket_shutdown(s, PICO_SHUT_WR);
                printf("tcpbench> TCPSIZ written\n");
                printf("tcpbench> Called shutdown()\n");
                tcpbench_time = (tcpbench_time_end - tcpbench_time_start) / 1000.0; /* get number of seconds */
                printf("tcpbench> Transmitted %u bytes in %lf seconds\n", TCPSIZ, tcpbench_time);
                printf("tcpbench> average write throughput %lf kbit/sec\n", ((TCPSIZ * 8.0) / tcpbench_time) / 1000);
                closed = 1;
            }
        }
    }
}

void app_tcpbench(char *arg)
{
    struct pico_socket *s;
    char *dport = NULL;
    char *dest = NULL;
    char *mode = NULL;
    char *nagle = NULL;
    int port = 0, i;
    uint16_t port_be = 0;
    char *nxt;
    char *sport = NULL;
    int nagle_off = 1;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } inaddr_any = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    nxt = cpy_arg(&mode, arg);

    if ((*mode == 't') || (*mode == 'f')) { /* TEST BENCH SEND MODE */
        if (*mode == 't')
            tcpbench_mode = TCP_BENCH_TX;
        else
            tcpbench_mode = TCP_BENCH_TX_FOREVER;

        printf("tcpbench> TX\n");

        nxt = cpy_arg(&dest, nxt);
        if (!dest) {
            fprintf(stderr, "tcpbench send needs the following format: tcpbench:tx:dst_addr[:dport][:n] -- 'n' is for nagle\n");
            exit(255);
        }

        printf ("+++ Dest is %s\n", dest);
        if (nxt) {
            printf("Next arg: %s\n", nxt);
            nxt = cpy_arg(&dport, nxt);
            printf("Dport: %s\n", dport);
        }

        if (nxt) {
            printf("Next arg: %s\n", nxt);
            nxt = cpy_arg(&nagle, nxt);
            printf("nagle: %s\n", nagle);
            if (strlen(nagle) == 1 && nagle[0] == 'n') {
                nagle_off = 0;
                printf("Nagle algorithm enabled\n");
            }
        }

        if (dport) {
            port = atoi(dport);
            port_be = short_be((uint16_t)port);
        }

        if (port == 0) {
            port_be = short_be(5555);
        }

        buffer0 = malloc(TCPSIZ);
        buffer1 = malloc(TCPSIZ);
        printf("Buffer1 (%p)\n", buffer1);
        for (i = 0; i < TCPSIZ; i++) {
            char c = (i % 26) + 'a';
            buffer0[i] = c;
        }
        memset(buffer1, 'a', TCPSIZ);
        printf("tcpbench> Connecting to: %s:%d\n", dest, short_be(port_be));

        if (!IPV6_MODE) {
            struct pico_ip4 server_addr;
            s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpbench);
            if (!s)
                exit(1);

            pico_socket_setoption(s, PICO_TCP_NODELAY, &nagle_off);

            /* NOTE: used to set a fixed local port and address
               local_port = short_be(6666);
               pico_string_to_ipv4("10.40.0.11", &local_addr.addr);
               pico_socket_bind(s, &local_addr, &local_port);*/

            pico_string_to_ipv4(dest, &server_addr.addr);
            pico_socket_connect(s, &server_addr, port_be);
        } else {
            struct pico_ip6 server_addr;
            s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpbench);
            if (!s)
                exit(1);

            pico_socket_setoption(s, PICO_TCP_NODELAY, &nagle_off);

            /* NOTE: used to set a fixed local port and address
               local_port = short_be(6666);
               pico_string_to_ipv4("10.40.0.11", &local_addr.addr);
               pico_socket_bind(s, &local_addr, &local_port);*/
#ifdef PICO_SUPPORT_IPV6
            pico_string_to_ipv6(dest, server_addr.addr);
            pico_socket_connect(s, &server_addr, port_be);
#endif

        }

    } else if (*mode == 'r') { /* TEST BENCH RECEIVE MODE */
        int ret;
        tcpbench_mode = TCP_BENCH_RX;
        printf("tcpbench> RX\n");

        cpy_arg(&sport, nxt);
        if (!sport) {
            fprintf(stderr, "tcpbench receive needs the following format: tcpbench:rx[:dport]\n");
            exit(255);
        }

        if (sport) {
            printf("s-port is %s\n", sport);
            port = atoi(sport);
            port_be = short_be((uint16_t)port);
            printf("tcpbench> Got port %d\n", port);
            free(sport);
        }

        if (port == 0) {
            port_be = short_be(5555);
        }

        printf("tcpbench> OPEN\n");
        if (!IPV6_MODE)
            s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpbench);
        else
            s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_tcpbench);

        if (!s)
            exit(1);

        printf("tcpbench> BIND\n");
        if (!IPV6_MODE)
            ret = pico_socket_bind(s, &inaddr_any.ip4, &port_be);
        else
            ret = pico_socket_bind(s, &inaddr_any.ip6, &port_be);

        if (ret < 0) {
            printf("tcpbench> BIND failed because %s\n", strerror(pico_err));
            exit(1);
        }

        printf("tcpbench> LISTEN\n");
        if (pico_socket_listen(s, 40) != 0)
            exit(1);

        printf("tcpbench> listening port %u ...\n", short_be(port_be));
    } else {
        printf("tcpbench> wrong mode argument\n");
        exit(1);
    }

    tcpbench_sock = s;

    /* free strdups */
    if (dport)
        free(dport);

    if (dest)
        free (dest);

    if (mode)
        free (mode);

    if (nagle)
        free (nagle);

    return;
}
/*** END TCP BENCH ***/
