#include "utils.h"
#include <pico_socket.h>

/*** START UDP CLIENT ***/
/*
 * udpclient expects the following format: udpclient:dest_addr:sendto_port[:listen_port:datasize:loops:subloops]
 * dest_addr: IP address to send datagrams to
 * sendto_port: port number to send datagrams to
 * listen_port [OPTIONAL]: port number on which the udpclient listens
 * datasize [OPTIONAL]: size of the data given to the socket in one go
 * loops [OPTIONAL]: number of intervals in which data is send
 * subloops [OPTIONAL]: number of sends in one interval
 *
 * REMARK: once an optional parameter is given, all optional parameters need a value!
 *
 * f.e.: ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.255.0: -a udpclient:10.40.0.3:6667:6667:1400:100:10
 */

struct udpclient_pas *udpclient_pas;

static int exit_retry = 0;

static void request_exit_echo(pico_time now, void *arg)
{
    struct pico_socket *s = (struct pico_socket *)arg;
    char end[4] = "end";
    pico_socket_send(s, end, 4);
    if (exit_retry++ > 3) {
        pico_timer_add(1000, deferred_exit, udpclient_pas);
    } else {
        pico_timer_add(1000, request_exit_echo, s);
        printf("%s: requested exit of echo\n", __FUNCTION__);
    }
}

void udpclient_send(pico_time __attribute__((unused)) now, void __attribute__((unused))  *arg)
{
    struct pico_socket *s = udpclient_pas->s;
    char *buf = NULL;
    int i = 0, w = 0;
    static uint16_t loop = 0;

    if (++loop > udpclient_pas->loops) {
        pico_timer_add(1000, request_exit_echo, s);
        return;
    } else {
        buf = calloc(1, udpclient_pas->datasize);
        if (!buf) {
            printf("%s: no memory available\n", __FUNCTION__);
            return;
        }

        memset(buf, '1', udpclient_pas->datasize);
        picoapp_dbg("%s: performing loop %u\n", __FUNCTION__, loop);
        for (i = 0; i < udpclient_pas->subloops; i++) {
            w =  pico_socket_send(s, buf, udpclient_pas->datasize);
            if (w <= 0)
                break;
        }
        picoapp_dbg("%s: written %u byte(s) in each of %u subloops\n", __FUNCTION__, udpclient_pas->datasize, i);
        free(buf);
    }

    pico_timer_add(100, udpclient_send, NULL);
}

void cb_udpclient(uint16_t ev, struct pico_socket *s)
{
    char *recvbuf = NULL;
    int r = 0;

    if (ev & PICO_SOCK_EV_RD) {
        recvbuf = calloc(1, udpclient_pas->datasize);
        if (!recvbuf) {
            printf("%s: no memory available\n", __FUNCTION__);
            return;
        }

        do {
            r = pico_socket_recv(s, recvbuf, udpclient_pas->datasize);
        } while ( r > 0);
        free(recvbuf);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        printf("Socket Error received. Bailing out.\n");
        free(udpclient_pas);
        exit(7);
    }
}

void app_udpclient(char *arg)
{
    char *daddr = NULL, *lport = NULL, *sport = NULL, *s_datasize = NULL, *s_loops = NULL, *s_subloops = NULL;
    char *nxt = arg;
    char sinaddr_any[40] = {
        0
    };
    uint16_t listen_port = 0;
    int ret = 0;

    udpclient_pas = calloc(1, sizeof(struct udpclient_pas));
    if (!udpclient_pas) {
        printf("%s: no memory available\n", __FUNCTION__);
        exit(255);
    }

    udpclient_pas->s = NULL;
    udpclient_pas->loops = 100;
    udpclient_pas->subloops = 10;
    udpclient_pas->datasize = 1400;

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&daddr, arg);
        if (daddr) {
            if (!IPV6_MODE)
                pico_string_to_ipv4(daddr, &udpclient_pas->dst.ip4.addr);

      #ifdef PICO_SUPPORT_IPV6
            else
                pico_string_to_ipv6(daddr, udpclient_pas->dst.ip6.addr);
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing dest_addr */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            udpclient_pas->sport = short_be(atoi(sport));
        } else {
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            goto out;
        }
    } else {
        /* missing listen_port, use default */
        listen_port = 0;
    }

    if (nxt) {
        nxt = cpy_arg(&s_datasize, nxt);
        if (s_datasize && atoi(s_datasize)) {
            udpclient_pas->datasize = atoi(s_datasize);
        } else {
            goto out;
        }
    } else {
        /* missing datasize, incomplete optional parameters? -> exit */
        if (lport)
            goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&s_loops, nxt);
        if (s_loops && atoi(s_loops)) {
            udpclient_pas->loops = atoi(s_loops);
        } else {
            goto out;
        }
    } else {
        /* missing loops, incomplete optional parameters? -> exit */
        if (s_datasize)
            goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&s_subloops, nxt);
        if (s_subloops && atoi(s_subloops)) {
            udpclient_pas->subloops = atoi(s_subloops);
        } else {
            goto out;
        }
    } else {
        /* missing subloops, incomplete optional parameters? -> exit */
        if (s_loops)
            goto out;
    }

    /* end of argument parsing */

    if (!IPV6_MODE)
        pico_ipv4_to_string(sinaddr_any, inaddr_any.addr);

  #ifdef PICO_SUPPORT_IPV6
    else
        pico_ipv6_to_string(sinaddr_any, inaddr6_any.addr);
  #endif

    if (!IPV6_MODE)
        udpclient_pas->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpclient);
    else
        udpclient_pas->s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, &cb_udpclient);

    if (!udpclient_pas->s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        free(udpclient_pas);
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_bind(udpclient_pas->s, &inaddr_any, &listen_port);
    else
        ret = pico_socket_bind(udpclient_pas->s, &inaddr6_any, &listen_port);

    if (ret < 0) {
        free(udpclient_pas);
        printf("%s: error binding socket to %s:%u: %s\n", __FUNCTION__, sinaddr_any, short_be(listen_port), strerror(pico_err));
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_connect(udpclient_pas->s, &udpclient_pas->dst.ip4, udpclient_pas->sport);
    else
        ret = pico_socket_connect(udpclient_pas->s, &udpclient_pas->dst.ip6, udpclient_pas->sport);

    if (ret < 0) {
        printf("%s: error connecting to [%s]:%u: %s\n", __FUNCTION__, daddr, short_be(udpclient_pas->sport), strerror(pico_err));
        free(udpclient_pas);
        exit(1);
    }

    printf("\n%s: UDP client launched. Sending packets of %u bytes in %u loops and %u subloops to %s:%u\n\n",
           __FUNCTION__, udpclient_pas->datasize, udpclient_pas->loops, udpclient_pas->subloops, daddr, short_be(udpclient_pas->sport));

    pico_timer_add(100, udpclient_send, NULL);

    /* free strdups */
    if (daddr)
      free (daddr);
    if (lport)
      free (lport);
    if (sport)
      free (sport);
    if (s_datasize)
      free (s_datasize);
    if (s_loops)
      free (s_loops);
    if (s_subloops)
      free (s_subloops);

    return;

out:
    fprintf(stderr, "udpclient expects the following format: udpclient:dest_addr:dest_port[:listen_port:datasize:loops:subloops]\n");
    free(udpclient_pas);
    exit(255);
}
/*** END UDP CLIENT ***/
