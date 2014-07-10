#include "utils.h"
#include <pico_socket.h>

/*** START UDP NAT CLIENT ***/
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10: -a udpnatclient:10.50.0.8:6667: */
static struct pico_ip4 udpnatclient_inaddr_dst;
static uint16_t udpnatclient_port_be;

void udpnatclient_send(pico_time __attribute__((unused)) now, void *arg)
{
    int i, w;
    struct pico_socket *s = (struct pico_socket *)arg;
    char buf[1400] = { };
    char end[4] = "end";
    static int loop = 0;

    for ( i = 0; i < 3; i++) {
        w = pico_socket_send(s, buf, 1400);
    }
    if (++loop > 1000) {
        udpnatclient_port_be = 0;
        for (i = 0; i < 3; i++) {
            w = pico_socket_send(s, end, 4);
            if (w <= 0)
                break;

            printf("End!\n");
        }
        pico_timer_add(1000, deferred_exit, NULL);
        return;
    }
}

void cb_udpnatclient(uint16_t ev, struct pico_socket *s)
{
    char recvbuf[1400];
    int r = 0;

    if (ev & PICO_SOCK_EV_RD) {
        do {
            r = pico_socket_recv(s, recvbuf, 1400);
        } while(r > 0);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        printf("Socket Error received. Bailing out.\n");
        exit(7);
    }

    /* Not closing to test port check */
    /* pico_socket_close(s); */
}

void udpnatclient_open_socket(pico_time __attribute__((unused)) now, void __attribute__((unused)) *arg)
{
    struct pico_socket *s = NULL;
    static int loop;

    if (!udpnatclient_port_be)
        return;

    loop++;
    picoapp_dbg(">>>>> Loop %d\n", loop);
    if (!(loop % 100))
        printf("Created %d sockets\n", loop);

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpnatclient);
    if (!s)
        exit(1);

    if (pico_socket_connect(s, &udpnatclient_inaddr_dst, udpnatclient_port_be) != 0)
    {
        printf("Error connecting\n");
        exit(1);
    }

    picoapp_dbg("New socket with port %u\n", s->local_port);

    pico_timer_add(25, udpnatclient_send, s);
    pico_timer_add(25, udpnatclient_open_socket, 0);
}

void app_udpnatclient(char *arg)
{
    struct pico_socket *s;
    char *daddr, *dport;
    int port = 0;
    uint16_t port_be = 0;
    struct pico_ip4 inaddr_dst = ZERO_IP4;
    char *nxt;

    nxt = cpy_arg(&daddr, arg);
    if (!daddr) {
        fprintf(stderr, " udpnatclient expects the following format: udpnatclient:dest_addr[:dest_port]\n");
        exit(255);
    }

    if (nxt) {
        nxt = cpy_arg(&dport, nxt);
        if (dport) {
            port = atoi(dport);
            if (port > 0)
                port_be = short_be(port);
        }
    }

    if (port == 0) {
        port_be = short_be(5555);
    }

    printf("UDP NAT client started. Sending packets to %s:%d\n", daddr, short_be(port_be));

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpnatclient);
    if (!s)
        exit(1);

    pico_string_to_ipv4(daddr, &inaddr_dst.addr);

    if (pico_socket_connect(s, &inaddr_dst, port_be) != 0)
    {
        printf("Error binding the port \n");
        exit(1);
    }

    picoapp_dbg("New socket with port %u\n", s->local_port);

    udpnatclient_inaddr_dst = inaddr_dst;
    udpnatclient_port_be = port_be;

    pico_timer_add(100, udpnatclient_send, s);
    pico_timer_add(1000, udpnatclient_open_socket, 0);
}
/*** END UDP NAT CLIENT ***/
