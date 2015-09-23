#include "utils.h"
#include <pico_socket.h>

/**** START UDP ECHO ****/
/*
 * udpecho expects the following format: udpecho:bind_addr:listen_port[:sendto_port:datasize]
 * bind_addr: IP address to bind to
 * listen_port: port number on which the udpecho listens
 * sendto_port [OPTIONAL]: port number to echo datagrams to (echo to originating IP address)
 * datasize [OPTIONAL]: max size of the data red from the socket in one go
 *
 * REMARK: once an optional parameter is given, all optional parameters need a value!
 *
 * f.e.: ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.3:255.255.255.0: -a udpecho:10.40.0.3:6667:6667:1400
 */
static int udpecho_exit = 0;

struct udpecho_pas *udpecho_pas;

void cb_udpecho(uint16_t ev, struct pico_socket *s)
{
    char *recvbuf = NULL;
    uint16_t port = 0;
    int r = 0;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } peer;
    if (udpecho_exit)
        return;
    if (ev == PICO_SOCK_EV_RD) {
        recvbuf = calloc(1, udpecho_pas->datasize);
        if (!recvbuf) {
            printf("%s: no memory available\n", __FUNCTION__);
            return;
        }

        do {
            r = pico_socket_recvfrom(s, recvbuf, udpecho_pas->datasize, IPV6_MODE ? (void *)peer.ip6.addr : (void *)&peer.ip4.addr, &port);
            /* printf("UDP recvfrom returned %d\n", r); */
            if (r > 0) {
                if (strncmp(recvbuf, "end", 3) == 0) {
                    printf("Client requested to exit... test successful.\n");
                    pico_timer_add(1000, deferred_exit, udpecho_pas);
                    udpecho_exit++;
                }

                pico_socket_sendto(s, recvbuf, r, IPV6_MODE ? (void *)peer.ip6.addr : (void *)&peer.ip4.addr, port);
            }
        } while (r > 0);
        free(recvbuf);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        printf("Socket Error received. Bailing out.\n");
        free(udpecho_pas);
        exit(7);
    }

    picoapp_dbg("%s: received packet from %08X:%u\n", __FUNCTION__, long_be(peer), short_be(port));
}

void app_udpecho(char *arg)
{
    char *baddr = NULL, *lport = NULL, *sport = NULL, *s_datasize = NULL;
    char *nxt = arg;
    uint16_t listen_port = 0;
    struct pico_ip4 inaddr_bind = { };
    struct pico_ip6 inaddr_bind6 = { };
    int ret = 0;

    udpecho_pas = calloc(1, sizeof(struct udpecho_pas));
    if (!udpecho_pas) {
        printf("%s: no memory available\n", __FUNCTION__);
        exit(255);
    }

    udpecho_pas->s = NULL;
    udpecho_pas->sendto_port = 0;
    udpecho_pas->datasize = 5000;

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&baddr, nxt);
        if (baddr) {
            if (!IPV6_MODE)
                pico_string_to_ipv4(baddr, &inaddr_bind.addr);

      #ifdef PICO_SUPPORT_IPV6
            else
                pico_string_to_ipv6(baddr, inaddr_bind6.addr);
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing bind_addr */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            listen_port = short_be(5555);
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            udpecho_pas->sendto_port = atoi(sport);
        } else {
            /* incorrect send_port */
            goto out;
        }
    } else {
        /* missing send_port, use default */
    }

    if (nxt) {
        nxt = cpy_arg(&s_datasize, nxt);
        if (s_datasize && atoi(s_datasize)) {
            udpecho_pas->datasize = atoi(s_datasize);
        } else {
            /* incorrect datasize */
            goto out;
        }
    } else {
        /* missing datasize, incomplete optional parameters? -> exit */
        if (sport)
            goto out;
    }

    /* end of argument parsing */
    if (!IPV6_MODE)
        udpecho_pas->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpecho);
    else 
        udpecho_pas->s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, &cb_udpecho);
    if (!udpecho_pas->s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        free(udpecho_pas);
        exit(1);
    }

    if (!IPV6_MODE)
        ret = pico_socket_bind(udpecho_pas->s, &inaddr_bind, &listen_port);
    else {
        ret = pico_socket_bind(udpecho_pas->s, &inaddr_bind6, &listen_port);
        printf("udpecho> Bound to [%s]:%d.\n", baddr, short_be(listen_port));
    }

    if (ret != 0) {
        free(udpecho_pas);
        if (!IPV6_MODE)
            printf("%s: error binding socket to %08X:%u: %s\n", __FUNCTION__, long_be(inaddr_bind.addr), short_be(listen_port), strerror(pico_err));
        else
            printf("%s: error binding socket to [%s]:%u: %s\n", __FUNCTION__, baddr, short_be(listen_port), strerror(pico_err));

        exit(1);
    }

#ifdef PICOAPP_IPFILTER
    {
        struct pico_ip4 address, in_addr_netmask, in_addr;
        /* struct pico_ipv4_link *link; */
        int ret = 0;
        address.addr = 0x0800280a;
        in_addr_netmask.addr = 0x00FFFFFF;
        in_addr.addr = 0x0000320a;
        /* link = pico_ipv4_link_get(&address); */

        printf("udpecho> IPFILTER ENABLED\n");

        /*Adjust your IPFILTER*/
        ret |= pico_ipv4_filter_add(NULL, 17, NULL, NULL, &in_addr, &in_addr_netmask, 0, 5555, 0, 0, FILTER_DROP);

        if (ret < 0)
            printf("Filter_add invalid argument\n");
    }
#endif

    printf("\n%s: UDP echo launched. Receiving packets of %u bytes on port %u\n\n", __FUNCTION__, udpecho_pas->datasize, short_be(listen_port));

    /* free strdups */
    if (baddr)
      free (baddr);
    if (lport)
      free (lport);
    if (sport)
      free (sport);
    if (s_datasize)
      free (s_datasize);

    return;

out:
    fprintf(stderr, "udpecho expects the following format: udpecho:bind_addr:listen_port[:sendto_port:datasize]\n");
    free(udpecho_pas);
    exit(255);
}
/*** END UDP ECHO ***/
