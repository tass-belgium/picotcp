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

void dummy_cb(uint16_t __attribute__((unused)) ev, struct pico_socket __attribute__((unused)) *s)
{

}

void app_sendto_test(char *arg)
{
    char *nxt = arg;
    char *dstaddr = NULL;
    char *dstport = NULL;
    struct pico_ip4 inaddr_dst = {};
    struct pico_ip6 inaddr_dst6 = {};
    uint16_t dport;
    struct pico_socket *sock;
    int ret;

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&dstaddr, nxt);
        if (dstaddr) {
            if (!IPV6_MODE)
                pico_string_to_ipv4(dstaddr, &inaddr_dst.addr);

      #ifdef PICO_SUPPORT_IPV6
            else
                pico_string_to_ipv6(dstaddr, inaddr_dst6.addr);
      #endif
        } else {
            goto out;
        }
    } else {
        /* missing bind_addr */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&dstport, nxt);
        if (dstport && atoi(dstport)) {
            dport = short_be(atoi(dstport));
        } else {
            dport = short_be(5555);
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    if (!IPV6_MODE)
        sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &dummy_cb);
    else
        sock = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, &dummy_cb);

    ret = pico_socket_sendto(sock, "Testing", 7u, ((IPV6_MODE) ? (void *)(&inaddr_dst6) : (void *)(&inaddr_dst)), dport);
    if (ret < 0)
        printf("Failure in first pico_socket_send\n");

    ret = pico_socket_sendto(sock, "Testing", 7u, ((IPV6_MODE) ? (void *)(&inaddr_dst6) : (void *)(&inaddr_dst)), dport);
    if (ret < 0)
        printf("Failure in second pico_socket_send\n");

    ret = pico_socket_close(sock);
    if (ret)
        printf("Failure in pico_socket_close\n");

    printf("\n%s: UDP sendto test launched. Sending packets to ip %s port %u\n\n", __FUNCTION__, dstaddr, short_be(dport));
    return;

out:
    fprintf(stderr, "udp_sendto_test expects the following format: udp_sendto_test:dest_addr:[dest_por]t\n");
    exit(255);
}
