#include "utils.h"
#include <pico_ipv6.h>
#include <pico_socket.h>

extern void app_udpecho(char *arg);

/*** START Multicast RECEIVE + ECHO ***/
/*
 * multicast receive expects the following format: mcastreceive:link_addr:mcast_addr:listen_port:sendto_port
 * link_addr: mcastreceive picoapp IP address
 * mcast_addr: multicast IP address to receive
 * listen_port: port number on which the mcastreceive listens
 * sendto_port: port number to echo multicast traffic to (echo to originating IP address)
 *
 * f.e.: ./build/test/picoapp.elf --vde pic1:/tmp/pic0.ctl:10.40.0.3:255.255.0.0: -a mcastreceive:10.40.0.3:224.7.7.7:6667:6667
 */
extern struct udpclient_pas *udpclient_pas;
extern struct udpecho_pas *udpecho_pas;
#ifdef PICO_SUPPORT_MCAST
void app_mcastreceive_ipv6(char *arg)
{
    char *new_arg = NULL, *p = NULL, *nxt = arg;
    char *laddr = NULL, *maddr = NULL, *lport = NULL, *sport = NULL;
    uint16_t listen_port = 0;
    union pico_address inaddr_link = {
        0
    }, inaddr_mcast = {
        0
    },   src[5] = {
        {.ip6 = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0xac, 0x10, 0x01, 0 }},
        {.ip6 = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0xac, 0x10, 0x01, 0x10}},
        {.ip6 = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0xac, 0x10, 0x01, 0x01 }},
        {.ip6 = { 0xff, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0x01, 0x01, 0x01 }},
    };
    struct pico_ip_mreq mreq = ZERO_MREQ_IP6;
    struct pico_ip_mreq_source mreq_source = ZERO_MREQ_SRC_IP6;
    /* start of parameter parsing */
    if (nxt) {
        nxt = cpy_arg(&laddr, nxt);
        if (laddr) {
            pico_string_to_ipv6(laddr, &inaddr_link.ip6.addr[0]);
        } else {
            goto out;
        }
    } else {
        /* no arguments */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&maddr, nxt);
        if (maddr) {
            pico_string_to_ipv6(maddr, &inaddr_mcast.ip6.addr[0]);
        } else {
            goto out;
        }
    } else {
        /* missing multicast address */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            /* incorrect listen_port */
            goto out;
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            /* unused at this moment */
            /* send_port = short_be(atoi(sport)); */
        } else {
            /* incorrect send_port */
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    /* end of parameter parsing */

    printf("\n%s: multicast receive started. Receiving packets on [%s]:%d\n\n", __FUNCTION__, maddr, short_be(listen_port));

    /* udpecho:bind_addr:listen_port[:sendto_port:datasize] */
    new_arg = calloc(1, strlen(laddr) + 1 + strlen(lport) + 1 + strlen(sport) + strlen(",64:") + 1);
    p = strcat(new_arg, laddr);
    p = strcat(p + strlen(laddr), ",");
    p = strcat(p + 1, lport);
    p = strcat(p + strlen(lport), ",");
    p = strcat(p + 1, sport);
    p = strcat(p + strlen(sport), ",64,");

    /* DAD needs to verify the link address before we can continue */
    while(!pico_ipv6_link_get(&inaddr_link.ip6)) {
        pico_stack_tick();
        usleep(2000);
    }
    app_udpecho(new_arg);

    memcpy(&mreq.mcast_group_addr, &inaddr_mcast, sizeof(struct pico_ip6));
    memcpy( &mreq_source.mcast_group_addr, &inaddr_mcast, sizeof(struct pico_ip6));
    memcpy(&mreq.mcast_link_addr, &inaddr_link, sizeof(struct pico_ip6));
    memcpy(&mreq_source.mcast_link_addr, &inaddr_link, sizeof(struct pico_ip6));
    memcpy(&mreq_source.mcast_source_addr, &src[0], sizeof(struct pico_ip6));
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_BLOCK_SOURCE, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_BLOCK_SOURCE failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_UNBLOCK_SOURCE, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_UNBLOCK_SOURCE failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    memcpy(&mreq_source.mcast_source_addr, &src[1], sizeof(struct pico_ip6));
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
        printf("%s: socket_setoption PICO_IP_DROP_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
    }

    memcpy(&mreq_source.mcast_source_addr, &src[2], sizeof(struct pico_ip6));
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    memcpy(&mreq_source.mcast_group_addr, &src[3], sizeof(struct pico_ip6));
    if(pico_socket_setoption(udpecho_pas->s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source) < 0) {
        printf("%s: socket_setoption PICO_IP_ADD_SOURCE_MEMBERSHIP: %s\n", __FUNCTION__, strerror(pico_err));
    }

    return;

out:
    fprintf(stderr, "mcastreceive expects the following format: mcastreceive:link_addr:mcast_addr:listen_port[:send_port]\n");
    exit(255);
}
#else
void app_mcastreceive_ipv6(char *arg)
{
    printf("ERROR: PICO_SUPPORT_MCAST disabled\n");
    return;
}
#endif
/*** END Multicast RECEIVE + ECHO ***/
