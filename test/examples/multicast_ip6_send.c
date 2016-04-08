#include "utils.h"
#include <pico_ipv4.h>
#include <pico_ipv6.h>
#include <pico_socket.h>

extern void app_udpclient(char *arg);
/*** START Multicast SEND ***/
/*
 * multicast send expects the following format: mcastsend:link_addr:mcast_addr:sendto_port:listen_port
 * link_addr: mcastsend picoapp IP address
 * mcast_addr: multicast IP address to send to
 * sendto_port: port number to send multicast traffic to
 * listen_port: port number on which the mcastsend can receive data
 *
 * f.e.: ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.255.0: -a mcastsend:10.40.0.2:224.7.7.7:6667:6667
 */
extern struct udpclient_pas *udpclient_pas;
#ifdef PICO_SUPPORT_MCAST
void app_mcastsend_ipv6(char *arg)
{
    int retval = 0;
    char *maddr = NULL, *laddr = NULL, *lport = NULL, *sport = NULL;
    uint16_t sendto_port = 0;
    struct pico_ip6 inaddr_link = {
        0
    }, inaddr_mcast = {
        0
    };
    char *new_arg = NULL, *p = NULL, *nxt = arg;
    struct pico_ip_mreq mreq = ZERO_MREQ_IP6;

    /* start of parameter parsing */
    if (nxt) {
        nxt = cpy_arg(&laddr, nxt);
        if (laddr) {
            pico_string_to_ipv6(laddr, &inaddr_link.addr[0]);
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
            pico_string_to_ipv6(maddr, &inaddr_mcast.addr[0]);
        } else {
            goto out;
        }
    } else {
        /* missing multicast address */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&sport, nxt);
        if (sport && atoi(sport)) {
            sendto_port = short_be(atoi(sport));
        } else {
            /* incorrect send_port */
            goto out;
        }
    } else {
        /* missing send_port */
        goto out;
    }

    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            /* unused at this moment */
            /* listen_port = short_be(atoi(lport)); */
        } else {
            /* incorrect listen_port */
            goto out;
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    picoapp_dbg("\n%s: mcastsend started. Sending packets to %s:%u\n\n", __FUNCTION__, maddr, short_be(sendto_port));

    /* udpclient:dest_addr:sendto_port[:listen_port:datasize:loops:subloops] */
    new_arg = calloc(1, strlen(maddr) + 1 + strlen(sport) + 1 + strlen(lport) + strlen(",64,10,5,") + 1);
    p = strcat(new_arg, maddr);
    p = strcat(p + strlen(maddr), ",");
    p = strcat(p + 1, sport);
    p = strcat(p + strlen(sport), ",");
    p = strcat(p + 1, lport);
    p = strcat(p + strlen(lport), ",64,10,5,");

    /* DAD needs to verify the link address before we can continue */
    while(!pico_ipv6_link_get(&inaddr_link)) {
        pico_stack_tick();
        usleep(2000);
    }
    app_udpclient(new_arg);

    memcpy(&mreq.mcast_group_addr, &inaddr_mcast, sizeof(struct pico_ip6));
    memcpy(&mreq.mcast_link_addr, &inaddr_link, sizeof(struct pico_ip6));
    if(pico_socket_setoption(udpclient_pas->s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        picoapp_dbg("%s: socket_setoption PICO_IP_ADD_MEMBERSHIP failed: %s\n", __FUNCTION__, strerror(pico_err));
        retval = 1;
    }

    if (new_arg)
        free(new_arg);

    if (lport)
        free(lport);

    if (maddr)
        free(maddr);

    if (sport)
        free(sport);

    if (laddr)
        free(laddr);

    if (retval)
        exit(retval);

    return;

out:
    picoapp_dbg("mcastsend expects the following format: mcastsend:link_addr:mcast_addr:sendto_port:listen_port\n");
    exit(255);
}
#else
void app_mcastsend_ipv6(char *arg)
{
    picoapp_dbg("ERROR: PICO_SUPPORT_MCAST disabled\n");
    return;
}
#endif
/*** END Multicast SEND ***/
