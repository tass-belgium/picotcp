#include "utils.h"
#include <pico_icmp4.h>
#include <pico_icmp6.h>
/*** START PING ***/
#ifdef PICO_SUPPORT_PING
#define NUM_PING 10

void cb_ping(struct pico_icmp4_stats *s)
{
    char host[30];
    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=%lu time=%lu ms\n", s->size, host, s->seq,
            s->ttl, (long unsigned int)s->time);
        if (s->seq >= NUM_PING)
            exit(0);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
        exit(1);
    }
}

#ifdef PICO_SUPPORT_IPV6
void cb_ping6(struct pico_icmp6_stats *s)
{
    char host[50];
    pico_ipv6_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=%lu time=%lu ms\n", s->size, host, s->seq,
            s->ttl, (long unsigned int)s->time);
        if (s->seq >= NUM_PING)
            exit(0);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
        exit(1);
    }
}
#endif

void ping_abort_timer(pico_time now, void *_id)
{
    int *id = (int *) _id;
    printf("Ping: aborting...\n");
    if (!IPV6_MODE)
        pico_icmp4_ping_abort(*id);

#ifdef PICO_SUPPORT_IPV6
    else
        pico_icmp6_ping_abort(*id);
#endif
}

void app_ping(char *arg)
{
    char *dest = NULL;
    char *next = NULL;
    char *abort = NULL;
    static int id;
    int timeout = 0;
    next = cpy_arg(&dest, arg);
    if (!dest) {
        fprintf(stderr, "ping needs the following format: ping:dst_addr:[abort after N sec]\n");
        exit(255);
    }

    if (next) {
        next = cpy_arg(&abort, next);
        if (strlen(abort) > 0) {
            printf("Got arg: '%s'\n", abort);
            timeout = atoi(abort);
            if (timeout <= 0) {
                fprintf(stderr, "ping needs the following format: ping:dst_addr:[abort after N sec]\n");
                exit(255);
            }

            printf("Aborting ping after %d seconds\n", timeout);
        }
    }

    if (!IPV6_MODE)
        id = pico_icmp4_ping(dest, NUM_PING, 1000, 10000, 64, cb_ping);

#ifdef PICO_SUPPORT_IPV6
    else
        id = pico_icmp6_ping(dest, NUM_PING, 1000, 10000, 64, cb_ping6, NULL);
#endif
    if (timeout > 0) {
        printf("Adding abort timer after %d seconds for id %d\n", timeout, id);
        pico_timer_add(timeout * 1000, ping_abort_timer, &id);
    }

    /* free copied args */
    if (dest)
      free(dest);
    if (abort)
      free(abort);
}
#endif
/*** END PING ***/

