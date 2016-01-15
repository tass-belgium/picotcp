#include "utils.h"
#include <pico_ipv4.h>
#include <pico_ipv6.h>
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
    char *delay = NULL;
    char *asize = NULL;
    int initial_delay = 0;
    static int id;
    int timeout = 0;
    int size = 64;

    next = cpy_arg(&dest, arg);
    if (!dest) {
        fprintf(stderr, "ping needs the following format: ping:dst_addr:[size:[abort after N sec:[wait N sec before start]]]\n");
        exit(255);
    }
    if (next) {
        next = cpy_arg(&asize, next);
        size = atoi(asize);
        if (size <= 0) {
            size = 64; /* Default */
        }
    }

    if (next) {
        next = cpy_arg(&abort, next);
        if (strlen(abort) > 0) {
            printf("Got arg: '%s'\n", abort);
            timeout = atoi(abort);
            if (timeout < 0) {
                fprintf(stderr, "ping needs the following format: ping:dst_addr:[size:[abort after N sec:[wait N sec before start]]]\n");
                exit(255);
            }
            printf("Aborting ping after %d seconds\n", timeout);
        }
    }

    if (next) {
        next = cpy_arg(&delay, next);
        if (strlen(delay) > 0) {
            initial_delay = atoi(delay);
            if (initial_delay > 0) {
                printf("Initial delay: %d seconds\n", initial_delay);
                initial_delay = PICO_TIME_MS() + initial_delay * 1000;
                while (PICO_TIME_MS() < initial_delay) {
                    pico_stack_tick();
                    usleep(10000);
                }
            }
        }
    }
    printf("Starting ping.\n");

    if (!IPV6_MODE)
        id = pico_icmp4_ping(dest, NUM_PING, 1000, 10000, size, cb_ping);

#ifdef PICO_SUPPORT_IPV6
    else
        id = pico_icmp6_ping(dest, NUM_PING, 1000, 10000, size, cb_ping6, NULL);
#endif
    if (timeout > 0) {
        printf("Adding abort timer after %d seconds for id %d\n", timeout, id);
        pico_timer_add(timeout * 1000, ping_abort_timer, &id);
    } else {
        printf("abort timer is %d seconds for id %d, ignoring\n", timeout, id);

    }

    /* free copied args */
    if (dest)
        free(dest);

    if (abort)
        free(abort);
}
#endif
/*** END PING ***/

