#include "utils.h"
#include <pico_dns_sd.h>
#include <pico_ipv4.h>
#include <pico_addressing.h>
#include <pico_device.h>
#include <pico_ipv4.h>

/*** START DNS_SD ***/
#ifdef PICO_SUPPORT_DNS_SD

#define TTL 30
#define SECONDS 10

static int fully_initialized = 0;
static char *service_name = NULL;

void dns_sd_claimed_callback( pico_mdns_rtree *tree,
                              char *str,
                              void *arg )
{
    printf("DONE - Registering DNS-SD Service\n");

    IGNORE_PARAMETER(tree);
    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);
}

void dns_sd_init_callback( pico_mdns_rtree *tree,
                           char *str,
                           void *arg )
{
    PICO_DNS_SD_KV_VECTOR_DECLARE(key_value_pair_vector);

    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);
    IGNORE_PARAMETER(tree);

    pico_dns_sd_kv_vector_add(&key_value_pair_vector, "key", "value");

    printf("DONE - Initialising DNS Service Discovery module.\n");

    if (pico_dns_sd_register_service(service_name,
                                     "_http._tcp", 80,
                                     &key_value_pair_vector,
                                     TTL, dns_sd_claimed_callback, NULL) < 0) {
        printf("Registering service failed!\n");
    }

    fully_initialized = 1;
}

void app_dns_sd(char *arg, struct pico_ip4 address)
{
    char *hostname;
    char *nxt = arg;
    uint64_t starttime = 0;
    int once = 0;

    if (!nxt) {
        exit(255);
    }

    nxt = cpy_arg(&hostname, nxt);
    if(!hostname) {
        exit(255);
    }

    if(!nxt) {
        printf("Not enough args supplied!\n");
        exit(255);
    }

    nxt = cpy_arg(&service_name, nxt);
    if(!service_name) {
        exit(255);
    }

    printf("\nStarting DNS Service Discovery module...\n");
    if (pico_dns_sd_init(hostname, address, &dns_sd_init_callback, NULL) != 0) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }

    printf("\nTry reinitialising DNS-SD\n");
    if (pico_dns_sd_init(hostname, address, &dns_sd_init_callback, NULL)) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }

    printf("DONE - Re-initialising DNS-SD module.\n");

    starttime = PICO_TIME_MS();
    printf("Starting time: %d\n", starttime);

    while(1) {
        pico_stack_tick();
        usleep(2000);

        if (((PICO_TIME_MS() - starttime) > SECONDS * 1000) && fully_initialized && !once) {
            printf("\nTry reinitialising DNS-SD (a second time)\n");
            if (pico_dns_sd_init(hostname, address, &dns_sd_init_callback, NULL)) {
                printf("Initialisation returned with Error!\n");
                exit(255);
            }
            once = 1;
            printf("DONE - Re-initialising mDNS module. (a second time)\n");
        }
    }
}

#endif
/*** END DNS_SD ***/
