#include "utils.h"
#include "pico_dns_common.h"
#include "pico_mdns.h"
#include "pico_ipv4.h"
#include "pico_addressing.h"

/*** START MDNS ***/

#ifdef PICO_SUPPORT_MDNS

void mdns_init_callback( pico_mdns_rtree *rtree,
                         char *str,
                         void *arg )
{
    printf("\nInitialised with hostname: %s\n\n", str);
}

void app_mdns(char *arg, struct pico_ip4 address)
{
    char *hostname, *peername;
    char *nxt = arg;

    if (!nxt)
        exit(255);

    nxt = cpy_arg(&hostname, nxt);
    if(!hostname) {
        exit(255);
    }

    if(!nxt) {
        printf("Not enough args supplied!\n");
        exit(255);
    }

    nxt = cpy_arg(&peername, nxt);
    if(!peername) {
        exit(255);
    }

    printf("\nStarting mDNS module...\n");
    if (pico_mdns_init(hostname, address, &mdns_init_callback, NULL)) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }

    printf("DONE - Initialising mDNS module.\n");

    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
#endif
/*** END MDNS ***/
