#include "utils.h"
#include <pico_ipv4.h>
#include <pico_nat.h>

/*** START NATBOX ***/
void app_natbox(char *arg)
{
    char *dest = NULL;
    struct pico_ip4 ipdst, pub_addr, priv_addr;
    struct pico_ipv4_link *link;

    cpy_arg(&dest, arg);
    if (!dest) {
        fprintf(stderr, "natbox needs the following format: natbox:dst_addr\n");
        exit(255);
    }

    pico_string_to_ipv4(dest, &ipdst.addr);
    link = pico_ipv4_link_get(&ipdst);
    if (!link) {
        fprintf(stderr, "natbox: Destination not found.\n");
        exit(255);
    }

    pico_ipv4_nat_enable(link);
    pico_string_to_ipv4("10.50.0.10", &pub_addr.addr);
    pico_string_to_ipv4("10.40.0.08", &priv_addr.addr);
    pico_ipv4_port_forward(pub_addr, short_be(5555), priv_addr, short_be(6667), PICO_PROTO_UDP, PICO_NAT_PORT_FORWARD_ADD);
    fprintf(stderr, "natbox: started.\n");
}
/*** END NATBOX ***/
