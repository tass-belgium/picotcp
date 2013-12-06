#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include "ptsocket/pico_ptsocket.h"


void callback_exit(int signum)
{
    if (signum == SIGUSR1) {
        printf("SERVER > RECEIVED SIGUSR1\n");
    }
}



int main(void)
{
    unsigned char macaddr0[6] = {
        0, 0, 0, 0xa, 0xb, 0xc
    };
    struct pico_device *vde0;
    struct pico_ip4 address, netmask;

    uint16_t port = short_be(5555);

    struct sockaddr_in local = {}, remote = {};
    int sk, ask, size_ask = sizeof(struct sockaddr_in);

    signal(SIGUSR1, callback_exit);
    pico_stack_init();

    pico_string_to_ipv4("10.40.0.3", &address.addr);
    pico_string_to_ipv4("255.255.255.0", &netmask.addr);

    /* add local interface (device) with a mac address, connected to vde switch */
    vde0 = pico_vde_create("/tmp/pic0.ctl", "vde0", macaddr0);
    if (!vde0)
        return 1;

    /* add network adress 10.40.0.x to route by vde0 */
    pico_ipv4_link_add(vde0, address, netmask);


    /* Initialize POSIX-like interface */
    local.sin_family = AF_INET;
    remote.sin_family = AF_INET;
    pico_string_to_ipv4("10.40.0.1", &remote.sin_addr.s_addr);
    local.sin_addr.s_addr = address.addr; /* INADDR_ANY */
    local.sin_port = port;



    pico_ptstart();

    sk = pico_ptsocket(PF_INET, SOCK_STREAM, 0);

    if (sk < 0)
        return 5;

    if (pico_ptbind(sk, &local, sizeof(struct sockaddr_in)) != 0)
        return 4;

    if (pico_ptlisten(sk, 3) != 0)
        return 3;

    while(1) {
        int r, w;
        char buf[20];
        printf ("Awaiting connection...\n");
        ask = pico_ptaccept(sk, &remote, &size_ask);
        if (ask < 0) {
            perror("accept(): ");
            return 2;
        }

        printf ("Connection established.\n");

        do {
            r = pico_ptread(ask, buf, 20);
            if (r > 0) {
                printf ("Received %d bytes\n", r);
                printf ("Sending...\n");
                w = pico_ptwrite(ask, buf, r);
                printf ("Sent %d bytes\n", w);
            }
        } while(r > 0);
    }
    return 0;
}


