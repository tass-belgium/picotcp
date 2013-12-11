#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include "ptsocket/pico_ptsocket.h"

int sk;

static int sigint;
void callback_exit(int signum)
{
    if (signum == SIGINT) {
        printf("SERVER > RECEIVED SIGINT\n");
        if (sigint++)
            exit(0);

        pico_ptclose(sk);
        sleep(2);
        exit(0);
    }
}

int main(void)
{
    unsigned char macaddr0[6] = {
        0, 0, 0, 0xa, 0xb, 0xc
    };
    struct pico_device *vde0;
    struct pico_ip4 address, netmret;

    uint16_t port = short_be(5555);

    struct sockaddr_in local = {}, remote = {};
    int ret;

    signal(SIGINT, callback_exit);
    pico_stack_init();

    pico_string_to_ipv4("10.40.0.4", &address.addr);
    pico_string_to_ipv4("255.255.255.0", &netmret.addr);

    /* add local interface (device) with a mac address, connected to vde switch */
    vde0 = pico_vde_create("/tmp/pic0.ctl", "vde0", macaddr0);
    if (!vde0)
        return 1;

    /* add network adress 10.40.0.x to route by vde0 */
    pico_ipv4_link_add(vde0, address, netmret);


    /* Initialize POSIX-like interface */
    local.sin_family = AF_INET;
    remote.sin_family = AF_INET;
    pico_string_to_ipv4("10.40.0.1", &remote.sin_addr.s_addr);
    local.sin_addr.s_addr = address.addr; /* INADDR_ANY */
    remote.sin_port = port;



    pico_ptstart();

    sk = pico_ptsocket(PF_INET, SOCK_STREAM, 0);

    if (sk < 0)
        return 5;

    printf("Sk is %d\n", sk);

    while(1) {
        int w;
        char buf[20];
        printf ("Waiting a bit...\n");
        sleep(5);
        printf ("Attempting connection...\n");
        ret = pico_ptconnect(sk, &remote, sizeof(struct sockaddr_in));
        if (ret != 0) {
            perror("connect(): ");
            return 2;
        }

        printf ("Connection established.\n");
        printf("Sk is %d\n", sk);
        memset(buf, 'a', 20);

        do {
            w = pico_ptwrite(sk, buf, 20);
            printf ("Sent %d bytes\n", w);
            sleep(1);
        } while(w > 0);
    }
    return 0;
}


