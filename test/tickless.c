#include "pico_defines.h"
#include "pico_stack.h"
#include "pico_jobs.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dev_tap.h"
#include "pico_socket.h"

#define DURATION 30


struct iperf_hdr {
    int32_t flags;          /* 0 */
    int32_t numThreads;     /* 1 */
    int32_t mPort;          /* 5001  */
    int32_t bufferlen;      /* 0 */ 
    int32_t mWinBand;       /* 0 */
    int32_t mAmount;        /* 0xfffffc18 */
};

#define IPERF_PORT 5001
#define MTU 1444
static pico_time deadline;

static void panic(void)
{
    for(;;);
}

static char buf[MTU] = {};

static void buf_paint(void)
{
    char paint[11] = "0123456789";
    int i;
    for (i = 0; i < MTU; i++) {
        buf[i] = paint[i % 10];
    }
}

static void send_hdr(struct pico_socket *s)
{
    struct iperf_hdr hdr = {} ;
    hdr.numThreads = long_be(1);
    hdr.mPort = long_be(5001);
    hdr.mAmount = long_be(0xfffffc18);
    pico_socket_write(s, &hdr, sizeof(hdr));
    deadline = PICO_TIME_MS() + DURATION * 1000;
}

static void iperf_cb(uint16_t ev, struct pico_socket *s)
{
    int r;
    if (ev & PICO_SOCK_EV_CONN) {
        printf("Connected!\n");
        send_hdr(s);
        return;
    }

    if (ev & PICO_SOCK_EV_WR) {
        if (PICO_TIME_MS() > deadline) {
            pico_socket_close(s);
            return;
        }
        pico_socket_write(s, buf, MTU);
    }
}


static void socket_setup(void)
{
	int yes = 1;
    uint16_t send_port = 0;
    struct pico_socket *s = NULL;
    union pico_address dst = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    pico_string_to_ipv4("192.168.2.1", &dst.ip4.addr);
    send_port = short_be(5001);
    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &iperf_cb);
    pico_socket_connect(s, &dst.ip4, send_port);
    return;
}

int main(void)
{
    long long interval = 0;
    char ipaddr[]="192.168.2.150";
    struct pico_ip4 my_eth_addr, netmask;
    struct pico_device *tap;

    uint8_t mac[6] = {0x00,0x00,0x00,0x12,0x34,0x56};
    struct pico_socket *s;

    pico_stack_init();

    tap = (struct pico_device *) pico_tap_create("tap0");
    if (!tap)
        while (1);

    pico_string_to_ipv4(ipaddr, &my_eth_addr.addr);
    pico_string_to_ipv4("255.255.255.0", &netmask.addr);
    pico_ipv4_link_add(tap, my_eth_addr, netmask);
#ifdef PICO_SUPPORT_IPV6
    {
    struct pico_ip6 my_addr6, netmask6;
    pico_string_to_ipv6("3ffe:501:ffff:100:260:37ff:fe12:3456", my_addr6.addr);
    pico_string_to_ipv6("ffff:ffff:ffff:ffff::0", netmask6.addr);
    pico_ipv6_link_add(tap, my_addr6, netmask6);
    }
#endif

    socket_setup();

    while(1) {
        interval = pico_stack_go();
        if (interval != 0) {
//            printf("Interval: %lld\n", interval);
            pico_tap_WFI(tap, interval);
        }
    }
}
