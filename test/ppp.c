#include <pico_stack.h>
#include <pico_dev_ppp.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <pico_icmp4.h>
#include <pico_ipv4.h>
#include <pico_md5.h>
#include <pico_socket.h>
#ifdef PICO_SUPPORT_POLARSSL
#include <polarssl/md5.h>
#endif
#ifdef PICO_SUPPORT_CYASSL
#include <cyassl/ctaocrypt/md5.h>
#endif
#define MODEM "/dev/ttyUSB0"
#define SPEED 236800
/* #define APN "gprs.base.be" */
#define APN "web.be"
#define PASSWD "web"
#define USERNAME "altran"
/* #define DEBUG_FLOW */
static int fd = -1;
static int idx;
static int ping_on = 0;
static struct pico_device *ppp = NULL;

static void sigusr1_hdl(int signo)
{
    fprintf(stderr, "SIGUSR1: Connecting!\n");
    if (ppp)
        pico_ppp_connect(ppp);
}

static void sigusr2_hdl(int signo)
{
    fprintf(stderr, "SIGUSR2/SIGINT: Disconnecting!\n");
    if (ppp)
        pico_ppp_disconnect(ppp);

    if (signo == SIGINT)
        exit(0);
}

#ifdef PICO_SUPPORT_POLARSSL
static void md5sum(uint8_t *dst, const uint8_t *src, size_t len)
{
    md5(src, len, dst);
}
#endif

#ifdef PICO_SUPPORT_CYASSL
static void md5sum(uint8_t *dst, const uint8_t *src, size_t len)
{
    Md5 md5;
    InitMd5(&md5);
    Md5Update(&md5, src, len);
    Md5Final(&md5, dst);
}
#endif

int modem_read(struct pico_device *dev, void *data, int len)
{
    int r;
    r = read(fd, data, len);
#ifdef DEBUG_FLOW
    if (r > 0) {
        printf(" <<< ");
        for(idx = 0; idx < r; idx++) {
            printf(" %02x", ((uint8_t*)data)[idx]);
        }
        printf("\n");
    }

#endif

    return r;
}

int modem_write(struct pico_device *dev, const void *data, int len)
{
    int r;
#ifdef DEBUG_FLOW
    printf(" >>> ");
    for(idx = 0; idx < len; idx++) {
        printf(" %02x", ((uint8_t*)data)[idx]);
    }
    printf("\n");
#endif
    r = write(fd, data, len);
    return r;
}

int modem_set_speed(struct pico_device *dev, uint32_t speed)
{
    struct termios term;
    if (tcgetattr(fd, &term) != 0)
        return 6;

    if (cfsetspeed(&term, B115200) != 0)
        return 7;

    if (tcsetattr(fd, TCSANOW, &term) != 0)
        return 8;

    printf("Speed set to 115200.\n");
    return 0;
}

void cb_ping(struct pico_icmp4_stats *s)
{
    char host[30];
    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
    }
}

static void cb_sock(uint16_t ev, struct pico_socket *s)
{

}

static void ping(void)
{
    struct pico_socket *s;
    struct pico_ip4 dst;

    pico_string_to_ipv4("80.68.95.85", &dst.addr);
    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, cb_sock);
    pico_socket_connect(s, &dst, short_be(80));
    pico_icmp4_ping("80.68.95.85", 10, 1000, 4000, 8, cb_ping);
}


int main(int argc, const char *argv[])
{
    const char *path = MODEM;
    const char *apn = APN;
    const char *passwd = PASSWD;
    const char *username = USERNAME;

    if (argc > 1)
        path = argv[1];

    if (argc > 2)
        apn = argv[2];

    if (argc > 3)
        passwd = argv[3];

    fd = open(path, O_RDWR);
    if (fd < 0)
        return 1;

    fcntl(fd, F_SETFL, O_NONBLOCK);

    signal(SIGUSR1, sigusr1_hdl);
    signal(SIGUSR2, sigusr2_hdl);
    signal(SIGINT, sigusr2_hdl);

    pico_stack_init();

#if defined PICO_SUPPORT_POLARSSL || defined PICO_SUPPORT_CYASSL
    pico_register_md5sum(md5sum);
#endif

    ppp = pico_ppp_create();
    if (!ppp)
        return 2;

    pico_ppp_set_serial_read(ppp, modem_read);
    pico_ppp_set_serial_write(ppp, modem_write);
    pico_ppp_set_serial_set_speed(ppp, modem_set_speed);

    pico_ppp_set_apn(ppp, apn);
    pico_ppp_set_password(ppp, passwd);
    pico_ppp_set_username(ppp, username);

    pico_ppp_connect(ppp);

    while(1 < 2) {
        pico_stack_tick();
        usleep(1000);
        if (ppp->link_state(ppp) && !ping_on) {
            ping_on++;
            ping();
        }
    }
}
