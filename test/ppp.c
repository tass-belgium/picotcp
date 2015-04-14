#include <pico_stack.h>
#include <pico_dev_ppp.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <pico_icmp4.h>
#include <pico_socket.h>
#define MODEM "/dev/ttyUSB0"
#define SPEED 236800
#define APN "gprs.base.be"
#define PASSWD "base"
//#define DEBUG_FLOW 
static int fd = -1;
static int idx;
static int ping_on = 0;
static int disconnected = 0;

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

static void disconnect_cb(void *arg)
{
    disconnected = 1;
}

static void timer(pico_time now, void *arg)
{
    struct pico_device *dev = (struct pico_device *)arg;

    pico_ppp_disconnect(dev, disconnect_cb, NULL);
}

int main(int argc, const char *argv[])
{
    struct pico_device *dev;
    const char *path = MODEM;
    const char *apn = APN;
    const char *passwd = PASSWD;

    if (argv[1])
        path = argv[1];
    if (argv[2])
        apn = argv[2];
    if (argv[3])
        passwd = argv[3];

    fd = open(path, O_RDWR);
    if (fd < 0)
        return 1;

    fcntl(fd, F_SETFL, O_NONBLOCK);

    pico_stack_init();

    dev = pico_ppp_create();
    if (!dev)
        return 2; 

    pico_ppp_set_serial_read(dev, modem_read);
    pico_ppp_set_serial_write(dev, modem_write);
    pico_ppp_set_serial_set_speed(dev, modem_set_speed);

    pico_ppp_set_apn(dev, apn);
    pico_ppp_set_password(dev, passwd);

    pico_ppp_connect(dev);

    while(!disconnected) {
        pico_stack_tick();
        usleep(1000);
        if (dev->link_state(dev) && !ping_on) {
            ping_on++;
            ping();
            pico_timer_add(60 * 1000, timer, dev);
        }
    }

    pico_ppp_destroy(dev);

}
