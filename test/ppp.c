#include <pico_stack.h>
#include <pico_dev_ppp.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#define MODEM "/dev/ttyUSB0"
#define SPEED 236800
#define DEBUG_FLOW 
static int fd = -1;
static int idx;

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

int main(void)
{
    struct pico_device *dev;
    fd = open(MODEM, O_RDWR);
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

    while(1) {
        pico_stack_tick();
        usleep(1000);
    }
}
