/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include "pico_device.h"
#include "pico_dev_tap.h"
#include "pico_stack.h"

#include <sys/poll.h>

struct pico_device_tap {
    struct pico_device dev;
    int fd;
};

#define TUN_MTU 2048

static int pico_tap_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_tap *tap = (struct pico_device_tap *) dev;
    return write(tap->fd, buf, (uint32_t)len);
}

static int pico_tap_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_tap *tap = (struct pico_device_tap *) dev;
    struct pollfd pfd;
    unsigned char buf[TUN_MTU];
    int len;
    pfd.fd = tap->fd;
    pfd.events = POLLIN;
    do  {
        if (poll(&pfd, 1, 0) <= 0)
            return loop_score;

        len = read(tap->fd, buf, TUN_MTU);
        if (len > 0) {
            loop_score--;
            pico_stack_recv(dev, buf, (uint32_t)len);
        }
    } while(loop_score > 0);
    return 0;
}

/* Public interface: create/destroy. */

void pico_tap_destroy(struct pico_device *dev)
{
    struct pico_device_tap *tap = (struct pico_device_tap *) dev;
    if(tap->fd > 0)
        close(tap->fd);
}


static int tap_open(char *name)
{
    struct ifreq ifr;
    int tap_fd;
    if((tap_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return(-1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if(ioctl(tap_fd, TUNSETIFF, &ifr) < 0) {
        return(-1);
    }

    return tap_fd;
}


static int tap_get_mac(char *name, uint8_t *mac)
{
    int sck;
    struct ifreq eth;
    int retval = -1;

    sck = socket(AF_INET, SOCK_DGRAM, 0);
    if(sck < 0) {
        return retval;
    }

    memset(&eth, 0, sizeof(struct ifreq));
    strcpy(eth.ifr_name, name);


    /* call the IOCTL */
    if (ioctl(sck, SIOCGIFHWADDR, &eth) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        return -1;
        ;
    }

    memcpy (mac, &eth.ifr_hwaddr.sa_data, 6);

    close(sck);
    return 0;

}


struct pico_device *pico_tap_create(char *name)
{
    struct pico_device_tap *tap = PICO_ZALLOC(sizeof(struct pico_device_tap));
    uint8_t mac[6] = {};

    if (!tap)
        return NULL;

    tap->dev.overhead = 0;
    tap->fd = tap_open(name);
    if (tap->fd < 0) {
        dbg("Tap creation failed.\n");
        pico_tap_destroy((struct pico_device *)tap);
        return NULL;
    }

    if (tap_get_mac(name, mac) < 0) {
        dbg("Tap mac query failed.\n");
        pico_tap_destroy((struct pico_device *)tap);
        return NULL;
    }

    mac[5]++;

    if( 0 != pico_device_init((struct pico_device *)tap, name, mac)) {
        dbg("Tap init failed.\n");
        pico_tap_destroy((struct pico_device *)tap);
        return NULL;
    }

    tap->dev.send = pico_tap_send;
    tap->dev.poll = pico_tap_poll;
    tap->dev.destroy = pico_tap_destroy;
    dbg("Device %s created.\n", tap->dev.name);
    return (struct pico_device *)tap;
}

