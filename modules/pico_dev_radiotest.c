/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_device.h"
#include "pico_dev_tap.h"
#include "pico_stack.h"
#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "sys/poll.h"

struct ieee_radio *pico_radiotest_create(uint8_t addr, uint8_t area0, uint8_t area1);


#define RFDEV_PANID               0xABCD
#define MC_ADDR_BE       0x010101EBU
#define LO_ADDR          0x0100007FU

struct sockaddr_in MCADDR0;
struct sockaddr_in MCADDR1;
int areas = 1;

struct radiotest_radio {
    struct ieee_radio radio;
    uint16_t pan_id;
    uint16_t addr;
    int sock0;
    int sock1;
};

static uint16_t radiotest_get_sh(struct ieee_radio *radio)
{
    struct radiotest_radio *dev = (struct radiotest_radio *)radio;
    if (!dev)
        return (uint16_t)-1;
    return dev->addr;
}

static uint16_t radiotest_get_pan_id(struct ieee_radio *radio)
{
    struct radiotest_radio *dev = (struct radiotest_radio *)radio;
    if (!dev)
        return (uint16_t)-1;
    return dev->pan_id;
}    

static int radiotest_get_ex(struct ieee_radio *radio, uint8_t *buf)
{
    struct radiotest_radio *dev = (struct radiotest_radio *)radio;
    if (!dev)
        return -1;
    buf[0] = 0x00;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0xaa;
    buf[4] = 0xab;
    buf[5] = 0x00;
    buf[6] = (uint8_t)(dev->addr & 0xFF00) >> 8u;
    buf[7] = (uint8_t)(dev->addr & 0xFFu);

    return 0;
}

static int radiotest_set_sh(struct ieee_radio *radio, uint16_t short_id)
{
    struct radiotest_radio *dev = (struct radiotest_radio *)radio;
    if (!dev)
        return -1;
    dev->addr = short_id;
    return 0;
}

/* also poll */
static int radiotest_rx(struct ieee_radio *radio, uint8_t *buf, int len)
{
    struct radiotest_radio *dev = (struct radiotest_radio *)radio;
    int ret_len;
    struct pollfd p[2];
    int pollret;

    uint8_t my_id = radio->get_addr_short(radio);
    if (!dev)
        return -1;

    p[0].fd = dev->sock0;
    p[0].events = POLLIN;
    if (areas > 1) {
        p[1].fd = dev->sock1;
        p[1].events = POLLIN;

    }

    pollret = poll(p, areas, 1);
    if (pollret == 0)
        return 0;

    if (pollret == -1) {
        fprintf(stderr, "Socket error!\n");
        exit(5);
    }

    if (p[0].revents & POLLIN) {
        ret_len = recv(dev->sock0, buf, (size_t)(len), 0);
        if (buf[0] == my_id)
            ret_len = 0;
    } else {
        ret_len = recv(dev->sock1, buf, (size_t)(len), 0);
        if (buf[0] == my_id)
            ret_len = 0;
    }

    if (ret_len < 2) /* not valid */
        return 0;

    buf[0] = (uint8_t)(ret_len);
    return ret_len - 1;
}

static int radiotest_tx(struct ieee_radio *radio, void *_buf, int len)
{
    struct radiotest_radio *radiotest = (struct radiotest_radio *)radio;
    uint8_t *buf = (uint8_t *)_buf;
    int ret = 0;

    buf[0] = (uint8_t) radio->get_addr_short(radiotest);
    ret = sendto(radiotest->sock0, buf, (size_t)(len), 0, (struct sockaddr *)&(MCADDR0), sizeof(struct sockaddr_in));
    if (areas > 1)
        ret = sendto(radiotest->sock1, buf, (size_t)(len), 0, (struct sockaddr *)&(MCADDR1), sizeof(struct sockaddr_in));
    return ret;
}


struct ieee_radio *pico_radiotest_create(uint8_t addr, uint8_t area0, uint8_t area1)
{
    struct radiotest_radio *dev = PICO_ZALLOC(sizeof(struct radiotest_radio));
    uint8_t ext_add[8] = {};
    struct ip_mreqn mreq0, mreq1;
    int yes = 1;
    int no = 0;
    
    mreq0.imr_multiaddr.s_addr =  MC_ADDR_BE + (area0 << 24);
    mreq0.imr_address.s_addr =  INADDR_ANY;
    mreq0.imr_ifindex = 0;

    mreq1.imr_multiaddr.s_addr =  MC_ADDR_BE + (area1 << 24);
    mreq1.imr_address.s_addr =  INADDR_ANY;
    mreq1.imr_ifindex = 0;

    if (!dev)
        return NULL;
    dev->radio.transmit         = radiotest_tx;
    dev->radio.get_addr_short   = radiotest_get_sh;
    dev->radio.get_pan_id       = radiotest_get_pan_id;
    dev->radio.receive          = radiotest_rx;
    dev->radio.get_addr_ext     = radiotest_get_ex;
    dev->radio.set_addr_short   = radiotest_set_sh;

    dev->addr = addr;
    dev->pan_id = RFDEV_PANID;
    radiotest_get_ex(&dev->radio , ext_add);

    dev->sock0 = socket(AF_INET, SOCK_DGRAM, 0);
    if (dev->sock0 < 0)
        return NULL;
    setsockopt(dev->sock0, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    if (area1 > 0) {
        dev->sock1 = socket(AF_INET, SOCK_DGRAM, 0);

        if (dev->sock1 < 0)
            return NULL;
        setsockopt(dev->sock1, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    }

    memset(&MCADDR0, 0, sizeof(struct sockaddr_in));
    MCADDR0.sin_family = AF_INET;
    MCADDR0.sin_port = htons(7777);
    MCADDR0.sin_addr.s_addr = MC_ADDR_BE + (area0 << 24);
    bind(dev->sock0, (struct sockaddr *)&MCADDR0, sizeof(struct sockaddr_in));
    setsockopt(dev->sock0, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq0, sizeof(struct ip_mreqn));
    setsockopt(dev->sock0, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(int));
    
    if (area1 > 0) {
        memset(&MCADDR1, 0, sizeof(struct sockaddr_in));
        MCADDR1.sin_family = AF_INET;
        MCADDR1.sin_port = htons(7777);
        MCADDR1.sin_addr.s_addr = MC_ADDR_BE + (area1 << 24);

        bind(dev->sock1, (struct sockaddr *)&MCADDR1, sizeof(struct sockaddr_in));
        setsockopt(dev->sock1, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq1, sizeof(struct ip_mreqn));
        setsockopt(dev->sock1, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(int));
        areas++;
    }


    return &dev->radio;
}

