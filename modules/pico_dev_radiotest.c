/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/


/* Uncomment next line to enable libPCAP dump */
/* #define RADIO_PCAP */

/* Uncomment next line to enable Random packet loss (specify percentage) */
/* #define P_LOSS 3 */

#include "pico_dev_radiotest.h"
#include "pico_device.h"
#include "pico_dev_tap.h"
#include "pico_stack.h"
#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "sys/poll.h"
#ifdef RADIO_PCAP
#   include <pcap/pcap.h>
static char pcap_dump_name[] = "/tmp/radio_%04x.pcap";
#endif

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
#ifdef RADIO_PCAP
    pcap_t *pcap;
    pcap_dumper_t *pcapd;
#endif
};


#ifdef RADIO_PCAP
void radiotest_pcap_open(struct radiotest_radio *dev, char *dump) 
{
    char dumpfile[100];
    dev->pcap = pcap_open_dead(DLT_IEEE802_15_4, 65535);
    if (!dev->pcap) {
        perror("LibPCAP");
        exit (1);
    }
    snprintf(dumpfile, 100, dump, dev->addr);
    dev->pcapd = pcap_dump_open(dev->pcap, dumpfile);
    if (!dev->pcapd){
        perror("opening pcap dump file");
        exit(1);
    }
}

void radiotest_pcap_write(struct radiotest_radio *dev, uint8_t *buf, int len)
{
    struct pcap_pkthdr ph;
    if (!dev || !dev->pcapd)
        return;
    ph.caplen = len;
    ph.len = len;
    gettimeofday(&ph.ts, NULL);
    pcap_dump((u_char *)dev->pcapd, &ph, buf);
    pcap_dump_flush(dev->pcapd);
}

#else 

void radiotest_pcap_open(struct radiotest_radio *dev, char *dump)
{
    (void)dev;
    (void)dump;
}

void radiotest_pcap_write(struct radiotest_radio *dev, uint8_t *buf, int len)
{
    (void)dev;
    (void)buf;
    (void)len;
}

#endif

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
    radiotest_pcap_write(dev, buf + 1, ret_len - 1);
#ifdef P_LOSS
    long n = lrand48();
    n = n % 100;
    if (n < P_LOSS) {
        printf("Packet got lost!\n");
        return 0;
    }

#endif

    buf[0] = (uint8_t)(ret_len);
    return ret_len - 1;
}

/**
 *  Simulated CRC16-CITT Kermit generation
 *
 *  @param buf uint8_t *, buffer to generate FCS for.
 *  @param len uint8_t, len of the buffer
 *
 *  @return CITT Kermit CRC16 of the buffer
 */
static uint16_t calculate_crc16(uint8_t *buf, uint8_t len)
{
    uint16_t crc = 0x0000;
    uint16_t q = 0, i = 0;
    uint8_t c = 0;
    
    for (i = 0; i < len; i++) {
        c = buf[i];
        q = (crc ^ c) & 0x0F;
        crc = (crc >> 4) ^ (q * 0x1081);
        q = (crc ^ (c >> 4)) & 0xF;
        crc = (crc >> 4) ^ (q * 0x1081);
    }
    
    return crc;
}

static int radiotest_tx(struct ieee_radio *radio, void *_buf, int len)
{
    struct radiotest_radio *radiotest = (struct radiotest_radio *)radio;
    uint8_t *buf = (uint8_t *)_buf;
    uint16_t crc = 0;
    int ret = 0;

    buf[0] = (uint8_t) radio->get_addr_short(radiotest);
    
    /* Genereate FCS, to make pcap happy... */
    crc = calculate_crc16(buf + 1, len - 3);
    memcpy(buf + len - 2, (void *)&crc, 2);

    ret = sendto(radiotest->sock0, buf, (size_t)(len), 0, (struct sockaddr *)&(MCADDR0), sizeof(struct sockaddr_in));
    if (areas > 1)
        ret = sendto(radiotest->sock1, buf, (size_t)(len), 0, (struct sockaddr *)&(MCADDR1), sizeof(struct sockaddr_in));

    radiotest_pcap_write(radio, buf + 1, len - 1);
    return ret;
}

struct ieee_radio *pico_radiotest_create(uint8_t addr, uint8_t area0, uint8_t area1, char *dump)
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
    
    if (dump) {
       radiotest_pcap_open(dev, dump);
    }

    return (struct ieee_radio *)dev;
}

