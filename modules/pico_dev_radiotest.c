/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/

/*******************************************************************************
 * PicoTCP
 ******************************************************************************/

#include "pico_dev_radiotest.h"
#include "pico_addressing.h"
#include "pico_dev_tap.h"
#include "pico_802154.h"
#include "pico_device.h"
#include "pico_config.h"
#include "pico_stack.h"

/* Uncomment next line to enable pcap-dump, also make sure the binary is linked
 * against the lpcaplib: '-lpcap' */
#define RADIO_PCAP

/*******************************************************************************
 * System sockets
 ******************************************************************************/

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>

#ifdef RADIO_PCAP
#include <pcap.h>
#endif

/*******************************************************************************
 * Constants
 ******************************************************************************/

/* Uncomment next line to enable Random packet loss (specify percentage) */
//#define PACKET_LOSS   3

#define RFDEV_PANID      0xABCD
#define MC_ADDR_BE       0x010101EBU
#define LO_ADDR          0x0100007FU

#define LOOP_MTU 127

/*******************************************************************************
 * Type definitions
 ******************************************************************************/

struct radiotest_radio {
    struct pico_device dev;
    struct pico_802154_info addr;
    int sock0;
    int sock1;
#ifdef RADIO_PCAP
    pcap_t *pcap;
    pcap_dumper_t *pcapd;
#endif
};

struct radiotest_frame
{
    uint8_t *buf;
    int len;
    uint32_t id;
};

/*******************************************************************************
 * Global variables
 ******************************************************************************/

static struct sockaddr_in MCADDR0;
static struct sockaddr_in MCADDR1;
static int areas = 1;

static uint32_t tx_id = 0;
static uint32_t rx_id = 0;

/*******************************************************************************
 * pcap
 ******************************************************************************/

#ifdef RADIO_PCAP

static void radiotest_pcap_open(struct radiotest_radio *dev, char *dump)
{
    char path[100];

    /* Open offline packet capture */
    dev->pcap = pcap_open_dead(DLT_IEEE802_15_4, 65535);
    if (!dev->pcap) {
        perror("LibPCAP");
        exit (1);
    }

    /* Construct file path */
    snprintf(path, 100, dump, dev->addr);

    /* Open dump */
    dev->pcapd = pcap_dump_open(dev->pcap, path);
    if (dev->pcapd)
        dbg("PCAP Enabled\n");
    else
        dbg("PCAP Disabled\n");
}

static void radiotest_pcap_write(struct radiotest_radio *dev, uint8_t *buf, int len)
{
    struct pcap_pkthdr ph;
    if (!dev || !dev->pcapd)
        return;
    ph.caplen = (uint32_t)len;
    ph.len = (uint32_t)len;
    gettimeofday(&ph.ts, NULL);
    pcap_dump((u_char *)dev->pcapd, &ph, buf);
    pcap_dump_flush(dev->pcapd);
}

#else

static void radiotest_pcap_open(struct radiotest_radio *dev, char *dump)
{
    (void)dev;
    (void)dump;
}

static void radiotest_pcap_write(struct radiotest_radio *dev, uint8_t *buf, int len)
{
    (void)dev;
    (void)buf;
    (void)len;
}

#endif

static int radiotest_cmp(void *a, void *b)
{
    struct radiotest_frame *fa = (struct radiotest_frame *)a;
    struct radiotest_frame *fb = (struct radiotest_frame *)b;
    return (int)(fa->id - fb->id);
}

PICO_TREE_DECLARE(LoopFrames, radiotest_cmp);

static uint8_t *radiotest_nxt_rx(int *len)
{
    struct radiotest_frame test, *found = NULL;
    uint8_t *ret = NULL;
    test.id = rx_id++;

    found = pico_tree_findKey(&LoopFrames, &test);
    if (found) {
        ret = found->buf;
        *len = found->len;
        pico_tree_delete(&LoopFrames, found);
        PICO_FREE(found);
    } else {
        rx_id--;
    }
    return ret;
}

static void radiotest_nxt_tx(uint8_t *buf, int len)
{
    struct radiotest_frame *new = PICO_ZALLOC(sizeof(struct radiotest_frame));
    if (new) {
        new->buf = PICO_ZALLOC((uint16_t)len);
        if (new->buf) {
            memcpy(new->buf, buf, (size_t)len);
            new->len = len;
            new->id = tx_id++;
            if (pico_tree_insert(&LoopFrames, new)) {
                PICO_FREE(new);
                tx_id--;
            }
        } else {
            PICO_FREE(new);
        }
    }
}

static int pico_loop_send(struct pico_device *dev, void *buf, int len)
{
    IGNORE_PARAMETER(dev);
    if (len > LOOP_MTU)
        return 0;

    printf("Looping back frame of %d bytes.\n", len);
    radiotest_nxt_tx(buf, len);
    return len;
}

static int pico_loop_poll(struct pico_device *dev, int loop_score)
{
    uint8_t *buf = NULL;
    int len = 0;

    if (loop_score <= 0)
        return 0;

    buf = radiotest_nxt_rx(&len);
    if (buf) {
        printf("Receiving frame of %d bytes.\n", len);
        pico_stack_recv(dev, buf, (uint32_t)len);
        PICO_FREE(buf);
        loop_score--;
    }

    return loop_score;
}


/* Generates a simple extended address */
static void radiotest_gen_ex(struct pico_802154_short addr_short, uint8_t *buf)
{
    uint16_t sh = addr_short.addr;
    buf[0] = 0x00;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0xaa;
    buf[4] = 0xab;
    buf[5] = 0x00;
    buf[6] = (uint8_t)(sh & 0xFF00) >> 8u;
    buf[7] = (uint8_t)(sh & 0xFFu);
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
        crc = (uint16_t)((uint16_t)(crc >> 4) ^ (q * 0x1081));
        q = (crc ^ (c >> 4)) & 0xF;
        crc = (uint16_t)((uint16_t)(crc >> 4) ^ (q * 0x1081));
    }

    return crc;
}

/* Send-function for the pico_device-structure */
static int radiotest_send(struct pico_device *dev, void *_buf, int len)
{
    struct radiotest_radio *radio = (struct radiotest_radio *)dev;
    uint8_t *buf = PICO_ZALLOC((size_t)(len + 3));
    uint16_t crc = 0;
    int ret = 0;

    if (!buf)
        return -1;

    printf("Transmitting frame of %d bytes.\n", len);

    /* Store the address in buffer for management */
    memcpy(buf, _buf, (size_t)len);
    len += 3;
    buf[len - 1] = (uint8_t)radio->addr.addr_short.addr;

    /* Generate FCS, keep pcap happy ... */
    crc = calculate_crc16(_buf, (uint8_t)(len - 3));
    memcpy(buf + len - 3, (void *)&crc, 2);

    /* Send frame out on multicast socket */
    ret = (int)sendto(radio->sock0, buf, (size_t)(len), 0, (struct sockaddr *)&(MCADDR0), sizeof(struct sockaddr_in));
    if (areas > 1)
        ret = (int)sendto(radio->sock1, buf, (size_t)(len), 0, (struct sockaddr *)&(MCADDR1), sizeof(struct sockaddr_in));
    PICO_FREE(buf);

    return ret;
}

/* Poll-function for the pico_device-structure */
static int radiotest_poll(struct pico_device *dev, int loop_score)
{
    struct radiotest_radio *radio = (struct radiotest_radio *)dev;
    int pollret, ret_len;
    struct pollfd p[2];
    uint8_t my_id = 0;
    uint8_t buf[128];

    if (loop_score <= 0)
        return 0;

    if (!dev)
        return loop_score;

    /* Get the radiotest-address */
    my_id = (uint8_t)radio->addr.addr_short.addr;

    p[0].fd = radio->sock0;
    p[0].events = POLLIN;
    if (areas > 1) {
        p[1].fd = radio->sock1;
        p[1].events = POLLIN;
    }

    /* Poll for data on any of the area-sockets */
    pollret = poll(p, (nfds_t)areas, 1);
    if (pollret == 0)
        return loop_score;

    if (pollret == -1) {
        fprintf(stderr, "Socket error!\n");
        exit(5);
    }

    if (p[0].revents & POLLIN) {
        ret_len = (int)recv(radio->sock0, buf, (size_t)(128), 0);
        if (buf[0] == my_id)
            ret_len = 0;
    } else {
        ret_len = (int)recv(radio->sock1, buf, (size_t)(128), 0);
        if (buf[0] == my_id)
            ret_len = 0;
    }

    if (ret_len < 2) /* Not valid */
        return loop_score;

#ifdef P_LOSS
    long n = lrand48();
    n = n % 100;
    if (n < P_LOSS) {
        printf("Packet got lost!\n");
        return loop_score;
    }
#endif

    /* Write the received frame to the pcap-dump */
    radiotest_pcap_write(radio, buf, ret_len - 1);

    /* Hand the frame over to pico  */
    pico_stack_recv(dev, buf, (uint32_t)(ret_len - 3));
    loop_score--;

    return loop_score;
}

/* Creates a radiotest-device */
struct pico_device *pico_radiotest_create(uint8_t addr, uint8_t area0, uint8_t area1, int loop, char *dump)
{
    struct radiotest_radio *dev = PICO_ZALLOC(sizeof(struct radiotest_radio));
    struct ip_mreqn mreq0, mreq1;
    int yes = 1;
    int no = 0;

    mreq0.imr_multiaddr.s_addr =  MC_ADDR_BE + (unsigned int)(area0 << 24);
    mreq0.imr_address.s_addr =  INADDR_ANY;
    mreq0.imr_ifindex = 0;

    mreq1.imr_multiaddr.s_addr =  MC_ADDR_BE + (unsigned int)(area1 << 24);
    mreq1.imr_address.s_addr =  INADDR_ANY;
    mreq1.imr_ifindex = 0;

    if (!dev)
        return NULL;

    dev->dev.mode = LL_MODE_IEEE802154;
    dev->dev.mtu = (uint32_t)MTU_802154_MAC;
    if (loop) {
        dev->dev.send = pico_loop_send;
        dev->dev.poll = pico_loop_poll;
    } else {
        dev->dev.send = radiotest_send;
        dev->dev.poll = radiotest_poll;
    }
    dev->addr.pan_id.addr = RFDEV_PANID;
    dev->addr.addr_short.addr = short_be((uint16_t)addr);
    radiotest_gen_ex(dev->addr.addr_short, dev->addr.addr_ext.addr);

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
    MCADDR0.sin_addr.s_addr = MC_ADDR_BE + (unsigned int)(area0 << 24);
    bind(dev->sock0, (struct sockaddr *)&MCADDR0, sizeof(struct sockaddr_in));
    setsockopt(dev->sock0, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq0, sizeof(struct ip_mreqn));
    setsockopt(dev->sock0, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(int));

    if (area1 > 0) {
        memset(&MCADDR1, 0, sizeof(struct sockaddr_in));
        MCADDR1.sin_family = AF_INET;
        MCADDR1.sin_port = htons(7777);
        MCADDR1.sin_addr.s_addr = MC_ADDR_BE + (unsigned int)(area1 << 24);

        bind(dev->sock1, (struct sockaddr *)&MCADDR1, sizeof(struct sockaddr_in));
        setsockopt(dev->sock1, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq1, sizeof(struct ip_mreqn));
        setsockopt(dev->sock1, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(int));
        areas++;
    }

    if (dump) {
       radiotest_pcap_open(dev, dump);
    }

    if (pico_device_init((struct pico_device *)dev, "radio", (uint8_t *)&dev->addr)) {
        dbg("pico_device_init failed.\n");
        pico_device_destroy((struct pico_device *)dev);
        return NULL;
    }

    return (struct pico_device *)dev;
}

