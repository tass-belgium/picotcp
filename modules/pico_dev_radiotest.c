/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera, Jelle De Vleeschouwer
 *********************************************************************/

/*******************************************************************************
 * PicoTCP
 ******************************************************************************/

#include "pico_dev_radiotest.h"
#include "pico_6lowpan_ll.h"
#include "pico_addressing.h"
#include "pico_dev_tap.h"
#include "pico_802154.h"
#include "pico_device.h"
#include "pico_config.h"
#include "pico_stack.h"

/*******************************************************************************
 * System sockets
 ******************************************************************************/

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <signal.h>
#include <errno.h>

#define LISTENING_PORT  7777
#define MESSAGE_MTU     150

#ifdef RADIO_PCAP
#include <pcap.h>
#endif

#ifdef DEBUG_RADIOTEST
#define RADIO_DBG       dbg
#else
#define RADIO_DBG(...)  do { } while (0)
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
    struct pico_dev_6lowpan dev;
    struct pico_6lowpan_info addr;
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
    union pico_ll_addr src;
    union pico_ll_addr dst;
};

/*******************************************************************************
 * Global variables
 ******************************************************************************/

static int connection = 0;

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
#ifdef PICO_SUPPORT_802154
    dev->pcap = pcap_open_dead(DLT_IEEE802_15_4, 65535);
#elif defined (PICO_SUPPORT_802154_NO_MAC)
    dev->pcap = pcap_open_dead(DLT_RAW, 65535);
#endif
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

static uint8_t *radiotest_nxt_rx(int *len, union pico_ll_addr *src, union pico_ll_addr *dst)
{
    struct radiotest_frame test, *found = NULL;
    uint8_t *ret = NULL;
    test.id = rx_id++;

    found = pico_tree_findKey(&LoopFrames, &test);
    if (found) {
        ret = found->buf;
        *len = found->len;
        *src = found->src;
        *dst = found->dst;
        pico_tree_delete(&LoopFrames, found);
        PICO_FREE(found);
    } else {
        rx_id--;
    }
    return ret;
}

static void radiotest_nxt_tx(uint8_t *buf, int len, union pico_ll_addr src, union pico_ll_addr dst)
{
    struct radiotest_frame *new = PICO_ZALLOC(sizeof(struct radiotest_frame));
    if (new) {
        new->buf = PICO_ZALLOC((uint16_t)len);
        if (new->buf) {
            memcpy(new->buf, buf, (size_t)len);
            new->len = len;
            new->id = tx_id++;
            new->src = src;
            new->dst = dst;
            if (pico_tree_insert(&LoopFrames, new)) {
                PICO_FREE(new);
                tx_id--;
            }
        } else {
            PICO_FREE(new);
        }
    }
}

static int pico_loop_send(struct pico_device *dev, void *buf, int len, union pico_ll_addr src, union pico_ll_addr dst)
{
    IGNORE_PARAMETER(dev);
    if (len > LOOP_MTU)
        return 0;
    RADIO_DBG("Looping back frame of %d bytes.\n", len);
    radiotest_nxt_tx(buf, len, src, dst);
    return len;
}

static int pico_loop_poll(struct pico_device *dev, int loop_score)
{
    union pico_ll_addr src, dst;
    uint8_t *buf = NULL;
    int len = 0;

    if (loop_score <= 0)
        return 0;

    buf = radiotest_nxt_rx(&len, &src, &dst);
    if (buf) {
        RADIO_DBG("Receiving frame of %d bytes.\n", len);
        pico_6lowpan_stack_recv(dev, buf, (uint32_t)len, &src, &dst);
        PICO_FREE(buf);
        loop_score--;
    }

    return loop_score;
}


/* Generates a simple extended address */
static void radiotest_gen_ex(struct pico_6lowpan_short addr_short, uint8_t *buf)
{
    uint16_t sh = addr_short.addr;
    buf[0] = 0x00;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0xaa;
    buf[4] = 0xab;
    buf[5] = 0x00;
    buf[6] = (uint8_t)((uint8_t)(short_be(sh) & 0xFF00) >> 8u);
    buf[7] = (uint8_t)(short_be(sh) & 0xFFu);
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

/* Poll-function for the pico_device-structure */
static int radiotest_poll(struct pico_device *dev, int loop_score)
{
    struct radiotest_radio *radio = (struct radiotest_radio *)dev;
    union pico_ll_addr src = {0}, dst = {0};
    int pollret, ret_len;
    struct pollfd p;
    uint8_t buf[128];
    uint8_t phy = 0;

    if (loop_score <= 0)
        return 0;

    if (!dev)
        return loop_score;

    p.fd = connection;
    p.events = POLLIN | POLLHUP;

    /* Poll for data from radio management */
    errno = 0;
    pollret = poll(&p, (nfds_t)1, 1);
    if (errno == EINTR || pollret == 0)
        return loop_score;

    if (pollret < 0) {
        fprintf(stderr, "Socket error %s!\n", strerror(errno));
        exit(5);
    }

    if (p.revents & POLLIN) {
        ret_len = (int)recv(connection, &phy, (size_t)1, 0);
        if (ret_len != 1) return loop_score;
        ret_len = (int)recv(connection, buf, (size_t)phy, 0);
        if (ret_len != (int)phy)
            return loop_score;
        else if (!ret_len) {
            RADIO_DBG("Radio manager detached from network\n");
            exit(1);
        }
    }

    if (ret_len < 2) { /* Not valid */
        return loop_score;
    }

#ifdef P_LOSS
    long n = lrand48();
    n = n % 100;
    if (n < P_LOSS) {
        RADIO_DBG("Packet got lost!\n");
        return loop_score;
    }
#endif

    /* ADDRESS FILTER */
    if (buf[ret_len - 1] != 0xFF && buf[ret_len - 1] != (uint8_t)short_be(radio->addr.addr_short.addr)) {
        RADIO_DBG("Packet is not for me!\n");
        return loop_score;
    }

    /* Get src and destination address */
    dst.pan.addr._ext = radio->addr.addr_ext;
    src.pan.addr.data[3] = 0xAA;
    src.pan.addr.data[4] = 0xAB;
    src.pan.addr.data[7] = buf[ret_len - 1];
    src.pan.mode = AM_6LOWPAN_EXT;
    ret_len -= 2;

    /* Write the received frame to the pcap-dump */
    radiotest_pcap_write(radio, buf, ret_len);

    /* Hand the frame over to pico */
    pico_6lowpan_stack_recv(dev, buf, (uint32_t)(ret_len - 2), &src, &dst);
    loop_score--;

    return loop_score;
}

#define RADIO_OVERHEAD 4

/* Send-function for the pico_device-structure */
static int radiotest_send(struct pico_device *dev, void *_buf, int len, union pico_ll_addr src, union pico_ll_addr dst)
{
    struct radiotest_radio *radio = (struct radiotest_radio *)dev;
    uint8_t *buf = PICO_ZALLOC((size_t)(len + RADIO_OVERHEAD));
    uint8_t phy = 0, did = 0;
    uint16_t crc = 0;
    int ret = 0, dlen = 0;
    IGNORE_PARAMETER(src);

    if (!buf)
        return -1;

    /* Try to get node-ID from address */
    if (dev && pico_6lowpan_lls[dev->mode].addr_len) {
        dlen = pico_6lowpan_lls[dev->mode].addr_len(&dst);
        if (dlen < 0)
            return -1;
        did = dst.pan.addr.data[dlen - 1];
    }

    /* Store the addresses in buffer for management */
    memcpy(buf, _buf, (size_t)len);
    len = (uint16_t)(len + (uint16_t)RADIO_OVERHEAD); // CRC + ID
    buf[len - 2] = (uint8_t)short_be(radio->addr.addr_short.addr);
    buf[len - 1] = did;

    /* Generate FCS, keep pcap happy ... */
    crc = calculate_crc16(_buf, (uint8_t)(len - RADIO_OVERHEAD));
    memcpy(buf + len - RADIO_OVERHEAD, (void *)&crc, 2);

    /* Send frame to radio management */
    phy = (uint8_t)(len);
    ret = (int)sendto(connection, &phy, 1, 0, NULL, 0);
    if (ret != 1)
        return -1;
    ret = (int)sendto(connection, buf, (size_t)(len), 0, NULL, 0);
    RADIO_DBG("Radio '%u' transmitted a frame of %d bytes.\n", buf[len - 2], ret);

    /* Write the sent frame to the pcap-dump */
    radiotest_pcap_write(radio, buf, len - 2);

    PICO_FREE(buf);
    return ret;
}

static int radiotest_hello(int s, uint8_t id, uint8_t area0, uint8_t area1)
{
    uint8_t buf[3] = { id, area0, area1 };
    if (sendto(s, buf, (size_t)3, 0, NULL, 0) != 3) {
        RADIO_DBG("Radio '%u' failed to send hello message\n", id);
        return -1;
    }

    RADIO_DBG("Radio '%u' attached to network\n", id);
    return s;
}

static int radiotest_connect(uint8_t id, uint8_t area0, uint8_t area1)
{
    struct sockaddr_in addr;
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int ret = 0;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTENING_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    ret = connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (ret) {
        RADIO_DBG("Radio '%u' could not attach to network\n", id);
        return ret;
    }

    return radiotest_hello(s, id, area0, area1);
}

static void
pico_radiotest_quit(int signum)
{
    IGNORE_PARAMETER(signum);
    dbg("Quitting radiotest\n");
    exit(0);
}

/* Creates a radiotest-device */
struct pico_device *pico_radiotest_create(uint8_t addr, uint8_t area0, uint8_t area1, int loop, char *dump)
{
    struct radiotest_radio *radio = PICO_ZALLOC(sizeof(struct radiotest_radio));
    struct pico_dev_6lowpan *lp = (struct pico_dev_6lowpan *)radio;
    if (!radio)
        return NULL;
    if (!addr || (addr && !area0)) {
        RADIO_DBG("Usage (node): -6 [1-255],[1-255],[0-255] ...\n");
    }

    signal(SIGQUIT, pico_radiotest_quit);

    radio->addr.pan_id.addr = short_be(RFDEV_PANID);
    radio->addr.addr_short.addr = short_be((uint16_t)addr);
    radiotest_gen_ex(radio->addr.addr_short, radio->addr.addr_ext.addr);
    RADIO_DBG("Radiotest short address: 0x%04X\n", short_be(radio->addr.addr_short.addr));
    RADIO_DBG("Radiotest ext address: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
           radio->addr.addr_ext.addr[0],radio->addr.addr_ext.addr[1],
           radio->addr.addr_ext.addr[2],radio->addr.addr_ext.addr[3],
           radio->addr.addr_ext.addr[4],radio->addr.addr_ext.addr[5],
           radio->addr.addr_ext.addr[6],radio->addr.addr_ext.addr[7]);

    if (!loop) {
        if ((connection = radiotest_connect(addr, area0, area1)) <= 0) {
            return NULL;
        }
        if (pico_dev_6lowpan_init(lp, "radio", (uint8_t *)&radio->addr, LL_MODE_IEEE802154, MTU_802154_MAC, 0, radiotest_send, radiotest_poll)) {
            RADIO_DBG("pico_device_init failed.\n");
            pico_device_destroy((struct pico_device *)lp);
            return NULL;
        }
    } else {
        if (pico_dev_6lowpan_init(lp, "radio", (uint8_t *)&radio->addr, LL_MODE_IEEE802154, MTU_802154_MAC, 0, pico_loop_send, pico_loop_poll)) {
            RADIO_DBG("pico_device_init failed.\n");
            pico_device_destroy((struct pico_device *)lp);
            return NULL;
        }
    }

    if (dump) {
        dbg("Dump: %s\n", dump);
        radiotest_pcap_open(radio, dump);
    }

    return (struct pico_device *)lp;
}

