#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "modules/pico_dev_sixlowpan.c"
#include "check.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//###############
//  MACROS
//###############
#define STARTING() printf("*********************** STARTING %s ***\n", __func__);\
                   fflush(stdout);
#define TRYING(s, ...) printf("Trying %s: " s, __func__, ##__VA_ARGS__); \
                       fflush(stdout);
#define CHECKING() printf("Checking the results for %s...", __func__); \
                   fflush(stdout);
#define SUCCESS() printf(" SUCCES\n");\
                  fflush(stdout);
#define BREAKING(s, ...) printf("Breaking %s: " s, __func__, ##__VA_ARGS__); \
                         fflush(stdout);
#define ENDING() printf("*********************** ENDING %s ***\n",__func__); \
                 fflush(stdout);

#define DBG(s, ...) printf(s, ##__VA_ARGS__);\
                    fflush(stdout);

const char* const mdns6_frame_1 = "6008cd6f006c11fffe800000000000005ab035fffe7341e3ff0200000000000000000000000000fb14e914e9006c10ae000084000000000200000001124a656c6c65732d4d6163426f6f6b2d50726f056c6f63616c00001c8001000000780010fe800000000000005ab035fffe7341e3c00c00018001000000780004c0a80103c00c002f8001000000780008c00c000440000008";
const char* const icmp6_frame_1  = "6000000000203aff2aaa610900000000020000aaab000002ff0200000000000000000001ff0000018700f2c3000000002aaa610900000000020000beef000001010158b0357341e3";
const char* const mldv2_frame_1 = "6000000000380001fe800000000000005ab035fffe7341e3ff0200000000000000000000000000163a000100050200008f000ab50000000204000000ff0200000000000000000002fff9923704000000ff0200000000000000000001ff000002";

//###############
//  RADIO MOCK
//###############
struct unit_radio {
    struct ieee_radio radio;
    uint16_t pan_id;
    uint16_t addr;
    uint8_t addr_ext[8];
};

/*
 * Mock to intercept frame from 6LoWPAN, does nothing for now.
 */
static int radio_transmit(struct ieee_radio *radio, void *buf, int len)
{
    (void)radio;
    (void)buf;
    (void)len;
    return 0;
}

/*
 * Mock to pass data to 6LoWPAN-device, does nothing for now.
 */
static int radio_receive(struct ieee_radio *radio, uint8_t *buf, int len)
{
    (void)radio;
    (void)buf;
    (void)len;
    return 0;
}

/*
 * Required by the device-driver
 */
static int radio_addr_ext(struct ieee_radio *radio, uint8_t *buf)
{
    (void)radio;
    (void)buf;
    return 0;
}

/*
 * Required by the device-driver
 */
static uint16_t radio_addr_short(struct ieee_radio *radio)
{
    (void)radio;
    return 0;
}

/*
 * Required by the device-driver
 */
uint16_t get_pan_id(struct ieee_radio *radio)
{
    (void)radio;
    return 0;
}

/*
 * Required by the device-driver
 */
static int radio_addr_short_set(struct ieee_radio *radio, uint16_t short_16)
{
    (void)radio;
    (void)short_16;
    return 0;
}

//###############
//  FRAME UTILS
//###############
#define SIZE_DUMMY_FRAME 60
static struct sixlowpan_frame *create_dummy_frame(void)
{
    struct sixlowpan_frame *new = NULL;
    
    if (!(new = PICO_ZALLOC(sizeof(struct sixlowpan_frame))))
        return NULL;
    
    if (!(new->phy_hdr = PICO_ZALLOC((size_t)SIZE_DUMMY_FRAME))) {
        PICO_FREE(new);
        return NULL;
    }
    
    new->size = SIZE_DUMMY_FRAME;
    
    return new;
}

/*
 *  Converts an HEX ASCII-char to a 4-bit nibble value
 */
static uint8_t char_to_hex(const char a)
{
    if (a >= 'a' && a <= 'z')
        return (uint8_t)(a - 'a' + 10);
    else if (a >= 'A' && a <= 'Z')
        return (uint8_t)(a - 'A' + 10);
    else if (a >= '0' && a <= '9')
        return (uint8_t)(a - '0');
    else
        return 0;
}

/*
 *  Create's a buffer with RAW data from a HEX dump.
 */
static uint8_t *hex_to_byte_array(const char *stream, size_t *nlen)
{
    size_t i = 0;
    uint8_t *array = NULL;
    
    *nlen = strlen(stream) >> 1;
    array = (uint8_t *)PICO_ZALLOC(*nlen); /* Don't want trailing zero in */
    
    /* For every 2 ASCII chars in the stream ... */
    for (i = 0; i < strlen(stream); i += 2) {
        /* Put the sum of value of the first char, times 16, and the value of the second char
         * in the new buffer */
        array[i >> 1] = (uint8_t)((char_to_hex(stream[i]) << 4) + char_to_hex(stream[i + 1]));
    }
    
    return array;
}

/*
 *  Fill's a created 6LoWPAN-frame with an IPv6 hex-dump as raw data
 */
static int fill_frame_with_dump(struct sixlowpan_frame *f, const uint8_t const *dump)
{
    if (!dump || !f)
        return -1;
    
    /* Fill the network-layer buffer of the frame */
    if (!(f->net_hdr = hex_to_byte_array(dump, (size_t *)&f->size)))
        return -1;

    /* Set the network-chunk to fixed size of 40 bytes */
    f->net_len = PICO_SIZE_IP6HDR;

    /* The transport-layer chunk gets the rest */
    f->transport_hdr = f->net_hdr + f->net_len;
    f->transport_len = (uint16_t)(f->size - f->net_len);
}

/*
 *  Calculates the size the IEEE-hdr needs to be in order to fit in the header
 *  and the given IEEE-addresses.
 */
static inline uint8_t pico_ieee_hdr_estimate_size(struct pico_ieee_addr src, struct pico_ieee_addr dst)
{
    uint8_t len = IEEE_MIN_HDR_LEN;
    len = (uint8_t)(len + pico_ieee_addr_len(src._mode));
    len = (uint8_t)(len + pico_ieee_addr_len(dst._mode));
    return len;
}

//###############
//  DEBUG UTILS
//###############

/*
 *  Dumps a memory buffer {buf} of size {len}. Preceding message
 *  can be passed with {pre}.
 */
static void dbg_mem(const char *pre, void *buf, uint16_t len)
{
    uint16_t i = 0, j = 0;
    
    /* Print in factors of 8 */
    printf("%s\n", pre);
    for (i = 0; i < (len / 8); i++) {
        printf("%03d. ", i * 8);
        for (j = 0; j < 8; j++) {
            printf("%02X ", ((uint8_t *)buf)[j + (i * 8)] );
            if (j == 3)
                printf(" ");
        }
        printf("\n");
    }
    
    if (!(len % 8))
        return;
    
    /* Print the rest */
    printf("%03d. ", i * 8);
    for (j = 0; j < (len % 8); j++) {
        printf("%02X ", ((uint8_t *)buf)[j + (i * 8)] );
        if (j == 3)
            printf(" ");
    }
    printf("\n");
}

/*
 *  Dumps an IEEE802.15.4 address in a structured manner. Preceding message
 *  can be passed with {msg}.
 */
static void dbg_ieee_addr(const char *msg, struct pico_ieee_addr *ieee)
{
    printf("%s: ", msg);
    printf("{.short = 0x%04X}, {.ext = %02X%02X:%02X%02X:%02X%02X:%02X%02X} ",
              ieee->_short.addr,
              ieee->_ext.addr[0],
              ieee->_ext.addr[1],
              ieee->_ext.addr[2],
              ieee->_ext.addr[3],
              ieee->_ext.addr[4],
              ieee->_ext.addr[5],
              ieee->_ext.addr[6],
              ieee->_ext.addr[7]);
}

/*
 *  Just dumps 8 bytes
 */
static void dbg_ext(uint8_t ext[8])
{
    uint8_t i = 0;
    for (i = 0; i < 8; i ++ ){
        printf("0x%02X ", ext[i]);
    }
    printf("\n");
}

/*
 *  Dumps the routing-table entries in a structured manner
 */
static void rtable_print(void)
{
    struct pico_tree_node *node = NULL;
    struct sixlowpan_rtable_entry *entry = NULL;
    
    printf("\nROUTING TABLE:\n");
    
    pico_tree_foreach(node, &RTable) {
        entry = (struct sixlowpan_rtable_entry *)node->keyValue;
        dbg_ieee_addr("PEER", &entry->dst);
        dbg_ieee_addr("VIA", &entry->via);
        printf("HOPS: %d\n", entry->hops);
    }
    
    printf("~~~ END OF ROUTING TABLE\n\n");
}

//###############
//  MARK: TESTS
//###############
START_TEST(tc_buf_delete) /* MARK: CHECKED */
{
    /* Works with not allocated buffers as well, since it doesn't free anything */
    char str[] = "Sing Hello, World!";
    uint16_t len = 19;
    uint16_t nlen = 0, plen = 0;
    
    /* Test removing the Hello-word including the preceding space */
    struct range r = {.offset = 4, .length = 6};
    
    STARTING();
    
    TRYING("\n");
    nlen = buf_delete(str, len, r);
    
    CHECKING();
    fail_unless(0 == strcmp(str, "Sing, World!"), "%s didnt't correctly delete chunk (%s)\n", __func__, str);
    fail_unless(nlen == (len - r.length), "%s didn't return the right nlen expected %d and is %d\n", __func__,  (len - r.length), nlen);
    SUCCESS();
    
    TRYING("\n");
    r.offset = 13;
    r.length = 1;
    plen = nlen;
    nlen = buf_delete(str, nlen, r);
    
    CHECKING();
    fail_unless(0 == strcmp(str, "Sing, World!"), "%s deleted while it didn't suppose to (%s)\n", __func__, str);
    fail_unless(nlen == plen, "%s returned wrong length, expected (%d) and is (%d)\n", __func__, plen, nlen);
    SUCCESS();
    
    TRYING("\n");
    r.offset = 0;
    r.length = 13;
    plen = nlen;
    nlen = buf_delete(str, nlen, r);
    
    CHECKING();
    fail_unless(0 == strcmp(str, ""), "%s should have deleted everything (%s)\n", __func__, str);
    fail_unless(nlen == 0, "%s returned wrong length, expected (0) and is (%d)\n", __func__, plen, nlen);
    SUCCESS();
    
    BREAKING("\n");
    fail_if(buf_delete(NULL, 4, r), "%s didn't check params!\n", __func__);
    
    /* Try with out of boundary offset */
    r.offset = len;
    r.length = 0;
    fail_unless(buf_delete(str, len, r), "%s didn't check offset!\n", __func__);
    
    /* Try with out of boundary range */
    r.offset = (uint16_t)(len - 1);
    r.length = 2;
    fail_unless(len == buf_delete(str, len, r), "%s didn't check range!\n", __func__);
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_buf_insert) /* MARK: CHECKED */
{
    struct range r = {.offset = 0, .length = 0};
    uint8_t *buf = NULL;
    uint8_t *pbuf = NULL;
    uint8_t cmp[] = {5,5,0,0,0,5,5,5};
    
    STARTING();
    TRYING("\n");
    /* Try to insert in a NULL-buff */
    r.offset = 0;
    r.length = 5;
    
    pbuf = buf;
    buf = buf_insert(buf, 0, r);
    CHECKING();
    fail_unless(buf !=  pbuf, "%s failed checking range!\n", __func__);
    SUCCESS();
    
    BREAKING("\n");
    /* OOB range */
    r.offset = 1;
    r.length = 1;
    pbuf = buf;
    buf = buf_insert(buf, 0, r);
    fail_unless(buf == pbuf, "%s failed checking offset!\n", __func__);
    SUCCESS();
    
    TRYING("\n");
    memset(buf, 5, 5);
    r.offset = 2;
    r.length = 3;
    pbuf = buf;
    buf = buf_insert(buf, 5, r);
    
    CHECKING();
    fail_unless(pbuf != buf, "%s didn't return a new ptr!\n", __func__);
    fail_unless(0 == memcmp(buf, cmp, (size_t)(5 + r.length)), "%s isn't formatted correctly!\n");
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_frame_rearrange_ptrs) /* MARK: CHECKED */
{
    struct sixlowpan_frame *new = NULL;
    STARTING();
    BREAKING("\n");
    new = create_dummy_frame();
    
    /* Invalid args */
    frame_rearrange_ptrs(new);
    fail_unless(new->link_hdr == (struct ieee_hdr *)(new->phy_hdr + IEEE_LEN_LEN), "%s failed rearranging PTRS!\n", __func__);
    
    TRYING("\n");
    new->link_hdr_len = 9;
    new->net_len = 40;
    new->transport_len = (uint16_t)(new->size - (uint16_t)(new->net_len - new->link_hdr_len));
    frame_rearrange_ptrs(new);
    
    CHECKING();
    fail_unless(new->link_hdr == (struct ieee_hdr  *)(new->phy_hdr + IEEE_LEN_LEN), "%s failed rearranging link header!\n", __func__);
    fail_unless(new->net_hdr == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + 9), "%s failed rearranging network header!\n", __func__);
    fail_unless(new->transport_hdr == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + 49), "%s failed rearranging transport header!\n", __func__);
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_frame_buf_insert) /* MARK: CHECKED */
{
    struct sixlowpan_frame *new = NULL;
    struct range r = {2, 5};
    uint16_t psize = 0;
    uint8_t *buf = NULL;
    STARTING();

    new = create_dummy_frame();
    new->link_hdr_len = 9;
    new->net_len = 40;
    new->transport_len = (uint16_t)(new->size - (uint16_t)(new->net_len - new->link_hdr_len));
    frame_rearrange_ptrs(new);
    
    TRYING("Network HDR\n"); /* NETWORK HDR */
    psize = new->size;
    buf = frame_buf_insert(new, PICO_LAYER_NETWORK, r);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - r.length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    TRYING("Datalink HDR\n");
    psize = new->size; /* LINK HDR */
    buf = frame_buf_insert(new, PICO_LAYER_DATALINK, r);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - r.length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    
    TRYING("Transport HDR\n");
    psize = new->size; /* TRANSPORT HDR */
    buf = frame_buf_insert(new, PICO_LAYER_TRANSPORT, r);
    
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + new->net_len + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - r.length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_frame_buf_prepend) /* MARK: CHECKED */
{
    struct sixlowpan_frame *new = NULL;
    uint16_t length = 5;
    uint16_t psize = 0;
    uint8_t *buf = NULL;
    STARTING();
    
    new = create_dummy_frame();
    new->link_hdr_len = 9;
    new->net_len = 40;
    new->transport_len = (uint16_t)(new->size - (uint16_t)(new->net_len - new->link_hdr_len));
    frame_rearrange_ptrs(new);
    
    
    TRYING("Network HDR\n"); /* NETWORK HDR */
    psize = new->size;
    buf = frame_buf_prepend(new, PICO_LAYER_NETWORK, length);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    TRYING("Datalink HDR\n");
    psize = new->size; /* LINK HDR */
    buf = frame_buf_prepend(new, PICO_LAYER_DATALINK, length);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    TRYING("Transport HDR\n");
    psize = new->size; /* TRANSPORT HDR */
    buf = frame_buf_prepend(new, PICO_LAYER_TRANSPORT, length);
    
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + new->net_len),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_frame_buf_delete) /* MARK: CHECKED */
{
    struct sixlowpan_frame *new = NULL;
    struct range r = {2, 5};
    uint16_t length = 5;
    uint16_t psize = 0;
    uint8_t *buf = NULL;
    STARTING();
    
    new = create_dummy_frame();
    new->link_hdr_len = 9;
    new->net_len = 40;
    new->transport_len = (uint16_t)(new->size - (uint16_t)(new->net_len - new->link_hdr_len));
    frame_rearrange_ptrs(new);
    
    TRYING("Network HDR\n"); /* NETWORK HDR */
    psize = new->size;
    buf = frame_buf_delete(new, PICO_LAYER_NETWORK, r, 0);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size + r.length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    TRYING("Datalink HDR\n");
    psize = new->size; /* LINK HDR */
    buf = frame_buf_delete(new, PICO_LAYER_DATALINK, r, 0);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size + r.length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    TRYING("Transport HDR\n");
    psize = new->size; /* TRANSPORT HDR */
    buf = frame_buf_delete(new, PICO_LAYER_TRANSPORT, r, 0);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + new->net_len + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size + r.length), "%s didn't update new size correctly\n", __func__);
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_pico_ieee_addr_to_flat) /* MARK: CHECKED */
{
    uint8_t buf[8] = { 0, 0, 0, 0, 0, 0 ,0 ,0 };
    uint8_t cmp1[8] = { 0x34, 0x12, 0, 0, 0, 0, 0, 0 };
    uint8_t cmp2[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint8_t cmp3[8] = { 0x12, 0x34, 0, 0, 0, 0, 0, 0 };
    uint8_t cmp4[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    struct pico_ieee_addr addr = {{0x1234}, {{ 1, 2, 3, 4, 5, 6, 7, 8 }}, IEEE_AM_BOTH};
    
    STARTING();
    
    printf("Short: 0x%04X\n", addr._short.addr);
    printf("Ext: ");
    dbg_ext(addr._ext.addr);
    
    TRYING("Flat IEEE-buffer, with AM_BOTH\n");
    pico_ieee_addr_to_flat(buf, addr, IEEE_TRUE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp1, PICO_SIZE_IEEE_SHORT), "%s didn't handle AM_BOTH correctly or IEEE_TRUE", __func__);
    SUCCESS();
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat IEEE-buffer, with AM_EXT\n");
    addr._mode = IEEE_AM_EXTENDED;
    pico_ieee_addr_to_flat(buf, addr, IEEE_TRUE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp2, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_TRUE", __func__);
    SUCCESS();
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat IEEE-buffer, with AM_SHORT\n");
    addr._mode = IEEE_AM_SHORT;
    pico_ieee_addr_to_flat(buf, addr, IEEE_TRUE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp1, PICO_SIZE_IEEE_SHORT), "%s didn't handle AM_BOTH correctly or IEEE_TRUE", __func__);
    SUCCESS();
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat Non-IEEE-buffer, with AM_BOTH\n");
    pico_ieee_addr_to_flat(buf, addr, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp3, PICO_SIZE_IEEE_SHORT), "%s didn't handle AM_BOTH correctly or IEEE_FALSE", __func__);
    SUCCESS();
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat Non-IEEE-buffer, with AM_EXT\n");
    addr._mode = IEEE_AM_EXTENDED;
    pico_ieee_addr_to_flat(buf, addr, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp4, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_FALSE", __func__);
    SUCCESS();
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat NonIEEE-buffer, with AM_SHORT\n");
    addr._mode = IEEE_AM_SHORT;
    pico_ieee_addr_to_flat(buf, addr, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp3, PICO_SIZE_IEEE_SHORT), "%s didn't handle AM_SHORT correctly or IEEE_FALSE", __func__);
    SUCCESS();
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    ENDING();
}
END_TEST
START_TEST(tc_pico_ieee_addr_from_flat) /* MARK: CHECKED */
{
    uint8_t cmp1[8] = { 0x34, 0x12, 0, 0, 0, 0, 0, 0 };
    uint8_t cmp2[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint8_t cmp4[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    struct pico_ieee_addr addr;

    STARTING();
    
    TRYING("Flat IEEE-buffer, with AM_SHORT\n");
    addr = pico_ieee_addr_from_flat(cmp1, IEEE_AM_SHORT, IEEE_TRUE);
    CHECKING();
    fail_unless(0x1234 == addr._short.addr, "%s didn't handle AM_SHORT correctly or IEEE_TRUE", __func__);
    SUCCESS();
    
    TRYING("Flat IEEE-buffer, with AM_EXT\n");
    addr = pico_ieee_addr_from_flat(cmp2, IEEE_AM_EXTENDED, IEEE_TRUE);
    CHECKING();
    fail_unless(0 == memcmp(cmp4, addr._ext.addr, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_TRUE", __func__);
    SUCCESS();
    
    TRYING("Flat Non-IEEE-buffer, with AM_SHORT\n");
    addr = pico_ieee_addr_from_flat(cmp1, IEEE_AM_SHORT, IEEE_FALSE);
    CHECKING();
    fail_unless(0x3412 == addr._short.addr, "%s didn't handle AM_SHORT correctly or IEEE_FALSE", __func__);
    SUCCESS();
    
    TRYING("Flat Non-IEEE-buffer, with AM_EXT\n");
    addr = pico_ieee_addr_from_flat(cmp2, IEEE_AM_EXTENDED, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(cmp2, addr._ext.addr, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_FALSE", __func__);
    SUCCESS();
    
    ENDING();
}
END_TEST
#define SIZE1 (IEEE_MIN_HDR_LEN + PICO_SIZE_IEEE_SHORT + PICO_SIZE_IEEE_SHORT)
#define SIZE2 (IEEE_MIN_HDR_LEN + PICO_SIZE_IEEE_EXT + PICO_SIZE_IEEE_SHORT)
#define SIZE3 (IEEE_MIN_HDR_LEN + PICO_SIZE_IEEE_EXT + PICO_SIZE_IEEE_EXT)
#define SIZE4 (IEEE_MIN_HDR_LEN + PICO_SIZE_IEEE_SHORT + PICO_SIZE_IEEE_EXT)
START_TEST(tc_pico_ieee_addr_to_hdr)
{
    uint8_t cmp1[SIZE1] = { 0x00, 0x88, 0x00, 0x00, 0x00, 0xDD, 0xCC, 0xBB, 0xAA };
    uint8_t cmp2[SIZE2] = { 0x00, 0x8C, 0x00, 0x00, 0x00, 16, 15, 14, 13, 12, 11, 10, 9, 0xBB, 0xAA };
    uint8_t cmp3[SIZE3] = { 0x00, 0xCC, 0x00, 0x00, 0x00, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    uint8_t cmp4[SIZE4] = { 0x00, 0xC8, 0x00, 0x00, 0x00, 0xDD, 0xCC, 8, 7, 6, 5, 4, 3, 2, 1 };
    
    struct pico_ieee_addr src = {{0xaabb}, {{ 1, 2, 3, 4, 5, 6, 7, 8 }}, IEEE_AM_BOTH};
    struct pico_ieee_addr dst = {{0xccdd}, {{ 9, 10, 11, 12, 13, 14, 15, 16 }}, IEEE_AM_BOTH};
    struct ieee_hdr * hdr = NULL;
    uint8_t max_size = SIZE3;
    uint8_t hdr_size = 0;
    int ret = 0;
    
    STARTING();
    /* First */
    if (!(hdr = PICO_ZALLOC((size_t)max_size))) {
        printf("PICO_ZALLOC failed before test!\n");
        return;
    }
    
    TRYING("Filling addresses with 2 x AM_BOTH\n");
    hdr_size = pico_ieee_hdr_estimate_size(src, dst);
    CHECKING();
    fail_unless(hdr_size = SIZE1, "Failed estimating size of the MAC header\n");
    ret = pico_ieee_addr_to_hdr(hdr, src, dst);
    dbg_mem("HDR: ", (uint8_t *)hdr, SIZE1);
    fail_if(ret, "%s failed filling addresses with 2 x AM_BOTH\n", __func__);
    fail_unless(0 == memcmp(hdr, cmp1, SIZE1), "%s failed comparing address with 2 x AM_BOTH\n", __func__);
    SUCCESS();
    memset(hdr, 0, max_size);
    
    TRYING("Filling addresses with DST: EXT and SRC: SHORT\n");
    dst._mode = IEEE_AM_EXTENDED;
    hdr_size = pico_ieee_hdr_estimate_size(src, dst);
    CHECKING();
    fail_unless(hdr_size = SIZE2, "Failed estimating size of the MAC header\n");
    ret = pico_ieee_addr_to_hdr(hdr, src, dst);
    dbg_mem("HDR: ", (uint8_t *)hdr, SIZE2);
    fail_if(ret, "%s failed filling addresses with DST: EXT and SRC: SHORT\n", __func__);
    fail_unless(0 == memcmp(hdr, cmp2, SIZE2), "%s failed comparing address with DST: EXT and SRC: SHORT\n", __func__);
    SUCCESS();
    memset(hdr, 0, max_size);
    
    TRYING("Filling addresses with 2 x AM_EXT \n");
    src._mode = IEEE_AM_EXTENDED;
    hdr_size = pico_ieee_hdr_estimate_size(src, dst);
    CHECKING();
    fail_unless(hdr_size = SIZE3, "Failed estimating size of the MAC header\n");
    ret = pico_ieee_addr_to_hdr(hdr, src, dst);
    dbg_mem("HDR: ", (uint8_t *)hdr, SIZE3);
    fail_if(ret, "%s failed filling addresses with 2 x AM_EXT\n", __func__);
    fail_unless(0 == memcmp(hdr, cmp3, SIZE3), "%s failed comparing address with 2 x AM_EXT\n", __func__);
    SUCCESS();
    memset(hdr, 0, max_size);
    
    TRYING("Filling addresses with DST: SHORT and SRC: EXT\n");
    dst._mode = IEEE_AM_SHORT;
    hdr_size = pico_ieee_hdr_estimate_size(src, dst);
    CHECKING();
    fail_unless(hdr_size = SIZE4, "Failed estimating size of the MAC header\n");
    ret = pico_ieee_addr_to_hdr(hdr, src, dst);
    dbg_mem("HDR: ", (uint8_t *)hdr, SIZE4);
    fail_if(ret, "%s failed filling addresses with DST: EXT and SRC: SHORT\n", __func__);
    fail_unless(0 == memcmp(hdr, cmp4, SIZE4), "%s failed comparing address with DST: EXT and SRC: SHORT\n", __func__);
    SUCCESS();
    memset(hdr, 0, max_size);
    
    BREAKING("Setting both address modes to NONE\n");
    dst._mode = IEEE_AM_NONE;
    src._mode = IEEE_AM_NONE;
    CHECKING();
    fail_unless(pico_ieee_addr_to_hdr(hdr, src, dst), "%s failed checking for IEEE_AM_NONE\n", __func__);
    SUCCESS();
    
    BREAKING("Passing NULL-ptrs\n");
    fail_unless(pico_ieee_addr_to_hdr(NULL, src, dst), "%s failed checking for NULL-ptrs\n", __func__);
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_pico_ieee_addr_from_hdr)
{
    uint8_t ext1[PICO_SIZE_IEEE_EXT] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t ext2[PICO_SIZE_IEEE_EXT] = { 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t ext3[PICO_SIZE_IEEE_EXT] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t cmp1[SIZE1] = { 0x00, 0x88, 0x00, 0x00, 0x00, 0xDD, 0xCC, 0xBB, 0xAA };
    uint8_t cmp2[SIZE2] = { 0x00, 0x8C, 0x00, 0x00, 0x00, 16, 15, 14, 13, 12, 11, 10, 9, 0xBB, 0xAA };
    uint8_t cmp3[SIZE3] = { 0x00, 0xCC, 0x00, 0x00, 0x00, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    struct pico_ieee_addr addr;
    
    STARTING();
    
    TRYING("Trying with 2 x AM_SHORT\n");
    addr = pico_ieee_addr_from_hdr((struct ieee_hdr *)cmp1, 0);

    CHECKING();
    fail_unless(IEEE_AM_SHORT == addr._mode, "%s failed setting addressing mode to short (%d)\n", __func__, addr._mode);
    fail_unless(0 == memcmp(addr._ext.addr, ext1, PICO_SIZE_IEEE_EXT), "%s failed clearing out extended address\n", __func__);
    fail_unless(0xCCDD == addr._short.addr, "%s failed setting short address correctly 0x%04X\n", __func__, addr._short.addr);
    SUCCESS();
    
    TRYING("Trying with EXT dst and SHORT src\n");
    addr = pico_ieee_addr_from_hdr((struct ieee_hdr *)cmp2, 0);
    
    CHECKING();
    fail_unless(IEEE_AM_EXTENDED == addr._mode, "%s failed setting addressing mode to extended (%d)\n", __func__, addr._mode);
    fail_unless(0 == memcmp(addr._ext.addr, ext2, PICO_SIZE_IEEE_EXT), "%s failed copying extended address\n", __func__);
    SUCCESS();

    /* TODO: Check this verification */
    /* fail_unless(0x0000 == addr._short.addr, "%s failed clearing out the short address 0x%04X\n", __func__, addr._short.addr); */
    
    TRYING("Trying with EXT dst and SHORT src, but for the SRC\n");
    addr = pico_ieee_addr_from_hdr((struct ieee_hdr *)cmp2, 1);
    
    CHECKING();
    fail_unless(IEEE_AM_SHORT == addr._mode, "%s failed setting addressing mode to short (%d)\n", __func__, addr._mode);
    fail_unless(0 == memcmp(addr._ext.addr, ext1, PICO_SIZE_IEEE_EXT), "%s failed clearing out extended address\n", __func__);
    fail_unless(0xAABB == addr._short.addr, "%s failed copying the short address 0x%04X\n", __func__, addr._short.addr);
    SUCCESS();
    
    TRYING("Trying with EXT dst and EXT src, but for the src\n");
    addr = pico_ieee_addr_from_hdr((struct ieee_hdr *)cmp3, 1);
    
    CHECKING();
    fail_unless(IEEE_AM_EXTENDED == addr._mode, "%s failed setting addressing mode to extended (%d)", __func__, addr._mode);
    fail_unless(0 == memcmp(addr._ext.addr, ext3, PICO_SIZE_IEEE_EXT), "%s failed copying extended address\n", __func__);
    /* TODO: Check this verification */
    //fail_unless(0x0000 == addr._short.addr, "%s failed clearing out the short address 0x%04X\n", __func__, addr._short.addr);
    SUCCESS();

    ENDING();
}
END_TEST
START_TEST(tc_sixlowpan_create)
{
    
    STARTING();
    
    struct unit_radio *radio = (struct unit_radio *)PICO_ZALLOC(sizeof(struct unit_radio));
    struct pico_device *new = NULL;
    
    /* Don't forget to initiate the stack for the timers... */
    pico_stack_init();
    
    TRYING("With invalid argument\n");
    new = pico_sixlowpan_create(NULL);
    CHECKING();
    fail_unless(NULL == new, "Failed checking params\n");
    SUCCESS();
    
    TRYING("With proper argument but invalid radio-format\n");
    new = pico_sixlowpan_create(radio);
    CHECKING();
    fail_unless(NULL == new, "Failed checking radio-format, callback-function not set\n");
    SUCCESS();
    
    radio->radio.transmit = radio_transmit;
    radio->radio.receive = radio_receive;
    radio->radio.get_pan_id = get_pan_id;
    radio->radio.get_addr_short = radio_addr_short;
    radio->radio.get_addr_ext = radio_addr_ext;
    radio->radio.set_addr_short = radio_addr_short_set;
    
    TRYING("With proper argument AND valid radio-format\n");
    new = pico_sixlowpan_create(radio);
    CHECKING();
    fail_if(NULL == new, "Failed creating a 6LoWPAN-radio interface\n");
    SUCCESS();
    
    ENDING();
}
END_TEST
START_TEST(tc_sixlowpan_frame_create)
{
    struct sixlowpan_frame *new = NULL;
    struct pico_ieee_addr src = {0};
    struct pico_ieee_addr dst = {0};
    struct pico_device *dev = NULL;
    
    STARTING();
    
    TRYING("with invalid arguments\n");
    //new = sixlowpan_frame_create(src, dst, dev);
    
    CHECKING();
    fail_unless(NULL == new, "Failed checking params\n");
    
    
    TRYING("With valid params\n");
    
    // TODO: Create valid device.
}
END_TEST
START_TEST(tc_sixlowpan_compress)
{
    struct sixlowpan_frame *new = NULL;
    
    //create_frame_from_dump(mdns6_frame_1);

    STARTING();

    TRYING();
    sixlowpan_compress(new);

    CHECKING();
    fail_if(new->state == FRAME_ERROR, "Error while compressing frame probably to not set of other fields in the frame\n");

    // TODO: Properly test.

    ENDING();
}
END_TEST
Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");             

    /* -------------------------------------------------------------------------------- */
    // MARK: MEMORY TCASES
    TCase *TCase_buf_delete = tcase_create("Unit test for buf_delete"); /* CHECKED */
    tcase_add_test(TCase_buf_delete, tc_buf_delete);
    suite_add_tcase(s, TCase_buf_delete);
    
    TCase *TCase_buf_insert = tcase_create("Unit test for buf_insert"); /* CHECKED */
    tcase_add_test(TCase_buf_insert, tc_buf_insert);
    suite_add_tcase(s, TCase_buf_insert);
    
    TCase *TCase_frame_rearrange_ptrs = tcase_create("Unit test for frame_rearrange_ptrs"); /* CHECKED */
    tcase_add_test(TCase_frame_rearrange_ptrs, tc_frame_rearrange_ptrs);
    suite_add_tcase(s, TCase_frame_rearrange_ptrs);
    
    TCase *TCase_frame_buf_insert = tcase_create("Unit test for frame_buf_insert"); /* CHECKED */
    tcase_add_test(TCase_frame_buf_insert, tc_frame_buf_insert);
    suite_add_tcase(s, TCase_frame_buf_insert);
    
    TCase *TCase_frame_buf_prepend = tcase_create("Unit test for frame_buf_prepend"); /* CHECKED */
    tcase_add_test(TCase_frame_buf_prepend, tc_frame_buf_prepend);
    suite_add_tcase(s, TCase_frame_buf_prepend);
    
    TCase *TCase_frame_buf_delete = tcase_create("Unit test for frame_buf_delete"); /* CHECKED */ 
    tcase_add_test(TCase_frame_buf_delete, tc_frame_buf_delete);
    suite_add_tcase(s, TCase_frame_buf_delete);

    /* -------------------------------------------------------------------------------- */
    // MARK: FLAT (ADDRESSES)
    TCase *TCase_pico_ieee_addr_to_flat = tcase_create("Unit test for pico_ieee_addr_to_flat"); /* CHECKED */
    tcase_add_test(TCase_pico_ieee_addr_to_flat, tc_pico_ieee_addr_to_flat);
    suite_add_tcase(s, TCase_pico_ieee_addr_to_flat);
    
    TCase *TCase_pico_ieee_addr_from_flat = tcase_create("Unit test for pico_ieee_addr_from_flat"); /*CHECKED */
    tcase_add_test(TCase_pico_ieee_addr_from_flat, tc_pico_ieee_addr_from_flat);
    suite_add_tcase(s, TCase_pico_ieee_addr_from_flat);
    
    TCase *TCase_pico_ieee_addr_to_hdr = tcase_create("Unit test for pico_ieee_addr_to_hdr"); /* CHECKED */
    tcase_add_test(TCase_pico_ieee_addr_to_hdr, tc_pico_ieee_addr_to_hdr);
    suite_add_tcase(s, TCase_pico_ieee_addr_to_hdr);
    
    TCase *TCase_pico_ieee_addr_from_hdr = tcase_create("Unit test for pico_ieee_addr_from_hdr"); /* CHECKED */
    tcase_add_test(TCase_pico_ieee_addr_from_hdr, tc_pico_ieee_addr_from_hdr);
    suite_add_tcase(s, TCase_pico_ieee_addr_from_hdr);

    /* -------------------------------------------------------------------------------- */
    // MARK: DEVICE
    TCase *TCase_sixlowpan_create = tcase_create("Unit test for sixlowpan_create");
    tcase_add_test(TCase_sixlowpan_create, tc_sixlowpan_create);
    suite_add_tcase(s, TCase_sixlowpan_create);
    
    /* -------------------------------------------------------------------------------- */
    // MARK: FRAMES
    TCase *TCase_sixlowpan_frame_create = tcase_create("Unit test for sixlowpan_frame_create");
    tcase_add_test(TCase_sixlowpan_frame_create, tc_sixlowpan_frame_create);
    suite_add_tcase(s, TCase_sixlowpan_frame_create);
    
    /* -------------------------------------------------------------------------------- */
    // MARK: COMPRESSION
    TCase *TCase_sixlowpan_compress = tcase_create("Unit test for sixlowpan_compress");
    tcase_add_test(TCase_sixlowpan_compress, tc_sixlowpan_compress);
    suite_add_tcase(s, TCase_sixlowpan_compress);
    

    return s;
}
                      
int main(void)                      
{                       
    int fails;                      
    Suite *s = pico_suite();                        
    SRunner *sr = srunner_create(s);                        
    srunner_run_all(sr, CK_NORMAL);                     
    fails = srunner_ntests_failed(sr);                      
    srunner_free(sr);                       
    return fails;                       
}
