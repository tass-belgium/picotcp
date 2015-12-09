#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "modules/pico_dev_sixlowpan.c"
#include "check.h"

#define STARTING() printf("*********************** STARTING %s ***\n", __func__)
#define TRYING(s, ...) printf("Trying %s: " s, __func__, ##__VA_ARGS__)
#define CHECKING() printf("Checking the results for %s\n", __func__)
#define BREAKING(s, ...) printf("Breaking %s: " s, __func__, ##__VA_ARGS__)
#define ENDING() printf("*********************** ENDING %s ***\n",__func__)

#define DBG(s, ...) printf(s, ##__VA_ARGS__)

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

static inline uint8_t pico_ieee_hdr_estimate_size(struct pico_ieee_addr src, struct pico_ieee_addr dst)
{
    uint8_t len = IEEE_MIN_HDR_LEN;
    len = (uint8_t)(len + pico_ieee_addr_len(src._mode));
    len = (uint8_t)(len + pico_ieee_addr_len(dst._mode));
    return len;
}

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

static void debug_ieee_addr(const char *msg, struct pico_ieee_addr *ieee)
{
    printf("%s: ", msg);
    printf("{0x%04X}, {%02X%02X:%02X%02X:%02X%02X:%02X%02X} ",
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

static void rtable_print(void)
{
    struct pico_tree_node *node = NULL;
    struct sixlowpan_rtable_entry *entry = NULL;
    
    printf("\nROUTING TABLE:\n");
    
    pico_tree_foreach(node, &RTable) {
        entry = (struct sixlowpan_rtable_entry *)node->keyValue;
        debug_ieee_addr("PEER", &entry->dst);
        debug_ieee_addr("VIA", &entry->via);
        printf("METRIC: %d\n", entry->hops);
    }
    printf("~~~ END OF ROUTING TABLE\n\n");
}

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
    
    TRYING("\n");
    r.offset = 13;
    r.length = 1;
    plen = nlen;
    nlen = buf_delete(str, nlen, r);
    
    CHECKING();
    fail_unless(0 == strcmp(str, "Sing, World!"), "%s deleted while it didn't suppose to (%s)\n", __func__, str);
    fail_unless(nlen == plen, "%s returned wrong length, expected (%d) and is (%d)\n", __func__, plen, nlen);
    
    TRYING("\n");
    r.offset = 0;
    r.length = 13;
    plen = nlen;
    nlen = buf_delete(str, nlen, r);
    
    CHECKING();
    fail_unless(0 == strcmp(str, ""), "%s should have deleted everything (%s)\n", __func__, str);
    fail_unless(nlen == 0, "%s returned wrong length, expected (0) and is (%d)\n", __func__, plen, nlen);
    
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
    fail_unless(buf !=  pbuf, "%s failed checking range!\n", __func__);
    
    BREAKING("\n");
    /* OOB range */
    r.offset = 1;
    r.length = 1;
    pbuf = buf;
    buf = buf_insert(buf, 0, r);
    fail_unless(buf == pbuf, "%s failed checking offset!\n", __func__);
    
    TRYING("\n");
    memset(buf, 5, 5);
    r.offset = 2;
    r.length = 3;
    pbuf = buf;
    buf = buf_insert(buf, 5, r);
    
    CHECKING();
    fail_unless(pbuf != buf, "%s didn't return a new ptr!\n", __func__);
    fail_unless(0 == memcmp(buf, cmp, (size_t)(5 + r.length)), "%s isn't formatted correctly!\n");
    
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
    
    TRYING("Datalink HDR\n");
    psize = new->size; /* LINK HDR */
    buf = frame_buf_insert(new, PICO_LAYER_DATALINK, r);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - r.length), "%s didn't update new size correctly\n", __func__);
    
    
    TRYING("Transport HDR\n");
    psize = new->size; /* TRANSPORT HDR */
    buf = frame_buf_insert(new, PICO_LAYER_TRANSPORT, r);
    
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + new->net_len + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - r.length), "%s didn't update new size correctly\n", __func__);
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
    
    TRYING("Datalink HDR\n");
    psize = new->size; /* LINK HDR */
    buf = frame_buf_prepend(new, PICO_LAYER_DATALINK, length);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - length), "%s didn't update new size correctly\n", __func__);
    
    TRYING("Transport HDR\n");
    psize = new->size; /* TRANSPORT HDR */
    buf = frame_buf_prepend(new, PICO_LAYER_TRANSPORT, length);
    
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + new->net_len),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size - length), "%s didn't update new size correctly\n", __func__);
    
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
    
    TRYING("Datalink HDR\n");
    psize = new->size; /* LINK HDR */
    buf = frame_buf_delete(new, PICO_LAYER_DATALINK, r, 0);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size + r.length), "%s didn't update new size correctly\n", __func__);
    
    TRYING("Transport HDR\n");
    psize = new->size; /* TRANSPORT HDR */
    buf = frame_buf_delete(new, PICO_LAYER_TRANSPORT, r, 0);
    CHECKING();
    fail_unless((int)(long)buf, "%s returned NULL-ptr", __func__);
    fail_unless(buf == (uint8_t *)(new->phy_hdr + IEEE_LEN_LEN + new->link_hdr_len + new->net_len + r.offset),
                "%s returned pointer that doesn't point to inserted chunk\n", __func__);
    fail_unless(psize == (uint16_t)(new->size + r.length), "%s didn't update new size correctly\n", __func__);
    
    ENDING();
}
END_TEST
static void dbg_ext(uint8_t ext[8] )
{
    uint8_t i = 0;
    for (i = 0; i < 8; i ++ ){
        printf("0x%02X ", ext[i]);
    }
    printf("\n");
}
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
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat IEEE-buffer, with AM_EXT\n");
    addr._mode = IEEE_AM_EXTENDED;
    pico_ieee_addr_to_flat(buf, addr, IEEE_TRUE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp2, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_TRUE", __func__);
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat IEEE-buffer, with AM_SHORT\n");
    addr._mode = IEEE_AM_SHORT;
    pico_ieee_addr_to_flat(buf, addr, IEEE_TRUE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp1, PICO_SIZE_IEEE_SHORT), "%s didn't handle AM_BOTH correctly or IEEE_TRUE", __func__);
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat Non-IEEE-buffer, with AM_BOTH\n");
    pico_ieee_addr_to_flat(buf, addr, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp3, PICO_SIZE_IEEE_SHORT), "%s didn't handle AM_BOTH correctly or IEEE_FALSE", __func__);
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat Non-IEEE-buffer, with AM_EXT\n");
    addr._mode = IEEE_AM_EXTENDED;
    pico_ieee_addr_to_flat(buf, addr, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp4, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_FALSE", __func__);
    memset(buf, 0, PICO_SIZE_IEEE_EXT);
    
    TRYING("Flat NonIEEE-buffer, with AM_SHORT\n");
    addr._mode = IEEE_AM_SHORT;
    pico_ieee_addr_to_flat(buf, addr, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(buf, cmp3, PICO_SIZE_IEEE_SHORT), "%s didn't handle AM_SHORT correctly or IEEE_FALSE", __func__);
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
    
    TRYING("Flat IEEE-buffer, with AM_EXT\n");
    addr = pico_ieee_addr_from_flat(cmp2, IEEE_AM_EXTENDED, IEEE_TRUE);
    CHECKING();
    fail_unless(0 == memcmp(cmp4, addr._ext.addr, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_TRUE", __func__);
    
    TRYING("Flat Non-IEEE-buffer, with AM_SHORT\n");
    addr = pico_ieee_addr_from_flat(cmp1, IEEE_AM_SHORT, IEEE_FALSE);
    CHECKING();
    fail_unless(0x3412 == addr._short.addr, "%s didn't handle AM_SHORT correctly or IEEE_FALSE", __func__);
    
    TRYING("Flat Non-IEEE-buffer, with AM_EXT\n");
    addr = pico_ieee_addr_from_flat(cmp2, IEEE_AM_EXTENDED, IEEE_FALSE);
    CHECKING();
    fail_unless(0 == memcmp(cmp2, addr._ext.addr, PICO_SIZE_IEEE_EXT), "%s didn't handle AM_EXT correctly or IEEE_FALSE", __func__);
    
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
    memset(hdr, 0, max_size);
    
    BREAKING("Setting both address modes to NONE\n");
    dst._mode = IEEE_AM_NONE;
    src._mode = IEEE_AM_NONE;
    CHECKING();
    fail_unless(pico_ieee_addr_to_hdr(hdr, src, dst), "%s failed checking for IEEE_AM_NONE\n", __func__);
    
    BREAKING("Passing NULL-ptrs\n");
    fail_unless(pico_ieee_addr_to_hdr(NULL, src, dst), "%s failed checking for NULL-ptrs\n", __func__);
    
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
    
    TRYING("Trying with EXT dst and SHORT src\n");
    addr = pico_ieee_addr_from_hdr((struct ieee_hdr *)cmp2, 0);
    
    CHECKING();
    fail_unless(IEEE_AM_EXTENDED == addr._mode, "%s failed setting addressing mode to extended (%d)\n", __func__, addr._mode);
    fail_unless(0 == memcmp(addr._ext.addr, ext2, PICO_SIZE_IEEE_EXT), "%s failed copying extended address\n", __func__);
    fail_unless(0x0000 == addr._short.addr, "%s failed clearing out the short address 0x%04X\n", __func__, addr._short.addr);
    
    TRYING("Trying with EXT dst and SHORT src, but for the SRC\n");
    addr = pico_ieee_addr_from_hdr((struct ieee_hdr *)cmp2, 1);
    
    CHECKING();
    fail_unless(IEEE_AM_SHORT == addr._mode, "%s failed setting addressing mode to short (%d)\n", __func__, addr._mode);
    fail_unless(0 == memcmp(addr._ext.addr, ext1, PICO_SIZE_IEEE_EXT), "%s failed clearing out extended address\n", __func__);
    fail_unless(0xAABB == addr._short.addr, "%s failed copying the short address 0x%04X\n", __func__, addr._short.addr);
    
    TRYING("Trying with EXT dst and EXT src, but for the src\n");
    addr = pico_ieee_addr_from_hdr((struct ieee_hdr *)cmp3, 1);
    
    CHECKING();
    fail_unless(IEEE_AM_EXTENDED == addr._mode, "%s failed setting addressing mode to extended (%d)", __func__, addr._mode);
    fail_unless(0 == memcmp(addr._ext.addr, ext3, PICO_SIZE_IEEE_EXT), "%s failed copying extended address\n", __func__);
    fail_unless(0x0000 == addr._short.addr, "%s failed clearing out the short address 0x%04X\n", __func__, addr._short.addr);
    
    ENDING();
}
END_TEST
START_TEST(tc_IEEE_EUI64_LE)
{
//    uint8_t old[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
//    uint8_t new[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
//    STARTING();
//    TRYING("\n");
//    IEEE_EUI64_LE(old);
//    CHECKING();
//    fail_unless(0 == memcmp(old, new, 8), "%s failed converting to little endian", __func__);
//    ENDING();
}
END_TEST
START_TEST(tc_IEEE_hdr_len)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE_hdr_len(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_IEEE_len)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE_len(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_IEEE_hdr_buf_len)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE_hdr_buf_len(IEEE_hdr_t *hdr) */
}
END_TEST
START_TEST(tc_IEEE_process_address)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void IEEE_process_address(uint8_t *buf, struct pico_sixlowpan_addr *addr, IEEE_address_mode_t am) */
}
END_TEST
START_TEST(tc_IEEE_process_addresses)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void IEEE_process_addresses(IEEE_hdr_t *hdr, struct pico_sixlowpan_addr *dst, struct pico_sixlowpan_addr *src) */
}
END_TEST
START_TEST(tc_IEEE_unbuf)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static struct sixlowpan_frame *IEEE_unbuf(struct pico_device *dev, uint8_t *buf, uint8_t len) */
}
END_TEST
START_TEST(tc_sixlowpan_frame_destroy)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void sixlowpan_frame_destroy(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_addr_copy_flat)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int UNUSED sixlowpan_iid_is_derived_64(uint8_t in[8]) */
}
END_TEST
START_TEST(tc_sixlowpan_iid_is_derived_64)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int sixlowpan_iid_is_derived_16(uint8_t in[8]) */
}
END_TEST
START_TEST(tc_sixlowpan_iid_is_derived_16)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: inline static int sixlowpan_iid_is_derived_16(uint8_t in[8]) */
}
END_TEST
START_TEST(tc_sixlowpan_iid_from_extended)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int sixlowpan_iid_from_extended(struct pico_sixlowpan_addr_ext addr, uint8_t out[8]) */
}
END_TEST
START_TEST(tc_sixlowpan_iid_from_short)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int sixlowpan_iid_from_short(struct pico_sixlowpan_addr_short addr, uint8_t out[8]) */
}
END_TEST
START_TEST(tc_sixlowpan_addr_from_iid)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_addr_from_iid(struct pico_sixlowpan_addr *addr, uint8_t in[8]) */
}
END_TEST
START_TEST(tc_sixlowpan_ipv6_derive_local)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_ipv6_derive_mcast(iphc_dam_mcast_t am, uint8_t *addr) */
}
END_TEST
START_TEST(tc_sixlowpan_ipv6_derive_mcast)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_ipv6_derive_mcast(iphc_dam_mcast_t am, uint8_t *addr) */
}
END_TEST
START_TEST(tc_sixlowpan_ll_derive_local)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_ipv6_derive_mcast(iphc_dam_mcast_t am, uint8_t *addr) */
}
END_TEST
START_TEST(tc_sixlowpan_ll_derive_mcast)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_ipv6_derive_mcast(iphc_dam_mcast_t am, uint8_t *addr) */
}
END_TEST
START_TEST(tc_sixlowpan_ll_derive_nd)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_ipv6_derive_mcast(iphc_dam_mcast_t am, uint8_t *addr) */
}
END_TEST
START_TEST(tc_sixlowpan_nh_is_compressible)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_ipv6_derive_mcast(iphc_dam_mcast_t am, uint8_t *addr) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_udp_ports_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_udp_ports)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_udp_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_udp)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nh_from_eid)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_ext_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_ext)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_compress)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_am_undo(iphc_am_t am, ipv6_addr_id_t id, struct pico_sixlowpan_addr addr, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_am_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static range_t sixlowpan_iphc_mcast_dam(iphc_dam_mcast_t am) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_mcast_dam)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_dam_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_dam_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_rearrange_mcast(uint8_t *addr, sixlowpan_iphc_t *iphc) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_rearrange_mcast)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_dam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE_address_mode_t dam) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_dam)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_sam_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_sam_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_sam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE_address_mode_t sam) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_sam)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_hl_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_hl_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_hl(sixlowpan_iphc_t *iphc, uint8_t hl) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_hl)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static range_t sixlowpan_iphc_hl(sixlowpan_iphc_t *iphc, uint8_t hl) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_nh_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_iphc_nh_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_nh)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_nh(sixlowpan_iphc_t *iphc, uint8_t nh) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_pl)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static range_t sixlowpan_iphc_pl(void) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_pl_redo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int sixlowpan_iphc_pl_redo(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_pl_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_pl_undo(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_get_range)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static range_t sixlowpan_iphc_tf_get_range(iphc_tf_t tf) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_tf_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_tf_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_tf)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_tf(sixlowpan_iphc_t *iphc, uint32_t *vtf) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_compress)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_iphc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_uncompressed)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_uncompressed(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_compress)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_decompress_nhc)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_decompress_nhc(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_decompress_iphc)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_decompress_iphc(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_decompress_ipv6)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_decompress_ipv6(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_decompress)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_decompress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_ll_derive_dst)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_ll_provide(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_ll_provide)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_ll_provide(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_frame_convert)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_frame_convert(struct sixlowpan_frame *f, struct pico_frame *pf) */
}
END_TEST
START_TEST(tc_sixlowpan_frame_translate)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static struct sixlowpan_frame *sixlowpan_frame_translate(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_frame_frag)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_send(struct pico_device *dev, void *buf, int len) */
}
END_TEST
START_TEST(tc_sixlowpan_frame_tx_next)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST
START_TEST(tc_sixlowpan_frame_tx_stream_start)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST
START_TEST(tc_sixlowpan_send)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST

START_TEST(tc_sixlowpan_poll)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST
START_TEST(tc_pico_sixlowpan_set_prefix)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST
START_TEST(tc_pico_sixlowpan_short_addr_configured)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST
START_TEST(tc_pico_sixlowpan_create)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
    /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST

Suite *pico_suite(void)                       
{
    Suite *s = suite_create("PicoTCP");             

    /* -------------------------------------------------------------------------------- */
    // MARK: MEMORY TCASES
    TCase *TCase_buf_delete = tcase_create("Unit test for buf_delete");
    TCase *TCase_buf_insert = tcase_create("Unit test for buf_insert");
    TCase *TCase_frame_rearrange_ptrs = tcase_create("Unit test for frame_rearrange_ptrs");
    TCase *TCase_frame_buf_insert = tcase_create("Unit test for frame_buf_insert");
    TCase *TCase_frame_buf_prepend = tcase_create("Unit test for frame_buf_prepend");
    TCase *TCase_frame_buf_delete = tcase_create("Unit test for frame_buf_delete");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: IEEE802.15.4
    TCase *TCase_IEEE_EUI64_LE = tcase_create("Unit test for IEEE_EUI64_LE");
    TCase *TCase_ieee_addr_len = tcase_create("Unit test for ieee_addr_len");
    TCase *TCase_IEEE_hdr_len = tcase_create("Unit test for IEEE_hdr_len");
    TCase *TCase_IEEE_len = tcase_create("Unit test for IEEE_len");
    TCase *TCase_IEEE_hdr_buf_len = tcase_create("Unit test for IEEE_hdr_buf_len");
    TCase *TCase_IEEE_process_address = tcase_create("Unit test for IEEE_process_address");
    TCase *TCase_IEEE_process_addresses = tcase_create("Unit test for IEEE_process_addresses");
    TCase *TCase_IEEE_unbuf = tcase_create("Unit test for IEEE_unbuf");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: SIXLOWPAN
    TCase *TCase_sixlowpan_frame_destroy = tcase_create("Unit test for sixlowpan_frame_destroy");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: FLAT (ADDRESSES)
    TCase *TCase_pico_ieee_addr_to_flat = tcase_create("Unit test for pico_ieee_addr_to_flat");
    TCase *TCase_pico_ieee_addr_from_flat = tcase_create("Unit test for pico_ieee_addr_from_flat");
    TCase *TCase_pico_ieee_addr_to_hdr = tcase_create("Unit test for pico_ieee_addr_to_hdr");
    TCase *TCase_pico_ieee_addr_from_hdr = tcase_create("Unit test for pico_ieee_addr_from_hdr");
    
    TCase *TCase_sixlowpan_addr_copy_flat = tcase_create("Unit test for sixlowpan_addr_copy_flat");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: IIDs (ADDRESSES)
    TCase *TCase_sixlowpan_iid_is_derived_64 = tcase_create("Unit test for sixlowpan_iid_is_derived_64");
    TCase *TCase_sixlowpan_iid_is_derived_16 = tcase_create("Unit test for sixlowpan_iid_is_derived_16");
    TCase *TCase_sixlowpan_iid_from_extended = tcase_create("Unit test for sixlowpan_iid_from_extended");
    TCase *TCase_sixlowpan_iid_from_short = tcase_create("Unit test for sixlowpan_iid_from_short");
    TCase *TCase_sixlowpan_addr_from_iid = tcase_create("Unit test for sixlowpan_addr_from_iid");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: 6LoWPAN to IPv6 (ADDRESSES)
    TCase *TCase_sixlowpan_ipv6_derive_local = tcase_create("Unit test for sixlowpan_ipv6_derive_local");
    TCase *TCase_sixlowpan_ipv6_derive_mcast = tcase_create("Unit test for sixlowpan_ipv6_derive_mcast");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: IPv6 to 6LoWPAN (ADDRESSES)
    TCase *TCase_sixlowpan_ll_derive_local = tcase_create("Unit test for sixlowpan_ll_derive_local");
    TCase *TCase_sixlowpan_ll_derive_mcast = tcase_create("Unit test for sixlowpan_ll_derive_mcast");
    TCase *TCase_sixlowpan_ll_derive_nd = tcase_create("Unit test for sixlowpan_ll_derive_nd");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: COMPRESSION
    /* -------------------------------------------------------------------------------- */
    // MARK: LOWPAN_NHC
    TCase *TCase_sixlowpan_nh_is_compressible = tcase_create("Unit test for sixlowpan_nh_is_compressible");
    TCase *TCase_sixlowpan_nhc_udp_ports_undo = tcase_create("Unit test for sixlowpan_nhc_udp_ports_undo");
    TCase *TCase_sixlowpan_nhc_udp_ports = tcase_create("Unit test for sixlowpan_nhc_udp_ports");
    TCase *TCase_sixlowpan_nhc_udp_undo = tcase_create("Unit test for sixlowpan_nhc_udp_undo");
    TCase *TCase_sixlowpan_nhc_udp = tcase_create("Unit test for sixlowpan_nhc_udp");
    TCase *TCase_sixlowpan_nh_from_eid = tcase_create("Unit test for sixlowpan_nh_from_eid");
    TCase *TCase_sixlowpan_nhc_ext_undo = tcase_create("Unit test for sixlowpan_nhc_ext_undo");
    TCase *TCase_sixlowpan_nhc_ext = tcase_create("Unit test for sixlowpan_nhc_ext");
    TCase *TCase_sixlowpan_nhc = tcase_create("Unit test for sixlowpan_nhc");
    TCase *TCase_sixlowpan_nhc_compress = tcase_create("Unit test for sixlowpan_nhc_compress");

    /* -------------------------------------------------------------------------------- */
    // MARK: LOWPAN_IPHC
    TCase *TCase_sixlowpan_iphc_am_undo = tcase_create("Unit test for sixlowpan_iphc_am_undo");
    TCase *TCase_sixlowpan_iphc_mcast_dam = tcase_create("Unit test for sixlowpan_iphc_mcast_dam");
    TCase *TCase_sixlowpan_iphc_dam_undo = tcase_create("Unit test for sixlowpan_iphc_dam_undo");
    TCase *TCase_sixlowpan_iphc_rearrange_mcast = tcase_create("Unit test for sixlowpan_iphc_rearrange_mcast");
    TCase *TCase_sixlowpan_iphc_dam = tcase_create("Unit test for sixlowpan_iphc_dam");
    TCase *TCase_sixlowpan_iphc_sam_undo = tcase_create("Unit test for sixlowpan_iphc_sam_undo");
    TCase *TCase_sixlowpan_iphc_sam = tcase_create("Unit test for sixlowpan_iphc_sam");
    TCase *TCase_sixlowpan_iphc_hl_undo = tcase_create("Unit test for sixlowpan_iphc_hl_undo");
    TCase *TCase_sixlowpan_iphc_hl = tcase_create("Unit test for sixlowpan_iphc_hl");
    TCase *TCase_sixlowpan_iphc_nh_undo = tcase_create("Unit test for sixlowpan_iphc_nh_undo");
    TCase *TCase_sixlowpan_iphc_nh = tcase_create("Unit test for sixlowpan_iphc_nh");
    TCase *TCase_sixlowpan_iphc_pl = tcase_create("Unit test for sixlowpan_iphc_pl");
    TCase *TCase_sixlowpan_iphc_pl_redo = tcase_create("Unit test for sixlowpan_iphc_pl_redo");
    TCase *TCase_sixlowpan_iphc_pl_undo = tcase_create("Unit test for sixlowpan_iphc_pl_undo");
    TCase *TCase_sixlowpan_iphc_get_range = tcase_create("Unit test for sixlowpan_iphc_get_range");
    TCase *TCase_sixlowpan_iphc_tf_undo = tcase_create("Unit test for sixlowpan_iphc_tf_undo");
    TCase *TCase_sixlowpan_iphc_tf = tcase_create("Unit test for sixlowpan_iphc_tf");
    TCase *TCase_sixlowpan_iphc_compress = tcase_create("Unit test for sixlowpan_iphc_compress");
    TCase *TCase_sixlowpan_uncompressed = tcase_create("Unit test for sixlowpan_uncompressed");
    TCase *TCase_sixlowpan_compress = tcase_create("Unit test for sixlowpan_compress");
    TCase *TCase_sixlowpan_decompress_nhc = tcase_create("Unit test for sixlowpan_decompress_nhc");
    TCase *TCase_sixlowpan_decompress_iphc = tcase_create("Unit test for sixlowpan_decompress_iphc");
    TCase *TCase_sixlowpan_decompress_ipv6 = tcase_create("Unit test for sixlowpan_decompress_ipv6");
    TCase *TCase_sixlowpan_decompress = tcase_create("Unit test for sixlowpan_decompress");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: TRANSLATING
    TCase *TCase_sixlowpan_ll_derive_dst = tcase_create("Unit test for sixlowpan_ll_derive_dst");
    TCase *TCase_sixlowpan_ll_provide = tcase_create("Unit test for sixlowpan_ll_provide");
    TCase *TCase_sixlowpan_frame_convert = tcase_create("Unit test for sixlowpan_frame_convert");
    TCase *TCase_sixlowpan_frame_translate = tcase_create("Unit test for sixlowpan_frame_translate");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: FRAGMENTATION
    TCase *TCase_sixlowpan_frame_frag = tcase_create("Unit test for sixlowpan_frame_frag");
    TCase *TCase_sixlowpan_frame_tx_next = tcase_create("Unit test for sixlowpan_frame_tx_next");
    TCase *TCase_sixlowpan_frame_tx_stream_start = tcase_create("Unit test for sixlowpan_frame_tx_stream_start");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: PICO_DEV
    TCase *TCase_sixlowpan_send = tcase_create("Unit test for sixlowpan_send");
    TCase *TCase_sixlowpan_poll = tcase_create("Unit test for sixlowpan_poll");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: API
    TCase *TCase_pico_sixlowpan_set_prefix = tcase_create("Unit test for pico_sixlowpan_set_prefix");
    TCase *TCase_pico_sixlowpan_short_addr_configured = tcase_create("Unit test for pico_sixlowpan_short_addr_configured");
    TCase *TCase_pico_sixlowpan_create = tcase_create("Unit test for pico_sixlowpan_create");

    
    tcase_add_test(TCase_buf_delete, tc_buf_delete);
    suite_add_tcase(s, TCase_buf_delete);
    tcase_add_test(TCase_buf_insert, tc_buf_insert);
    suite_add_tcase(s, TCase_buf_insert);
    tcase_add_test(TCase_frame_rearrange_ptrs, tc_frame_rearrange_ptrs);
    suite_add_tcase(s, TCase_frame_rearrange_ptrs);
    tcase_add_test(TCase_frame_buf_insert, tc_frame_buf_insert);
    suite_add_tcase(s, TCase_frame_buf_insert);
    tcase_add_test(TCase_frame_buf_prepend, tc_frame_buf_prepend);
    suite_add_tcase(s, TCase_frame_buf_prepend);
    tcase_add_test(TCase_frame_buf_delete, tc_frame_buf_delete);
    suite_add_tcase(s, TCase_frame_buf_delete);
    tcase_add_test(TCase_IEEE_EUI64_LE, tc_IEEE_EUI64_LE);
    suite_add_tcase(s, TCase_IEEE_EUI64_LE);
    /* */
    tcase_add_test(TCase_pico_ieee_addr_to_flat, tc_pico_ieee_addr_to_flat);
    suite_add_tcase(s, TCase_pico_ieee_addr_to_flat);
    tcase_add_test(TCase_pico_ieee_addr_from_flat, tc_pico_ieee_addr_from_flat);
    suite_add_tcase(s, TCase_pico_ieee_addr_from_flat);
    tcase_add_test(TCase_pico_ieee_addr_to_hdr, tc_pico_ieee_addr_to_hdr);
    suite_add_tcase(s, TCase_pico_ieee_addr_to_hdr);
    tcase_add_test(TCase_pico_ieee_addr_from_hdr, tc_pico_ieee_addr_from_hdr);
    suite_add_tcase(s, TCase_pico_ieee_addr_from_hdr);
    /* */
    tcase_add_test(TCase_IEEE_hdr_len, tc_IEEE_hdr_len);
    suite_add_tcase(s, TCase_IEEE_hdr_len);
    tcase_add_test(TCase_IEEE_len, tc_IEEE_len);
    suite_add_tcase(s, TCase_IEEE_len);
    tcase_add_test(TCase_IEEE_hdr_buf_len, tc_IEEE_hdr_buf_len);
    suite_add_tcase(s, TCase_IEEE_hdr_buf_len);
    tcase_add_test(TCase_IEEE_process_address, tc_IEEE_process_address);
    suite_add_tcase(s, TCase_IEEE_process_address);
    tcase_add_test(TCase_IEEE_process_addresses, tc_IEEE_process_addresses);
    suite_add_tcase(s, TCase_IEEE_process_addresses);
    tcase_add_test(TCase_IEEE_unbuf, tc_IEEE_unbuf);
    suite_add_tcase(s, TCase_IEEE_unbuf);
    tcase_add_test(TCase_sixlowpan_frame_destroy, tc_sixlowpan_frame_destroy);
    suite_add_tcase(s, TCase_sixlowpan_frame_destroy);
    tcase_add_test(TCase_sixlowpan_addr_copy_flat, tc_sixlowpan_addr_copy_flat);
    suite_add_tcase(s, TCase_sixlowpan_addr_copy_flat);
    tcase_add_test(TCase_sixlowpan_iid_is_derived_64, tc_sixlowpan_iid_is_derived_64);
    suite_add_tcase(s, TCase_sixlowpan_iid_is_derived_64);
    tcase_add_test(TCase_sixlowpan_iid_is_derived_16, tc_sixlowpan_iid_is_derived_16);
    suite_add_tcase(s, TCase_sixlowpan_iid_is_derived_16);
    tcase_add_test(TCase_sixlowpan_iid_from_extended, tc_sixlowpan_iid_from_extended);
    suite_add_tcase(s, TCase_sixlowpan_iid_from_extended);
    tcase_add_test(TCase_sixlowpan_iid_from_short, tc_sixlowpan_iid_from_short);
    suite_add_tcase(s, TCase_sixlowpan_iid_from_short);
    tcase_add_test(TCase_sixlowpan_addr_from_iid, tc_sixlowpan_addr_from_iid);
    suite_add_tcase(s, TCase_sixlowpan_addr_from_iid);
    tcase_add_test(TCase_sixlowpan_ipv6_derive_local, tc_sixlowpan_ipv6_derive_local);
    suite_add_tcase(s, TCase_sixlowpan_ipv6_derive_local);
    tcase_add_test(TCase_sixlowpan_ipv6_derive_mcast, tc_sixlowpan_ipv6_derive_mcast);
    suite_add_tcase(s, TCase_sixlowpan_ipv6_derive_mcast);
    tcase_add_test(TCase_sixlowpan_ll_derive_local, tc_sixlowpan_ll_derive_local);
    suite_add_tcase(s, TCase_sixlowpan_ll_derive_local);
    tcase_add_test(TCase_sixlowpan_ll_derive_mcast, tc_sixlowpan_ll_derive_mcast);
    suite_add_tcase(s, TCase_sixlowpan_ll_derive_mcast);
    tcase_add_test(TCase_sixlowpan_ll_derive_nd, tc_sixlowpan_ll_derive_nd);
    suite_add_tcase(s, TCase_sixlowpan_ll_derive_nd);
    tcase_add_test(TCase_sixlowpan_nh_is_compressible, tc_sixlowpan_nh_is_compressible);
    suite_add_tcase(s, TCase_sixlowpan_nh_is_compressible);
    tcase_add_test(TCase_sixlowpan_nhc_udp_ports_undo, tc_sixlowpan_nhc_udp_ports_undo);
    suite_add_tcase(s, TCase_sixlowpan_nhc_udp_ports_undo);
    tcase_add_test(TCase_sixlowpan_nhc_udp_ports, tc_sixlowpan_nhc_udp_ports);
    suite_add_tcase(s, TCase_sixlowpan_nhc_udp_ports);
    tcase_add_test(TCase_sixlowpan_nhc_udp_undo, tc_sixlowpan_nhc_udp_undo);
    suite_add_tcase(s, TCase_sixlowpan_nhc_udp_undo);
    tcase_add_test(TCase_sixlowpan_nhc_udp, tc_sixlowpan_nhc_udp);
    suite_add_tcase(s, TCase_sixlowpan_nhc_udp);
    tcase_add_test(TCase_sixlowpan_nh_from_eid, tc_sixlowpan_nh_from_eid);
    suite_add_tcase(s, TCase_sixlowpan_nh_from_eid);
    tcase_add_test(TCase_sixlowpan_nhc_ext_undo, tc_sixlowpan_nhc_ext_undo);
    suite_add_tcase(s, TCase_sixlowpan_nhc_ext_undo);
    tcase_add_test(TCase_sixlowpan_nhc_ext, tc_sixlowpan_nhc_ext);
    suite_add_tcase(s, TCase_sixlowpan_nhc_ext);
    tcase_add_test(TCase_sixlowpan_nhc, tc_sixlowpan_nhc);
    suite_add_tcase(s, TCase_sixlowpan_nhc);
    tcase_add_test(TCase_sixlowpan_nhc_compress, tc_sixlowpan_nhc_compress);
    suite_add_tcase(s, TCase_sixlowpan_nhc_compress);
    tcase_add_test(TCase_sixlowpan_iphc_am_undo, tc_sixlowpan_iphc_am_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_am_undo);
    tcase_add_test(TCase_sixlowpan_iphc_mcast_dam, tc_sixlowpan_iphc_mcast_dam);
    suite_add_tcase(s, TCase_sixlowpan_iphc_mcast_dam);
    tcase_add_test(TCase_sixlowpan_iphc_dam_undo, tc_sixlowpan_iphc_dam_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_dam_undo);
    tcase_add_test(TCase_sixlowpan_iphc_rearrange_mcast, tc_sixlowpan_iphc_rearrange_mcast);
    suite_add_tcase(s, TCase_sixlowpan_iphc_rearrange_mcast);
    tcase_add_test(TCase_sixlowpan_iphc_dam, tc_sixlowpan_iphc_dam);
    suite_add_tcase(s, TCase_sixlowpan_iphc_dam);
    tcase_add_test(TCase_sixlowpan_iphc_sam_undo, tc_sixlowpan_iphc_sam_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_sam_undo);
    tcase_add_test(TCase_sixlowpan_iphc_sam, tc_sixlowpan_iphc_sam);
    suite_add_tcase(s, TCase_sixlowpan_iphc_sam);
    tcase_add_test(TCase_sixlowpan_iphc_hl_undo, tc_sixlowpan_iphc_hl_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_hl_undo);
    tcase_add_test(TCase_sixlowpan_iphc_hl, tc_sixlowpan_iphc_hl);
    suite_add_tcase(s, TCase_sixlowpan_iphc_hl);
    tcase_add_test(TCase_sixlowpan_iphc_nh_undo, tc_sixlowpan_iphc_nh_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_nh_undo);
    tcase_add_test(TCase_sixlowpan_iphc_nh, tc_sixlowpan_iphc_nh);
    suite_add_tcase(s, TCase_sixlowpan_iphc_nh);
    tcase_add_test(TCase_sixlowpan_iphc_pl, tc_sixlowpan_iphc_pl);
    suite_add_tcase(s, TCase_sixlowpan_iphc_pl);
    tcase_add_test(TCase_sixlowpan_iphc_pl_redo, tc_sixlowpan_iphc_pl_redo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_pl_redo);
    tcase_add_test(TCase_sixlowpan_iphc_pl_undo, tc_sixlowpan_iphc_pl_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_pl_undo);
    tcase_add_test(TCase_sixlowpan_iphc_get_range, tc_sixlowpan_iphc_get_range);
    suite_add_tcase(s, TCase_sixlowpan_iphc_get_range);
    tcase_add_test(TCase_sixlowpan_iphc_tf_undo, tc_sixlowpan_iphc_tf_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_tf_undo);
    tcase_add_test(TCase_sixlowpan_iphc_tf, tc_sixlowpan_iphc_tf);
    suite_add_tcase(s, TCase_sixlowpan_iphc_tf);
    tcase_add_test(TCase_sixlowpan_iphc_compress, tc_sixlowpan_iphc_compress);
    suite_add_tcase(s, TCase_sixlowpan_iphc_compress);
    tcase_add_test(TCase_sixlowpan_uncompressed, tc_sixlowpan_uncompressed);
    suite_add_tcase(s, TCase_sixlowpan_uncompressed);
    tcase_add_test(TCase_sixlowpan_compress, tc_sixlowpan_compress);
    suite_add_tcase(s, TCase_sixlowpan_compress);
    tcase_add_test(TCase_sixlowpan_decompress_nhc, tc_sixlowpan_decompress_nhc);
    suite_add_tcase(s, TCase_sixlowpan_decompress_nhc);
    tcase_add_test(TCase_sixlowpan_decompress_iphc, tc_sixlowpan_decompress_iphc);
    suite_add_tcase(s, TCase_sixlowpan_decompress_iphc);
    tcase_add_test(TCase_sixlowpan_decompress_ipv6, tc_sixlowpan_decompress_ipv6);
    suite_add_tcase(s, TCase_sixlowpan_decompress_ipv6);
    tcase_add_test(TCase_sixlowpan_decompress, tc_sixlowpan_decompress);
    suite_add_tcase(s, TCase_sixlowpan_decompress);
    tcase_add_test(TCase_sixlowpan_ll_derive_dst, tc_sixlowpan_ll_derive_dst);
    suite_add_tcase(s, TCase_sixlowpan_ll_derive_dst);
    tcase_add_test(TCase_sixlowpan_ll_provide, tc_sixlowpan_ll_provide);
    suite_add_tcase(s, TCase_sixlowpan_ll_provide);
    tcase_add_test(TCase_sixlowpan_frame_convert, tc_sixlowpan_frame_convert);
    suite_add_tcase(s, TCase_sixlowpan_frame_convert);
    tcase_add_test(TCase_sixlowpan_frame_translate, tc_sixlowpan_frame_translate);
    suite_add_tcase(s, TCase_sixlowpan_frame_translate);
    tcase_add_test(TCase_sixlowpan_frame_frag, tc_sixlowpan_frame_frag);
    suite_add_tcase(s, TCase_sixlowpan_frame_frag);
    tcase_add_test(TCase_sixlowpan_frame_tx_next, tc_sixlowpan_frame_tx_next);
    suite_add_tcase(s, TCase_sixlowpan_frame_tx_next);
    tcase_add_test(TCase_sixlowpan_frame_tx_stream_start, tc_sixlowpan_frame_tx_stream_start);
    suite_add_tcase(s, TCase_sixlowpan_frame_tx_stream_start);
    tcase_add_test(TCase_sixlowpan_send, tc_sixlowpan_send);
    suite_add_tcase(s, TCase_sixlowpan_send);
    tcase_add_test(TCase_sixlowpan_poll, tc_sixlowpan_poll);
    suite_add_tcase(s, TCase_sixlowpan_poll);
    tcase_add_test(TCase_pico_sixlowpan_set_prefix, tc_pico_sixlowpan_set_prefix);
    suite_add_tcase(s, TCase_pico_sixlowpan_set_prefix);
    tcase_add_test(TCase_pico_sixlowpan_short_addr_configured, tc_pico_sixlowpan_short_addr_configured);
    suite_add_tcase(s, TCase_pico_sixlowpan_short_addr_configured);
    tcase_add_test(TCase_pico_sixlowpan_create, tc_pico_sixlowpan_create);
    suite_add_tcase(s, TCase_pico_sixlowpan_create);
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
