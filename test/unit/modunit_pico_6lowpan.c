#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "pico_dev_radiotest.c"
#include "modules/pico_6lowpan_ll.c"
#include "modules/pico_6lowpan.c"
#include "pico_6lowpan_ll.h"
#include "check.h"

#include "pico_config.h"
#include "pico_frame.h"
#include "pico_device.h"
#include "pico_protocol.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_dns_client.h"

#include "pico_ethernet.h"
#include "pico_6lowpan.h"
#include "pico_802154.h"
#include "pico_olsr.h"
#include "pico_aodv.h"
#include "pico_eth.h"
#include "pico_arp.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_icmp4.h"
#include "pico_icmp6.h"
#include "pico_igmp.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "heap.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*******************************************************************************
*  MACROS
******************************************************************************/

#define STARTING()                                                             \
        printf("*********************** STARTING %s ***\n", __func__);     \
        fflush(stdout)
#define TRYING(s, ...)                                                         \
        printf("\n=== TRYING %s: " s, __func__, ##__VA_ARGS__);             \
        fflush(stdout)
#define OUTPUT()                                                               \
        do {                                                               \
            printf("\n> OUTPUT:\n");                                       \
        } while (0)
#define RESULTS()                                                              \
        do {                                                               \
            printf("\n> RESULTS:\n");                                      \
        } while (0)
#define FAIL_UNLESS(cond, i, s, ...)                                           \
        do { \
        char str[80] = { 0 };                                             \
        snprintf(str, 80, "TEST %2d: "s"...", (i)++,  ##__VA_ARGS__);     \
        printf("%s",str);                                                       \
        if (cond) {                                                        \
            printf("%-*s %s\n", (int)(80 - strlen(str) - 12), "", "[SUCCESS]");   \
        } else {                                                           \
            printf("%-*s %s\n", (int)(80 - strlen(str) - 12), "", "[FAILED]");    \
        }                                                                  \
        fflush(stdout);                                                    \
        fail_unless((int)(intptr_t)cond, s, ##__VA_ARGS__);                             \
        }while(0)
#define FAIL_IF(cond, i, s, ...)                                               }\
        do { \
        char str[80] = { 0 };                                             \
        snprintf(str, 80, "TEST %2d: "s"...", (i)++,  ##__VA_ARGS__);     \
        printf(str);                                                       \
        if (!cond) {                                                        \
            printf("%-*s %s\n", (int)(80 - strlen(str) - 12), "", "[SUCCESS]");   \
        } else {                                                           \
            printf("%-*s %s\n", (int)(80 - strlen(str) - 12), "", "[FAILED]");    \
        }                                                                  \
        fflush(stdout);                                                    \
       fail_if((int)(intptr_t)(cond), s, ##__VA_ARGS__);                                 \
        }while(0)
#define ENDING(i)                                                              \
        printf("*********************** ENDING %s *** NUMBER OF TESTS: %d\n",\
                __func__, ((i)-1));                                         \
        fflush(stdout)
#define DBG(s, ...)                                                            \
        printf(s, ##__VA_ARGS__);                                          \
        fflush(stdout)
static void
dbg_buffer(uint8_t *buf, size_t len)
{
    int i = 0;
    printf("Buffer:");
    for (i = 0; i < (int)len; i++) {
        if (i % 8 != 0)
            printf("0x%02x, ", buf[i]);
        else {
            printf("\n0x%02x, ", buf[i]);
        }
    }
    printf("\n");
}

/*******************************************************************************
*  CTX
******************************************************************************/

START_TEST(tc_compare_prefix)
{
    int test = 1, ret = 0;
    struct pico_ip6 a, b, c;
    pico_string_to_ipv6("2aaa:1234:5678:9123:0:0ff:fe00:0105", a.addr);
    pico_string_to_ipv6("2aaa:1234:5678:9143:0102:0304:0506:0708", b.addr);
    pico_string_to_ipv6("2aaa:1234:5678:9156:0102:0304:0506:0708", c.addr);

    STARTING();

    TRYING("With 2 equal prexixes\n");
    ret = compare_prefix(a.addr, b.addr, 54);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Prefixes are equal, should've returned 0, ret = %d",ret);

    TRYING("With b > a\n");
    ret = compare_prefix(a.addr, b.addr, 60);
    RESULTS();
    FAIL_UNLESS(ret, test, "Prefixes are not equal, shouldn't have returned 0, ret = %d",ret);

    TRYING("With c > b\n");
    ret = compare_prefix(b.addr, c.addr, 64);
    RESULTS();
    FAIL_UNLESS(ret, test, "Prefixes are not equal, shouldn't have returned 0, ret = %d",ret);

    ENDING(test);
}
END_TEST

START_TEST(tc_compare_ctx)
{
    int test = 1, ret = 0;
    struct pico_ip6 a, b, c;
    struct iphc_ctx ca, cb, cc;
    pico_string_to_ipv6("2aaa:1234:5678:9123:0:0ff:fe00:0105", a.addr);
    pico_string_to_ipv6("2aaa:1234:5678:9145:0102:0304:0506:0708", b.addr);
    pico_string_to_ipv6("2aaa:1234:5678:9156:0102:0304:0506:0708", c.addr);
    ca.prefix = a;
    ca.size = 54;
    cb.prefix = b;
    cc.prefix = c;

    STARTING();

    TRYING("With 2 equal ctx's\n");
    ret = compare_ctx(&ca, &cb);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Prefixes are equal, should've returned 0, ret = %d", ret);

    ca.size = 60;
    TRYING("With b > a\n");
    ret = compare_ctx(&ca, &cb);
    RESULTS();
    FAIL_UNLESS(ret, test, "Prefixes are not equal, shouln'r return 0, ret = %d", ret);

    cb.size = 64;
    TRYING("With b > c\n");
    ret = compare_ctx(&cb, &cc);
    RESULTS();
    FAIL_UNLESS(ret, test, "Prefixes are not equal, shouldn't return 0, ret = %d", ret);

    ENDING(test);
}
END_TEST

START_TEST(tc_ctx_lookup)
{
    int test = 1, ret = 0;
    struct pico_ip6 a, b;
    struct iphc_ctx *found = NULL;
    pico_string_to_ipv6("2aaa:1234:5678:9123:0:0ff:fe00:0105", a.addr);
    pico_string_to_ipv6("2aaa:1234:5678:9145:0102:0304:0506:0708", b.addr);

    STARTING();
    pico_stack_init();

    TRYING("To find a prefix in the context tree\n");
    ret = ctx_insert(a, 13, 54, 0, PICO_IPHC_CTX_COMPRESS, NULL);
    found = ctx_lookup(b);
    RESULTS();
    FAIL_UNLESS(!ret, test, "Inserting should've succeeded, return 0. ret = %d", ret);
    FAIL_UNLESS(found, test, "Should've found the context");
    FAIL_UNLESS(found->id == 13, test, "Should've found the correct ctx, ID = %d", ret);

    ENDING(test);
}
END_TEST

/*******************************************************************************
*  IPHC
******************************************************************************/

#ifdef PICO_6LOWPAN_IPHC_ENABLED

START_TEST(tc_compressor_vtf)
{
    int test = 1, ret = 0;
    uint8_t ori_fl[] = {0x64,0x00,0x00,0x00};
    uint8_t ori_dscp[] = {0x62,0x00,0x00,0x00};
    uint8_t ori_notc[] = {0x60,0x0f,0xed,0xcb};
    uint8_t ori_inline[] = {0x6f,0xaf,0xed,0xcb};
    uint8_t comp_fl[] = {0x40};
    uint8_t comp_dscp[] = {0x20};
    uint8_t comp_notc[] = {0x0f,0xed,0xcb};
    uint8_t comp_inline[] = {0xfa,0x0f,0xed,0xcb};
    uint8_t comp[4] = {0, 0, 0, 0};
    uint8_t iphc[3] = {0, 0, 0};

    STARTING();

    TRYING("With ECN set. No matter DSCP, should elide flow label and reformat tc\n");
    ret = compressor_vtf(ori_fl, comp, iphc, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS((iphc[0] & TF_ELIDED) == TF_ELIDED_FL, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
    FAIL_UNLESS(1 == ret, test, "Should've returned size of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(comp_fl, comp, (size_t)ret), test, "inline formatting not correct");
    memset(comp, 0, 4);
    memset(iphc, 0, 3);

    TRYING("With DSCP set. No matter ECN, should elide flow label and reformat tc\n");
    ret = compressor_vtf(ori_dscp, comp, iphc, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS((iphc[0] & TF_ELIDED) == TF_ELIDED_FL, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
    FAIL_UNLESS(1 == ret, test, "Should've returned size of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(comp_dscp, comp, (size_t)ret), test, "inline formatting not correct");
    memset(comp, 0, 4);
    memset(iphc, 0, 3);

    TRYING("With FL set. If DSCP is not set, can be compressed to 3 bytes\n");
    ret = compressor_vtf(ori_notc, comp, iphc, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS((iphc[0] & TF_ELIDED) == TF_ELIDED_DSCP, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
    FAIL_UNLESS(3 == ret, test, "Should've returned size of 3, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(comp_notc, comp, (size_t)ret), test, "inline formatting not correct");
    memset(comp, 0, 4);
    memset(iphc, 0, 3);

    TRYING("With evt. set. Should elide nothing and reformat traffic class\n");
    ret = compressor_vtf(ori_inline, comp, iphc, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS((iphc[0] & TF_ELIDED) == TF_INLINE, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
    FAIL_UNLESS(4 == ret, test, "Should've returned size of 4, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(comp_inline, comp, (size_t)ret), test, "inline formatting not correct");
    memset(comp, 0, 4);
    memset(iphc, 0, 3);

    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_vtf)
{
    int test = 1, ret = 0;
    uint8_t ori_fl[] = {0x64,0x00,0x00,0x00};
    uint8_t ori_dscp[] = {0x62,0x00,0x00,0x00};
    uint8_t ori_notc[] = {0x60,0x0f,0xed,0xcb};
    uint8_t ori_inline[] = {0x6f,0xaf,0xed,0xcb};
    uint8_t comp_fl[] = {0x40};
    uint8_t comp_dscp[] = {0x20};
    uint8_t comp_notc[] = {0x0f,0xed,0xcb};
    uint8_t comp_inline[] = {0xfa,0x0f,0xed,0xcb};
    uint8_t ori[4] = {0};
    uint8_t iphc_fl[3] = {TF_ELIDED_FL, 0,0};
    uint8_t iphc_dscp[3] = {TF_ELIDED_FL, 0,0};
    uint8_t iphc_notc[3] = {TF_ELIDED_DSCP, 0,0};
    uint8_t iphc_inline[3] = {TF_INLINE, 0,0};

    STARTING();

    TRYING("With flow label compressed\n");
    ret = decompressor_vtf(ori, comp_fl, iphc_fl, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(ori, 4);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned length of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(ori_fl, ori, (size_t)4), test, "Should've formatted IPv6 VTF-field correctly");
    memset(ori, 0, 4);

    TRYING("With flow label compression but with IPHC inline\n");
    ret = decompressor_vtf(ori, comp_dscp, iphc_dscp, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(ori, 4);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned length of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(ori_dscp, ori, (size_t)4), test, "Should've formatted IPv6 VTF-field correctly");
    memset(ori, 0, 4);

    TRYING("With flow label inline and DSCP compressed\n");
    ret = decompressor_vtf(ori, comp_notc, iphc_notc, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(ori, 4);
    RESULTS();
    FAIL_UNLESS(3 == ret, test, "Should've returned length of 3, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(ori_notc, ori, (size_t)4), test, "Should've formatted IPv6 VTF-field correctly");
    memset(ori, 0, 4);

    TRYING("With evt. inline\n");
    ret = decompressor_vtf(ori, comp_inline, iphc_inline, NULL, NULL, NULL);
    OUTPUT();
    dbg_buffer(ori, 4);
    RESULTS();
    FAIL_UNLESS(4 == ret, test, "Should've returned length of 4, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(ori_inline, ori, (size_t)4), test, "Should've formatted IPv6 VTF-field correctly");
    memset(ori, 0, 4);

    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_nh)
{
    int test = 1;
    uint8_t nxthdr = PICO_PROTO_UDP;
    uint8_t iphc = 0;
    uint8_t comp = 0;
    int ret = 0;

    STARTING();

    TRYING("With next header = UDP\n");
    ret = compressor_nh(&nxthdr, &comp, &iphc, NULL, NULL, NULL);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_HOPBYHOP\n");
    nxthdr = PICO_IPV6_EXTHDR_HOPBYHOP;
    ret = compressor_nh(&nxthdr, &comp, &iphc, NULL, NULL, NULL);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_ROUTING\n");
    nxthdr = PICO_IPV6_EXTHDR_ROUTING;
    ret = compressor_nh(&nxthdr, &comp, &iphc, NULL, NULL, NULL);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_FRAG\n");
    nxthdr = PICO_IPV6_EXTHDR_FRAG;
    ret = compressor_nh(&nxthdr, &comp, &iphc, NULL, NULL, NULL);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_DSTOPT\n");
    nxthdr = PICO_IPV6_EXTHDR_DESTOPT;
    ret = compressor_nh(&nxthdr, &comp, &iphc, NULL, NULL, NULL);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = TCP\n");
    nxthdr = PICO_PROTO_TCP;
    ret = compressor_nh(&nxthdr, &comp, &iphc, NULL, NULL, NULL);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == 0, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(PICO_PROTO_TCP == comp, test, "Shouldn't have changed compressed");

    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_nh)
{
    int test = 1;
    uint8_t iphc = NH_COMPRESSED;
    uint8_t ori = 0;
    int8_t ret = 0;
    uint8_t comp = PICO_PROTO_TCP;

    STARTING();

    TRYING("With NH bit set\n");
    ret = decompressor_nh(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(0 == ori, test, "Should've filled ori with NH_COMPRESSED");

    TRYING("With NH bit cleared\n");
    iphc = 0;
    ret = decompressor_nh(&ori, &comp, &iphc, NULL, NULL, NULL);
    FAIL_UNLESS(1 == ret, test, "Should've returned 1, ret = %d", ret);
    FAIL_UNLESS(PICO_PROTO_TCP == ori, test, "Should've filled ori with PICO_PROTO_TCP");

    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_hl)
{
    int test = 1;
    uint8_t iphc = 0;
    uint8_t ori = 1;
    uint8_t comp;
    int ret = 0;

    STARTING();

    TRYING("With HL set to 1\n");
    ret = compressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(HL_COMPRESSED_1 == iphc, test, "Should've set IPHC bits correctly");

    TRYING("With HL set to 64\n");
    ori = 64;
    ret = compressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(HL_COMPRESSED_64 == iphc, test, "Should've set IPHC bits correctly");

    TRYING("With HL set to 255\n");
    ori = 255;
    ret = compressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(HL_COMPRESSED_255 == iphc, test, "Should've set IPHC bits correctly");

    TRYING("With random HL\n");
    ori = 153;
    ret = compressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned 1, ret = %d",ret);
    FAIL_UNLESS(0 == iphc, test, "Should've set IPHC bits correctly");

    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_hl)
{
    int test = 1;
    uint8_t iphc = HL_COMPRESSED_1;
    uint8_t ori = 0;
    uint8_t comp = 0;
    int ret = 0;

    STARTING();

    TRYING("HL 1 compressed\n");
    ret = decompressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d",ret );
    FAIL_UNLESS(1 == ori, test, "Should filled in correct hop limit");

    TRYING("HL 64 compressed\n");
    iphc = HL_COMPRESSED_64;
    ret = decompressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d",ret );
    FAIL_UNLESS(64 == ori, test, "Should filled in correct hop limit");

    TRYING("HL 255 compressed\n");
    iphc = HL_COMPRESSED_255;
    ret = decompressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d",ret );
    FAIL_UNLESS(255 == ori, test, "Should filled in correct hop limit");

    TRYING("HL not compressed\n");
    iphc = 0;
    comp = 125;
    ret = decompressor_hl(&ori, &comp, &iphc, NULL, NULL, NULL);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned 0, ret = %d",ret );
    FAIL_UNLESS(125 == ori, test, "Should filled in correct hop limit");

    ENDING(test);
}
END_TEST

START_TEST(tc_addr_comp_mode)
{
    uint8_t iphc[3] = { 0 };
    int test = 1, ret = 0;
    struct pico_ip6 ip;
    struct pico_ip6 local;
    struct pico_ip6 local2;
    struct pico_ip6 local3;
    union pico_ll_addr addr = { .pan = { .addr.data = {1,2,3,4,5,6,7,8}, .mode = AM_6LOWPAN_SHORT }};
    struct pico_device dev = { .mode = LL_MODE_IEEE802154 };
    pico_string_to_ipv6("ff00:0:0:0:0:0:e801:100", ip.addr);
    pico_string_to_ipv6("fe80:0:0:0:0102:0304:0506:0708", local.addr);
    pico_string_to_ipv6("fe80:0:0:0:0:0ff:fe00:0105", local3.addr);
    pico_string_to_ipv6("fe80:0:0:0:0:0ff:fe00:0102", local2.addr);

    STARTING();

    pico_stack_init();

    TRYING("With MAC derived address\n");
    ret = addr_comp_mode(iphc, &local2, addr, &dev, SRC_SHIFT);
    OUTPUT();
    dbg_buffer(iphc, 3);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & SRC_COMPRESSED, test, "Should've set IPHC bits correctly, %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With wrong device link layer mode\n");
    dev.mode = LL_MODE_ETHERNET;
    ret = addr_comp_mode(iphc, &local2, addr, &dev, SRC_SHIFT);
    RESULTS();
    FAIL_UNLESS(-1 == ret, test, "Shoudl've returned error (-1), ret = %d", ret);
    memset(iphc, 0, 3);

    TRYING("With non MAC derived extended address\n");
    dev.mode = LL_MODE_IEEE802154;
    ret = addr_comp_mode(iphc, &local, addr, &dev, SRC_SHIFT);
    FAIL_UNLESS(8 == ret, test, "Should've return 8, ret = %d", ret);
    FAIL_UNLESS(SRC_COMPRESSED_64 == iphc[1], test, "Should've set the IPHC bits correctly, iphc = %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With non MAC derived short address\n");
    ret = addr_comp_mode(iphc, &local3, addr, &dev, SRC_SHIFT);
    FAIL_UNLESS(2 == ret, test, "should've returned 2, ret = %d", ret);
    FAIL_UNLESS(SRC_COMPRESSED_16 == iphc[1], test, "Should've set the IPHC bits correctly, iphc = %02X", iphc[1]);

    ENDING(test);
}
END_TEST

START_TEST(tc_addr_comp_prefix)
{
    int test = 1, ret = 0;
    uint8_t iphc[3] = { 0 };
    struct pico_ip6 ip;
    struct pico_ip6 local;
    struct pico_ip6 local3;
    pico_string_to_ipv6("ff00:0:0:0:0:0:e801:100", ip.addr);
    pico_string_to_ipv6("fe80:0:0:0:0102:0304:0506:0708", local.addr);
    pico_string_to_ipv6("2aaa:0:0:0:0:0ff:fe00:0105", local3.addr);

    STARTING();

    pico_stack_init();

    TRYING("With MCAST address\n");
    ret = addr_comp_prefix(iphc, &ip, 1);
    RESULTS();
    FAIL_UNLESS(COMP_MULTICAST == ret, test, "Should've returned COMP_MULTICAST, ret = %d", ret);
    FAIL_UNLESS(!iphc[1], test, "Shouldn't have set any IPHC bytes, iphc = %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With link local destination address\n");
    ret = addr_comp_prefix(iphc, &local, 0);
    RESULTS();
    FAIL_UNLESS(COMP_LINKLOCAL == ret, test, "Should've returned COMP_LINKLOCAL, ret = %d", ret);
    FAIL_UNLESS(!iphc[1], test, "Shouldn't have set any IPHC bytes, iphc = %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With a unicast address where there's no context available for\n");
    ret = addr_comp_prefix(iphc, &local3, 0);
    RESULTS();
    FAIL_UNLESS(COMP_STATELESS == ret, test, "Should've return COMP_STATELESS, ret = %d", ret);
    FAIL_UNLESS(!iphc[1], test, "Shouldn't have set any IPHC bytes, iphc = %02X", iphc[1]);
    memset(iphc, 0,3);

    TRYING("With a unicast address where there's context available for\n");
    ctx_insert(local3, 13, 64, 0, PICO_IPHC_CTX_COMPRESS, NULL);
    ret = addr_comp_prefix(iphc, &local3, 0);
    FAIL_UNLESS(13 == ret, test, "Should've returned CTX ID of 13, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & DST_STATEFUL, test, "Should've set DAC correctly, iphc = %02X", iphc[1]);
    FAIL_UNLESS(iphc[1] & CTX_EXTENSION, test, "Should've set CTX extension bit correctly, iphc = %02X", iphc[1]);

    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_src)
{
    int test = 1;
    struct pico_ip6 unspec = {{ 0 }};
    struct pico_ip6 ll_mac = {{0xfe,0x80,0,0,0,0,0,0  ,1,2,3,4,5,6,7,8}};
    struct pico_ip6 ll_nmac_16 = {{0xfe,0x80,0,0,0,0,0,0  ,0,0,0,0xff,0xfe,0,0x12,0x34}};
    struct pico_ip6 ll_nmac_64 = {{0xfe,0x80,0,0,0,0,0,0 ,8,7,6,5,4,3,2,1}};
    struct pico_ip6 ip_ctx = {{0x2a,0xaa,0,0,0,0,0,0  ,1,2,3,4,5,6,7,8}};
    struct pico_ip6 ip_stateless = {{0x2a,0xbb,0,0,0,0,0,0  ,1,2,3,4,5,6,7,8}};
    union pico_ll_addr mac = { .pan = {.addr.data = {3,2,3,4,5,6,7,8}, .mode = AM_6LOWPAN_EXT } };
    struct pico_device dev = { 0 };
    int ret = 0;

    uint8_t iphc[3] = { 0, 0, 0 };
    uint8_t buf[PICO_SIZE_IP6] = { 0 };

    dev.mode = LL_MODE_IEEE802154;
    STARTING();
    pico_stack_init();

    TRYING("With unspecified source address, should: set SAC, clear SAM\n");
    ret = compressor_src(unspec.addr, buf, iphc, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(iphc, 3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(16 == ret, test, "Shouldn't elide unspecified address, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & SRC_STATEFUL, test, "Should've set SAC");
    FAIL_UNLESS((iphc[1] & SRC_COMPRESSED) == 0, test, "Should've cleared SAM");

    TRYING("With invalid device, should indicate error\n");
    dev.mode = LL_MODE_ETHERNET;
    ret = compressor_src(ll_mac.addr, buf, iphc, &mac, NULL, &dev);
    RESULTS();
    FAIL_UNLESS(-1 == ret, test, "Should've indicated error, invalid device, ret = %d",ret);

    TRYING("With mac derived address, should elide fully\n");
    dev.mode = LL_MODE_IEEE802154;
    ret = compressor_src(ll_mac.addr, buf, iphc, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(iphc,3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned compressed size of 0, ret = %d", ret);
    FAIL_UNLESS(!(iphc[1] & SRC_STATEFUL), test, "Shoudln't have set SAC");
    FAIL_UNLESS((iphc[1] & SRC_COMPRESSED) == SRC_COMPRESSED, test, "Should set SAM to '11', iphc = %02X", iphc[1]);

    TRYING("With non mac derived 16-bit derivable address\n");
    ret = compressor_src(ll_nmac_16.addr, buf, iphc, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(iphc,3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(2 == ret, test, "Should've returned compressed size of 2, ret = %d", ret);
    FAIL_UNLESS(!(iphc[1] & SRC_STATEFUL), test, "Shouldn't have set SAC");
    FAIL_UNLESS((iphc[1] & SRC_COMPRESSED) == SRC_COMPRESSED_16, test, "Should've set SAM to '10', iphc = %02X", iphc[1]);
    FAIL_UNLESS(0 == memcmp(buf, ll_nmac_16.addr + 14, 2), test, "Should've copied 16 bit of source address inline");

    TRYING("With non mac derived 64-bit derivable address\n");
    ret = compressor_src(ll_nmac_64.addr, buf, iphc, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(iphc,3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(8 == ret, test, "Should've returned compressed size of 8, ret = %d", ret);
    FAIL_UNLESS(!(iphc[1] & SRC_STATEFUL), test, "Shoudln't have set SAC");
    FAIL_UNLESS((iphc[1] & SRC_COMPRESSED) == SRC_COMPRESSED_64, test, "Should've set SAM to '01', iphc = %02X", iphc[1]);
    FAIL_UNLESS(0 == memcmp(buf, ll_nmac_64.addr + 8, 8), test, "Should've copied IID of source address inline");

    TRYING("With context derived address\n");
    pico_stack_init();
    ctx_insert(ip_ctx, 13, 64, 0, PICO_IPHC_CTX_COMPRESS, NULL);
    ret = compressor_src(ip_ctx.addr, buf, iphc, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(iphc, 3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned compressed size of 0, ret = %d", ret);
    FAIL_UNLESS((iphc[1] & SRC_STATEFUL), test, "Shoudl've set SAC");
    FAIL_UNLESS((iphc[1] & SRC_COMPRESSED) == SRC_COMPRESSED, test, "Shoudl've set SAM to '11', iphc = %02X", iphc[1]);
    FAIL_UNLESS((iphc[2] >> SRC_SHIFT) == 13, test, "Should've filled in the context extension correctly, ctx = %02X", iphc[2]);

    TRYING("With stateless compression\n");
    ret = compressor_src(ip_stateless.addr, buf, iphc, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(iphc, 3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(PICO_SIZE_IP6 == ret, test, "Should've returned compressed size of 16, ret = %d",ret);
    FAIL_UNLESS((iphc[1] & SRC_STATEFUL) == 0, test, "Shoudln't have set SAC");
    FAIL_UNLESS((iphc[1] & SRC_COMPRESSED) == 0, test, "Should've set SAM to '00', iphc = %02X", iphc[1]);
    FAIL_UNLESS(0 == memcmp(buf, ip_stateless.addr, PICO_SIZE_IP6), test, "Should've copied the source address inline");

    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_src)
{
    int test = 1;
    int ret = 0;

    union pico_ll_addr mac = { .pan = {.addr.data = {3,2,3,4,5,6,7,8}, .mode = AM_6LOWPAN_EXT } };
    struct pico_device dev;

    /* Stateless compression */
    uint8_t iphc1[] = {0x00, 0x00, 0x00};
    uint8_t buf1[] = {0x2a, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    struct pico_ip6 ip1 = {{0x2a,0xbb,0,0,0,0,0,0  ,1,2,3,4,5,6,7,8}};

    /* With context */
    uint8_t iphc2[] = {0x00, 0xf0, 0xd0};
    uint8_t buf2[] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct pico_ip6 ip2 = {{0x2a,0xaa,0,0,0,0,0,0  ,1,2,3,4,5,6,7,8}};

    /* Link-local non-mac 64-bit derivable address */
    uint8_t iphc4[] = {0x00, 0x10, 0x00};
    uint8_t buf4[] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct pico_ip6 ip4 = {{0xfe,0x80,0,0,0,0,0,0 ,8,7,6,5,4,3,2,1}};

    /* Link-local non-mac 16-bit derivable address */
    uint8_t iphc3[] = {0x00, 0x20, 0x00};
    uint8_t buf3[] = {0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct pico_ip6 ip3 = {{0xfe,0x80,0,0,0,0,0,0  ,0,0,0,0xff,0xfe,0,0x12,0x34}};

    /* Link-local mac derivable address */
    uint8_t iphc5[] = {0x00, 0x30, 0x00};
    uint8_t buf5[] = {0};
    struct pico_ip6 ip5 = {{0xfe,0x80,0,0,0,0,0,0  ,1,2,3,4,5,6,7,8}};

    /* Context non-mac 16-bit derivable address */
    uint8_t iphc6[] = {0x00, 0xE0, 0xd0};
    uint8_t buf6[] = {0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct pico_ip6 ip6 = {{0x2a,0xaa,0,0,0,0,0,0  ,0,0,0,0xff,0xfe,0,0x12,0x34}};

    uint8_t buf[PICO_SIZE_IP6] = { 0 };
    dev.mode = LL_MODE_IEEE802154;

    pico_stack_init();
    STARTING();

    TRYING("With statelessly compressed address\n");
    ret = decompressor_src(buf, buf1, iphc1, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(16 == ret, test, "Should've returned compressed size of 16, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(buf, ip1.addr, PICO_SIZE_IP6), test, "Should've correctly decompressed address");
    memset(buf, 0, PICO_SIZE_IP6);

    TRYING("With context\n");
    pico_stack_init();
    ctx_insert(ip2, 13, 64, 0, PICO_IPHC_CTX_COMPRESS, NULL);
    ret = decompressor_src(buf, buf2, iphc2, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned compressed size of 0, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(buf, ip2.addr, PICO_SIZE_IP6), test, "Shoudld've correctly decompressed addresss");
    memset(buf, 0, PICO_SIZE_IP6);

    TRYING("With link-local non-mac 16-bit derivable address\n");
    ret = decompressor_src(buf, buf3, iphc3, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(2 == ret, test, "Shoudl've returned compressed size of 2, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(buf, ip3.addr, PICO_SIZE_IP6), test, "Shoudld've correctly decompressed addresss");
    memset(buf, 0, PICO_SIZE_IP6);

    TRYING("With link-local non-mac 64-bit derivable address\n");
    ret = decompressor_src(buf, buf4, iphc4, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(8 == ret, test, "Should've returned compressed size of 8, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(buf, ip4.addr, PICO_SIZE_IP6), test, "Should've correctly decompressed address");
    memset(buf, 0, PICO_SIZE_IP6);

    TRYING("With link-local mac based address\n");
    ret = decompressor_src(buf, buf5, iphc5, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned compressed size of 0, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(buf, ip5.addr, PICO_SIZE_IP6), test, "Should've correctly decompressed address");
    memset(buf, 0, PICO_SIZE_IP6);

    TRYING("Context based non-mac 16-bit derivable address\n");
    ret = decompressor_src(buf, buf6, iphc6, &mac, NULL, &dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(2 == ret, test, "Should've returned compressed size of 2, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(buf, ip6.addr, PICO_SIZE_IP6), test, "Should've correctly decompressed addresss");
    memset(buf, 0, PICO_SIZE_IP6);

    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_dst)
{
    int test = 1;
    int ret = 0;

    union pico_ll_addr mac = { .pan = {.addr.data = {3,2,3,4,5,6,7,8}, .mode = AM_6LOWPAN_EXT } };
    struct pico_device dev;

    /* Multicast 48-bit */
    struct pico_ip6 mcast1 = {{0xff,0x12,0,0,0,0,0,0 ,0,0,0,5,4,3,2,1}};
    uint8_t buf1[] = {0x12,5,4,3,2,1};

    /* Multicast 32-bit */
    struct pico_ip6 mcast2 = {{0xFF,0x34,0,0,0,0,0,0 ,0,0,0,0,0,1,2,3}};
    uint8_t buf2[] = {0x34,1,2,3};

    /* Multicast 8-bit */
    struct pico_ip6 mcast3 = {{0xFF,0x02,0,0,0,0,0,0 ,0,0,0,0,0,0,0,5}};
    uint8_t buf3 = 5;

    uint8_t iphc[3] = { 0 };
    uint8_t buf[PICO_SIZE_IP6] = { 0 };

    dev.mode = LL_MODE_IEEE802154;
    STARTING();
    pico_stack_init();

    TRYING("48-bit derivable mcast address\n");
    ret = compressor_dst(mcast1.addr, buf, iphc, NULL, &mac, &dev);
    OUTPUT();
    dbg_buffer(iphc, 3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(6 == ret, test, "Should've returned compressed length of 6, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & DST_MULTICAST, test, "Should've set IPHC mcast-flag");
    FAIL_UNLESS(!(iphc[1] & DST_STATEFUL), test, "Shouldn't have set stateful flag, iphc = %02X", iphc[1]);
    FAIL_UNLESS((iphc[1] & DST_COMPRESSED) == DST_MCAST_48, test, "Should've set DAM to '01', iphc = %02X", iphc[1]);
    FAIL_UNLESS(0 == memcmp(buf1, buf, 6), test, "Shoudl've correctly compressed MCAST 48 address");

    TRYING("32-bit derivable mcast address\n");
    ret = compressor_dst(mcast2.addr, buf, iphc, NULL, &mac, &dev);
    OUTPUT();
    dbg_buffer(iphc, 3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(4 == ret, test, "Should've returned compressed length of 4, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & DST_MULTICAST, test, "Should've set IPHC mcast-flag");
    FAIL_UNLESS(!(iphc[1] & DST_STATEFUL), test, "Shouldn't have set stateful flag, iphc = %02X", iphc[1]);
    FAIL_UNLESS((iphc[1] & DST_COMPRESSED) == DST_MCAST_32, test, "Should've set DAM to '10', iphc = %02X", iphc[1]);
    FAIL_UNLESS(0 == memcmp(buf2, buf, 4), test, "Shoudl've correctly compressed MCAST 32 address");

    TRYING("8-bit derivable mcast address\n");
    ret = compressor_dst(mcast3.addr, buf, iphc, NULL, &mac, &dev);
    OUTPUT();
    dbg_buffer(iphc, 3);
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned compressed length of 1, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & DST_MULTICAST, test, "Should've set IPHC mcast-flag");
    FAIL_UNLESS(!(iphc[1] & DST_STATEFUL), test, "Shouldn't have set stateful flag, iphc = %02X", iphc[1]);
    FAIL_UNLESS((iphc[1] & DST_COMPRESSED) == DST_MCAST_8, test, "Should've set DAM to '11', iphc = %02X", iphc[1]);
    FAIL_UNLESS(buf[0] == buf3, test, "Shoudl've correctly compressed MCAST 32 address");

    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_dst)
{
    int test = 1;
    int ret = 0;

    union pico_ll_addr mac = { .pan = {.addr.data = {3,2,3,4,5,6,7,8}, .mode = AM_6LOWPAN_EXT } };
    struct pico_device dev;

    /* Multicast 48-bit */
    uint8_t iphc1[3] = {0x00, 0x09, 0x00};
    struct pico_ip6 mcast1 = {{0xff,0x12,0,0,0,0,0,0 ,0,0,0,5,4,3,2,1}};
    uint8_t buf1[] = {0x12,5,4,3,2,1};

    /* Multicast 32-bit */
    uint8_t iphc2[3] = {0x00, 0x0a, 0x00};
    struct pico_ip6 mcast2 = {{0xFF,0x34,0,0,0,0,0,0 ,0,0,0,0,0,1,2,3}};
    uint8_t buf2[] = {0x34,1,2,3};

    /* Multicast 8-bit */
    uint8_t iphc3[3] = {0x00, 0x0b, 0x00};
    struct pico_ip6 mcast3 = {{0xFF,0x02,0,0,0,0,0,0 ,0,0,0,0,0,0,0,5}};
    uint8_t buf3[] = {5};

    uint8_t buf[PICO_SIZE_IP6] = { 0 };

    dev.mode = LL_MODE_IEEE802154;
    STARTING();
    pico_stack_init();

    TRYING("48-bit compressed address\n");
    ret = decompressor_dst(buf,buf1,iphc1,NULL, &mac,&dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(6 == ret, test, "Should've returned compressed length of 6, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(mcast1.addr, buf, PICO_SIZE_IP6), test, "Should've correctly decompressed the mcast address");

    TRYING("32-bit compressed address\n");
    ret = decompressor_dst(buf,buf2,iphc2,NULL, &mac,&dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(4 == ret, test, "Should've returned compressed length of 4, ret = %d",ret);
    FAIL_UNLESS(0 == memcmp(mcast2.addr, buf, PICO_SIZE_IP6), test, "Should've correctly decompressed 32-bit mcast address");

    TRYING("8-bit compressed address\n");
    ret = decompressor_dst(buf,buf3, iphc3, NULL, &mac, &dev);
    OUTPUT();
    dbg_buffer(buf, PICO_SIZE_IP6);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned compressed length of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(mcast3.addr, buf, PICO_SIZE_IP6), test, "Should've correctly decompressed 8-bit mcast address");

    ENDING(test);
}
END_TEST
static const unsigned char ipv6_frame[61] = {
0x60, 0x00, 0x00, 0x00, 0x00, 0x15, 0x3c, 0xff, /* `.....<. */
0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x02, 0x80, 0xe1, 0x03, 0x00, 0x00, 0x9d, 0x00, /* ........ */
0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x65, 0x63, /* ......ec */
0x11, 0x00, 0x1e, 0x00, 0x01, 0x02, 0x00, 0x00, /* ........ */
0x4d, 0x4c, 0x4d, 0x4c, 0x00, 0x0d, 0x7b, 0x50, /* MLML..{P */
0xff, 0x00, 0x01, 0x01, 0x08                    /* ..... */
};

static const unsigned char lowpan_frame[18] = {
0x7f, 0x33, 0xe7, 0x02, 0x1e, 0x00, 0xf0,
0x4d, 0x4c, 0x4d, 0x4c, 0x7b, 0x50, 0xff, 0x00,
0x01, 0x01, 0x08
};

static const unsigned char comp_frame[22] = {
0x7f, 0x33, 0xe7, 0x06, 0x1e, 0x00, 0x01, 0x02,
0x00, 0x00, 0xf0, 0x4d, 0x4c, 0x4d, 0x4c, 0x7b,
0x50, 0xff, 0x00, 0x01, 0x01, 0x08
};

START_TEST(tc_compressor_iphc)
{
    int test = 1;
    struct pico_frame *f = pico_frame_alloc(61);
    union pico_ll_addr src = { .pan = {.addr.data = {0x00,0x80,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_EXT } };
    union pico_ll_addr dst = { .pan = {.addr.data = {0x65,0x63,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_SHORT } };
    int compressed_len = 0;
    struct pico_device dev;
    uint8_t *buf = NULL;
    uint8_t nh;

    dev.mode = LL_MODE_IEEE802154;
    memcpy(f->buffer, ipv6_frame, 61);
    f->net_hdr = f->buffer;
    f->transport_hdr = f->buffer + 48;
    f->dev = &dev;
    f->src = src;
    f->dst = dst;

    STARTING();
    pico_stack_init();

    TRYING("To compress a IPv6 frame from a sample capture\n");
    buf = compressor_iphc(f, &compressed_len, &nh);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 42);
    RESULTS();
    FAIL_UNLESS(2 == compressed_len, test, "Should have returned compressed_len of 2, compressed_len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, lowpan_frame, (size_t)compressed_len), test, "Should've compressed frame correctly");
    pico_frame_discard(f);

    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_iphc)
{
    int test = 1;
    struct pico_frame *f = pico_frame_alloc(2);
    union pico_ll_addr src = { .pan = {.addr.data = {0x00,0x80,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_EXT } };
    union pico_ll_addr dst = { .pan = {.addr.data = {0x65,0x63,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_SHORT } };
    struct pico_device dev;
    int compressed_len = 0;
    uint8_t *buf = NULL;
    uint8_t hdr[40] = {
    0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, /* `.....<. */
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x02, 0x80, 0xe1, 0x03, 0x00, 0x00, 0x9d, 0x00, /* ........ */
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x65, 0x63 };
    dev.mode = LL_MODE_IEEE802154;
    memcpy(f->buffer, lowpan_frame, 2);
    f->net_hdr = f->buffer;
    f->dev = &dev;
    f->src = src;
    f->dst = dst;

    STARTING();
    pico_stack_init();

    TRYING("To decompress a 6LoWPAN frame from a sampel capture\n");
    buf = decompressor_iphc(f, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 40);
    RESULTS();
    FAIL_UNLESS(2 == compressed_len, test, "Should've returned compressed_len of 2, compressed_len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, hdr, 40), test, "Should've correctly decompressed the 6LoWPAN frame");
    pico_frame_discard(f);

    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_nhc_udp)
{
    int test = 1;
    struct pico_frame *f = pico_frame_alloc(8);
    int compressed_len = 0;
    uint8_t *buf = NULL;

    uint8_t udp1[8] = {0x4d, 0x4c, 0x4d, 0x4c, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp1[] = {0xf0, 0x4d, 0x4c, 0x4d, 0x4c, 0x7b, 0x50};

    uint8_t udp2[8] = {0xF0, 0xb1, 0xF0, 0xb2, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp2[] = {0xf3, 0x12, 0x7b, 0x50};

    uint8_t udp3[8] = {0xF0, 0xb1, 0x4d, 0x4c, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp3[] = {0xf2, 0xb1, 0x4d, 0x4c, 0x7b, 0x50};

    uint8_t udp4[8] = {0x4d, 0x4c, 0xF0, 0xb2, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp4[] = {0xf1, 0x4d, 0x4c, 0xb2, 0x7b, 0x50};

    f->transport_hdr = f->buffer;

    STARTING();

    TRYING("To compress a UDP header from a sample capture\n");
    memcpy(f->buffer, udp1, 8);
    buf = compressor_nhc_udp(f, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 7);
    RESULTS();
    FAIL_UNLESS(7 == compressed_len, test, "Should've returned compressed_len of 7, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, comp1, 7), test, "Should've correctly compressed UDP header");

    TRYING("To compress a UDP header from a sample capture with both compressible addresses\n");
    memcpy(f->buffer, udp2, 8);
    buf = compressor_nhc_udp(f, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 4);
    RESULTS();
    FAIL_UNLESS(4 == compressed_len, test, "Should've returned compressed_len of 4, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, comp2, 4), test, "should've correctly compressed UDP header");

    TRYING("To compress a UDP header from a sample capture with compressible source\n");
    memcpy(f->buffer, udp3, 8);
    buf = compressor_nhc_udp(f, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 6);
    RESULTS();
    FAIL_UNLESS(6 == compressed_len, test, "Should've returned compressed_len of 6, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, comp3, 6), test, "should've correctly compressed UDP header");

    TRYING("To compress a UDP header from a sample capture with compressible destination\n");
    memcpy(f->buffer, udp4, 8);
    buf = compressor_nhc_udp(f, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 6);
    RESULTS();
    FAIL_UNLESS(6 == compressed_len, test, "Should've returned compressed_len of 6, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, comp4, 6), test, "should've correctly compressed UDP header");


    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_nhc_udp)
{
    int test = 1;
    struct pico_frame *f = pico_frame_alloc(9);
    int compressed_len = 0;
    uint8_t *buf = NULL;

    uint8_t udp1[8] = {0x4d, 0x4c, 0x4d, 0x4c, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp1[] = {0xf0, 0x4d, 0x4c, 0x4d, 0x4c, 0x7b, 0x50};

    uint8_t udp2[8] = {0xF0, 0xb1, 0xF0, 0xb2, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp2[] = {0xf3, 0x12, 0x7b, 0x50};

    uint8_t udp3[8] = {0xF0, 0xb1, 0x4d, 0x4c, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp3[] = {0xf2, 0xb1, 0x4d, 0x4c, 0x7b, 0x50};

    uint8_t udp4[8] = {0x4d, 0x4c, 0xF0, 0xb2, 0x00, 0x0d, 0x7b, 0x50};
    uint8_t comp4[] = {0xf1, 0x4d, 0x4c, 0xb2, 0x7b, 0x50};

    f->transport_hdr = f->buffer;
    f->net_len = PICO_SIZE_IP6HDR;

    STARTING();

    TRYING("To decompress NH_UDP header with inline addresses\n");
    memcpy(f->buffer, comp1, 7);
    f->len = 12;
    buf = decompressor_nhc_udp(f, 0, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 8);
    RESULTS();
    FAIL_UNLESS(7 == compressed_len, test, "Should've returned compressed_len of 7, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, udp1, 8), test, "Should've correctly compressed UDP header");

    TRYING("To decompress NHC_UDP header with both addresses compressed\n");
    memcpy(f->buffer, comp2, 4);
    f->len = 9;
    buf = decompressor_nhc_udp(f, 0, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 8);
    RESULTS();
    FAIL_UNLESS(4 == compressed_len, test, "Should've returned compressed_len of 4, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, udp2, 8), test, "Should've correctly decompressed UDP header");

    TRYING("To decompress NHC_UDP header with both addresses compressed\n");
    memcpy(f->buffer, comp3, 6);
    f->len = 11;
    buf = decompressor_nhc_udp(f, 0, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 8);
    RESULTS();
    FAIL_UNLESS(6 == compressed_len, test, "Should've returned compressed_len of 6, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, udp3, 8), test, "Should've correctly decompressed UDP header");

    TRYING("To decompress NHC_UDP header with both addresses compressed\n");
    memcpy(f->buffer, comp4, 6);
    f->len = 11;
    buf = decompressor_nhc_udp(f, 0, &compressed_len);
    FAIL_UNLESS(buf, test, "Should've at least returned a buffer");
    OUTPUT();
    dbg_buffer(buf, 8);
    RESULTS();
    FAIL_UNLESS(6 == compressed_len, test, "Should've returned compressed_len of 6, len = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, udp4, 8), test, "Should've correctly decompressed UDP header");

    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_nhc_ext)
{
    int test = 1;
    struct pico_frame *f = pico_frame_alloc(9);
    uint8_t nh = PICO_IPV6_EXTHDR_DESTOPT;
    int compressed_len = 0;
    uint8_t *buf = NULL;

    uint8_t ext1[8] = {0x11, 0x00, 0x1e, 0x00, 0x01, 0x02, 0x00, 0x00};
    uint8_t nhc1[8] = {0xe7, 0x06, 0x1e, 0x00, 0x01, 0x02, 0x00, 0x00};

    f->net_hdr = f->buffer;

    STARTING();

    TRYING("With DSTOPT extension header\n");
    memcpy(f->buffer, ext1, 8);
    buf = compressor_nhc_ext(f, &compressed_len, &nh);
    FAIL_UNLESS(buf, test, "Should've at least returend a buffer");
    OUTPUT();
    dbg_buffer(buf, (size_t)compressed_len);
    RESULTS();
    FAIL_UNLESS(8 == compressed_len, test, "Should've returned length of 8, ret = %d", compressed_len);
    FAIL_UNLESS(PICO_PROTO_UDP == nh, test, "Should've updated next header to %02X, ret = %02X", PICO_PROTO_UDP, nh);
    FAIL_UNLESS(0 == memcmp(buf, nhc1, (size_t)compressed_len), test, "Should've correctly compressed next header");

    pico_frame_discard(f);
    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_nhc_ext)
{
    int test = 1;
    struct pico_frame *f = pico_frame_alloc(9);
    int compressed_len = 0, decomp;
    uint8_t *buf = NULL;

    uint8_t ext1[8] = {0x11, 0x00, 0x1e, 0x00, 0x01, 0x02, 0x00, 0x00};
    uint8_t nhc1[8] = {0xe7, 0x02, 0x1e, 0x00, 0xf0 /* udp dispatch */};

    f->net_hdr = f->buffer;

    STARTING();

    TRYING("nhc_ext compressed header with dstopt extension header\n");
    memcpy(f->buffer, nhc1, 5);
    buf = decompressor_nhc_ext(f, &compressed_len, &decomp);
    FAIL_UNLESS(buf, test, "should've at least returend a buffer");
    OUTPUT();
    dbg_buffer(buf, 8);
    RESULTS();
    FAIL_UNLESS(4 == compressed_len, test, "should've returned length of 4, ret = %d", compressed_len);
    FAIL_UNLESS(0 == memcmp(buf, ext1, 8), test, "should've correctly decompressed next header");

    pico_frame_discard(f);
    ENDING(test);
}
END_TEST

START_TEST(tc_pico_iphc_compress)
{
    int test = 1;
    struct pico_frame *f = pico_frame_alloc(61);
    union pico_ll_addr src = { .pan = {.addr.data = {0x00,0x80,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_EXT } };
    union pico_ll_addr dst = { .pan = {.addr.data = {0x65,0x63,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_SHORT } };
    struct pico_device dev;
    struct pico_frame *new = NULL;

    dev.mode = LL_MODE_IEEE802154;
    memcpy(f->buffer, ipv6_frame, 61);
    f->net_hdr = f->buffer;
    f->net_len = 48;
    f->transport_hdr = f->buffer + 48;
    f->transport_len = 8;
    f->len = 61;
    f->dev = &dev;
    f->src = src;
    f->dst = dst;

    STARTING();
    pico_stack_init();

    TRYING("Trying to compress an IPv6 frame from an example capture\n");
    new = pico_iphc_compress(f);
    FAIL_UNLESS(new, test, "Should've at least returned a frame");
    OUTPUT();
    dbg_buffer(new->net_hdr, new->len);
    RESULTS();
    FAIL_UNLESS(22 == new->len, test, "Should have returned length of 22, len = %d", new->len);
    FAIL_UNLESS(0 == memcmp(new->net_hdr, comp_frame, 22), test, "Should've compressed the frame correctly");

    ENDING(test);
}
END_TEST

START_TEST(tc_pico_iphc_decompress)
{
    int test = 0;
    struct pico_frame *f = pico_frame_alloc(61);
    union pico_ll_addr src = { .pan = {.addr.data = {0x00,0x80,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_EXT } };
    union pico_ll_addr dst = { .pan = {.addr.data = {0x65,0x63,0xe1,0x03,0x00,0x00,0x9d,0x00}, .mode = AM_6LOWPAN_SHORT } };
    struct pico_device dev;
    struct pico_frame *new = NULL;

    dev.mode = LL_MODE_IEEE802154;
    memcpy(f->buffer, comp_frame, 22);
    f->net_hdr = f->buffer;
    f->net_len = 22;
    f->len = 22;
    f->dev = &dev;
    f->src = src;
    f->dst = dst;

    STARTING();
    pico_stack_init();

    TRYING("Trying to decompress a 6LoWPAN frame from an example capture\n");
    new = pico_iphc_decompress(f);
    FAIL_UNLESS(new, test, "Should've at least returned a frame");
    OUTPUT();
    dbg_buffer(new->net_hdr, new->len);
    RESULTS();
    FAIL_UNLESS(61 == new->len, test, "Should've returned a length of 61, len = %d", new->len);
    dbg_buffer(new->net_hdr, new->len);
    FAIL_UNLESS(0 == memcmp(new->net_hdr, ipv6_frame, new->len), test, "Should've decompressed the frame correctly");


    ENDING(test);
}
END_TEST
#endif

static struct pico_frame *rx = NULL;
static uint8_t tx[1500];
static int rx_called = 0;
static int tx_called = 0;
static uint8_t tx_len = 0;

int pico_datalink_send(struct pico_frame *f) {
    dbg("Datalink_send called!\n");
    if (++tx_called == 2) {
        memcpy(tx, f->start, f->len);
        OUTPUT();
        dbg("tx: ");
        dbg_buffer(tx, tx_len);
    }

    if (f->dev->eth) {
        /* If device has stack with datalink-layer pass frame through it */
        if (LL_MODE_IEEE802154 == f->dev->mode) {
            return pico_enqueue(pico_proto_6lowpan.q_out, f);
        } else {
            return pico_enqueue(pico_proto_ethernet.q_out, f);
        }
    } else {
        /* non-ethernet: no post-processing needed */
        return pico_sendto_dev(f);
    }
}

int32_t pico_network_receive(struct pico_frame *f)
{
    dbg("Network_receive called!\n");
    if (++rx_called == 2)
        rx = pico_frame_copy(f);

    printf("RCVD frame at network layer \n");
    dbg_buffer(f->buffer, f->buffer_len);
    return (int32_t)f->buffer_len;
}

#define NUM_PING 1

#ifdef PICO_SUPPORT_IPV6
static void cb_ping6(struct pico_icmp6_stats *s)
{
    char host[50];
    pico_ipv6_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=%lu time=%lu ms\n", s->size, host, s->seq,
            s->ttl, (long unsigned int)s->time);
        if (s->seq >= NUM_PING)
            exit(0);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
        exit(1);
    }
}
#endif

static void ping_abort_timer(pico_time now, void *_id)
{
    int *id = (int *) _id;
    IGNORE_PARAMETER(now);
    printf("Ping: aborting...\n");
    pico_icmp6_ping_abort(*id);
}

/* Copy a string until the separator,
   terminate it and return the next index,
   or NULL if it encounters a EOS */
static char *cpy_arg(char **dst, char *str)
{
    char *p, *nxt = NULL;
    char *start = str;
    char *end = start + strlen(start);
    char sep = ',';

    p = str;
    while (p) {
        if ((*p == sep) || (*p == '\0')) {
            *p = (char)0;
            nxt = p + 1;
            if ((*nxt == 0) || (nxt >= end))
                nxt = 0;

            printf("dup'ing %s\n", start);
            *dst = strdup(start);
            break;
        }

        p++;
    }
    return nxt;
}

static void app_ping(char *arg)
{
    char *dest = NULL;
    char *next = NULL;
    char *abort = NULL;
    char *delay = NULL;
    char *asize = NULL;
    static int id;
    int timeout = 0;
    int size = 64;

    next = cpy_arg(&dest, arg);
    if (!dest) {
        fprintf(stderr, "ping needs the following format: ping:dst_addr:[size:[abort after N sec:[wait N sec before start]]]\n");
        exit(255);
    }
    if (next) {
        next = cpy_arg(&asize, next);
        size = atoi(asize);
        if (size <= 0) {
            size = 64; /* Default */
        }
    }

    if (next) {
        next = cpy_arg(&abort, next);
        if (strlen(abort) > 0) {
            printf("Got arg: '%s'\n", abort);
            timeout = atoi(abort);
            if (timeout < 0) {
                fprintf(stderr, "ping needs the following format: ping:dst_addr:[size:[abort after N sec:[wait N sec before start]]]\n");
                exit(255);
            }
            printf("Aborting ping after %d seconds\n", timeout);
        }
    }

    if (next) {
        next = cpy_arg(&delay, next);
        if (strlen(delay) > 0) {
            uint32_t initial_delay = (uint32_t) atoi(delay);
            if (initial_delay > 0) {
                printf("Initial delay: %u seconds\n", initial_delay);
                initial_delay = PICO_TIME_MS() + (initial_delay * 1000);
                while (PICO_TIME_MS() < initial_delay) {
                    pico_stack_tick();
                    usleep(10000);
                }
            }
        }
    }
    printf("Starting ping.\n");

    id = pico_icmp6_ping(dest, NUM_PING, 1000, 10000, size, cb_ping6, NULL);
    if (timeout > 0) {
        printf("Adding abort timer after %d seconds for id %d\n", timeout, id);
        if (!pico_timer_add((pico_time)(timeout * 1000), ping_abort_timer, &id)) {
            printf("Failed to set ping abort timeout, aborting ping\n");
            ping_abort_timer((pico_time)0, &id);
            exit(1);
        }
    }

    /* free copied args */
    if (dest)
        free(dest);

    if (abort)
        free(abort);
}

START_TEST(tc_tx_rx)
{
    int test = 0;
    struct pico_device *dev = NULL;
    uint8_t n_id, n_area0, n_area1;
    struct pico_ip6 myaddr, pan, netmask;
    const char pan_addr[] = "2aaa:abcd::0";
    const char pan_netmask[] = "ffff:ffff:ffff:ffff::0";

    const char *id = "3";
    const char *area0 = "1";
    const char *area1 = "0";
    char *dump = (char *)strdup("build/test/unit_6lowpan.pcap");
    char *arg = (char *)strdup("2aaa:abcd:0000:0000:0200:00aa:ab00:0001,1450,0,1,");

    STARTING();

    n_id = (uint8_t) atoi(id);
    n_area0 = (uint8_t) atoi(area0);
    n_area1 = (uint8_t) atoi(area1);

    /* Initialize picoTCP */
    pico_stack_init();

    pico_string_to_ipv6(pan_addr, myaddr.addr);
    pico_string_to_ipv6(pan_addr, pan.addr);
    pico_string_to_ipv6(pan_netmask, netmask.addr);
    myaddr.addr[8]  = 0x02;
    myaddr.addr[11] = 0xaa;
    myaddr.addr[12] = 0xab;
    myaddr.addr[15] = n_id;

    printf("%d:%d:%d\n", n_id, n_area0, n_area1);
    dev = pico_radiotest_create(n_id, n_area0, n_area1, 1, (char *)dump);
    if (!dev) {
        exit(1);
    }

    printf("Radiotest created.\n");

    /* Add a routable link */
    pico_ipv6_link_add(dev, myaddr, netmask);

    /* Start ping-application */
    app_ping((char *)arg);

    printf("%s: launching PicoTCP loop\n", __FUNCTION__);
    while(!rx) {
        pico_stack_tick();
        usleep(2000);
    }
    OUTPUT();
    dbg("RX: ");
    dbg_buffer(rx->start, rx->len);
    RESULTS();
    tx[0] |= 0x60;
    FAIL_UNLESS(0 == memcmp(rx->start, tx, rx->len), test, "Should've received exactly the same frame as was transmitted");

    ENDING(test);
}
END_TEST

static Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_compare_prefix = tcase_create("Unit test for compare_prefix");
    TCase *TCase_compare_ctx = tcase_create("Unit test for compare_ctx");
    TCase *TCase_ctx_lookup = tcase_create("Unit test for ctx_lookup");

/*******************************************************************************
 *  IPHC
 ******************************************************************************/
#ifdef PICO_6LOWPAN_IPHC_ENABLED
    TCase *TCase_compressor_vtf = tcase_create("Unit test for compressor_vtf");
    TCase *TCase_decompressor_vtf = tcase_create("Unit test for decompressor_vtf");
    TCase *TCase_compressor_nh = tcase_create("Unit test for compressor_nh");
    TCase *TCase_decompressor_nh = tcase_create("Unit test for decompressor_nh");
    TCase *TCase_compressor_hl = tcase_create("Unit test for compressor_hl");
    TCase *TCase_decompressor_hl = tcase_create("Unit test for decompressor_hl");
    TCase *TCase_addr_comp_prefix = tcase_create("Unit test for addr_comp_prefix");
    TCase *TCase_addr_comp_mode = tcase_create("Unit test for addr_comp_mode");
    TCase *TCase_compressor_src = tcase_create("Unit test for compressor_src");
    TCase *TCase_decompressor_src = tcase_create("Unit test for decompressor_src");
    TCase *TCase_compressor_dst = tcase_create("Unit test for compressor_dst");
    TCase *TCase_decompressor_dst = tcase_create("Unit test for decompressor_dst");
    TCase *TCase_compressor_iphc = tcase_create("Unit test for compressor_iphc");
    TCase *TCase_decompressor_iphc = tcase_create("Unit test for decompressor_iphc");
    TCase *TCase_compressor_nhc_udp = tcase_create("Unit test for compressor_nhc_udp");
    TCase *TCase_decompressor_nhc_udp = tcase_create("Unit test for decompressor_nhc_udp");
    TCase *TCase_compressor_nhc_ext = tcase_create("Unit test for compressor_nhc_ext");
    TCase *TCase_decompressor_nhc_ext = tcase_create("Unit test for decompressor_nhc_ext");
    TCase *TCase_pico_iphc_compress = tcase_create("Unit test for pico_iphc_compress");
    TCase *TCase_pico_iphc_decompress = tcase_create("Unit test for pico_iphc_decompress");
#endif

    TCase *TCase_tx_rx = tcase_create("Unit test for tx_rx");

    tcase_add_test(TCase_compare_prefix, tc_compare_prefix);
    suite_add_tcase(s, TCase_compare_prefix);
    tcase_add_test(TCase_compare_ctx ,tc_compare_ctx);
    suite_add_tcase(s, TCase_compare_ctx);
    tcase_add_test(TCase_ctx_lookup ,tc_ctx_lookup);
    suite_add_tcase(s, TCase_ctx_lookup);

/*******************************************************************************
 *  IPHC
 ******************************************************************************/
#ifdef PICO_6LOWPAN_IPHC_ENABLED
    tcase_add_test(TCase_compressor_vtf, tc_compressor_vtf);
    suite_add_tcase(s, TCase_compressor_vtf);
    tcase_add_test(TCase_decompressor_vtf, tc_decompressor_vtf);
    suite_add_tcase(s, TCase_decompressor_vtf);
    tcase_add_test(TCase_compressor_nh, tc_compressor_nh);
    suite_add_tcase(s, TCase_compressor_nh);
    tcase_add_test(TCase_decompressor_nh, tc_decompressor_nh);
    suite_add_tcase(s, TCase_decompressor_nh);
    tcase_add_test(TCase_compressor_hl, tc_compressor_hl);
    suite_add_tcase(s, TCase_compressor_hl);
    tcase_add_test(TCase_decompressor_hl, tc_decompressor_hl);
    suite_add_tcase(s, TCase_decompressor_hl);
    tcase_add_test(TCase_addr_comp_prefix, tc_addr_comp_prefix);
    suite_add_tcase(s, TCase_addr_comp_prefix);
    tcase_add_test(TCase_addr_comp_mode, tc_addr_comp_mode);
    suite_add_tcase(s, TCase_addr_comp_mode);
    tcase_add_test(TCase_compressor_src, tc_compressor_src);
    suite_add_tcase(s, TCase_compressor_src);
    tcase_add_test(TCase_decompressor_src, tc_decompressor_src);
    suite_add_tcase(s, TCase_decompressor_src);
    tcase_add_test(TCase_compressor_dst, tc_compressor_dst);
    suite_add_tcase(s, TCase_compressor_dst);
    tcase_add_test(TCase_decompressor_dst, tc_decompressor_dst);
    suite_add_tcase(s, TCase_decompressor_dst);
    tcase_add_test(TCase_compressor_iphc, tc_compressor_iphc);
    suite_add_tcase(s, TCase_compressor_iphc);
    tcase_add_test(TCase_decompressor_iphc, tc_decompressor_iphc);
    suite_add_tcase(s, TCase_decompressor_iphc);
    tcase_add_test(TCase_compressor_nhc_udp, tc_compressor_nhc_udp);
    suite_add_tcase(s, TCase_compressor_nhc_udp);
    tcase_add_test(TCase_decompressor_nhc_udp, tc_decompressor_nhc_udp);
    suite_add_tcase(s, TCase_decompressor_nhc_udp);
    tcase_add_test(TCase_compressor_nhc_ext, tc_compressor_nhc_ext);
    suite_add_tcase(s, TCase_compressor_nhc_ext);
    tcase_add_test(TCase_decompressor_nhc_ext, tc_decompressor_nhc_ext);
    suite_add_tcase(s, TCase_decompressor_nhc_ext);
    tcase_add_test(TCase_pico_iphc_compress, tc_pico_iphc_compress);
    suite_add_tcase(s, TCase_pico_iphc_compress);
    tcase_add_test(TCase_pico_iphc_decompress, tc_pico_iphc_decompress);
    suite_add_tcase(s, TCase_pico_iphc_decompress);
#endif

    tcase_add_test(TCase_tx_rx ,tc_tx_rx);
    suite_add_tcase(s, TCase_tx_rx);

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
