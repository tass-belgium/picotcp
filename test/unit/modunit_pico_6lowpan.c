#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "modules/pico_6lowpan.c"
#include "check.h"

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
                printf("\n> RESULTS:\n");                                       \
            } while (0)
#define FAIL_UNLESS(cond, i, s, ...)                                           \
            do { \
            printf("TEST %2d: "s"... ", (i)++, ##__VA_ARGS__);                 \
            if (cond) {                                                        \
                printf(" SUCCESS\n");                                          \
            } else {                                                           \
                printf(" FAILED\n");                                           \
            }                                                                  \
            fflush(stdout);                                                    \
            fail_unless((cond), s, ##__VA_ARGS__);                             \
            }while(0)
#define FAIL_IF(cond, i, s, ...)                                               \
            do { \
            printf("TEST %2d: "s"... ", (i)++, ##__VA_ARGS__);                 \
            if (!cond) {                                                       \
                printf(" SUCCESS\n");                                          \
            } else {                                                           \
                printf(" FAILED\n");                                           \
            }                                                                  \
            fflush(stdout);                                                    \
            fail_if((cond), s, ##__VA_ARGS__);                                 \
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
    for (i = 0; i < len; i++) {
        if (i % 8 != 0)
            printf("%02x ", buf[i]);
        else {
            printf("\n%02x ", buf[i]);
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
    pico_string_to_ipv6("2aaa:1234:5678:9145:0102:0304:0506:0708", b.addr);
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
    struct pico_ip6 a, b, c;
    pico_string_to_ipv6("2aaa:1234:5678:9123:0:0ff:fe00:0105", a.addr);
    pico_string_to_ipv6("2aaa:1234:5678:9145:0102:0304:0506:0708", b.addr);
    struct iphc_ctx *found = NULL;

    STARTING();
    pico_stack_init();

    TRYING("To find a prefix in the context tree\n");
    ret = ctx_insert(a, 13, 54);
    found = ctx_lookup(b);
    RESULTS();
    FAIL_UNLESS(!ret, test, "Inserting should've succeeded, return 0. ret = %d", ret);
    FAIL_UNLESS(found, test, "Should've found the context");
    FAIL_UNLESS(found->id == 13, test, "Should've found the correct ctx, ID = %d", ret);

    ENDING(test);
}
END_TEST

START_TEST(tc_ctx_remove)
{
    int test = 1, ret = 0;
    struct pico_ip6 a, b, c;
    pico_string_to_ipv6("2aaa:1234:5678:9123:0:0ff:fe00:0105", a.addr);
    pico_string_to_ipv6("2aaa:1234:5678:9145:0102:0304:0506:0708", b.addr);
    struct iphc_ctx *found = NULL;

    STARTING();
    pico_stack_init();

    TRYING("To find a prefix in the context tree\n");
    ret = ctx_insert(a, 13, 54);
    ctx_remove(b);
    found = ctx_lookup(b);
    RESULTS();
    FAIL_UNLESS(!ret, test, "Inserting should've succeeded, return 0. ret = %d", ret);
    FAIL_UNLESS(NULL == found, test, "Shouldn't have found the ctx again");

    ENDING(test);
}
END_TEST


/*******************************************************************************
 *  IPHC
 ******************************************************************************/

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
    ret = compressor_vtf(ori_fl, comp, iphc);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS(iphc[0] == TF_ELIDED_FL, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
    FAIL_UNLESS(1 == ret, test, "Should've returned size of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(comp_fl, comp, (size_t)ret), test, "inline formatting not correct");
    memset(comp, 0, 4);
    memset(iphc, 0, 3);

    TRYING("With DSCP set. No matter ECN, should elide flow label and reformat tc\n");
    ret = compressor_vtf(ori_dscp, comp, iphc);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS(iphc[0] == TF_ELIDED_FL, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
    FAIL_UNLESS(1 == ret, test, "Should've returned size of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(comp_dscp, comp, (size_t)ret), test, "inline formatting not correct");
    memset(comp, 0, 4);
    memset(iphc, 0, 3);

    TRYING("With FL set. If DSCP is not set, can be compressed to 3 bytes\n");
    ret = compressor_vtf(ori_notc, comp, iphc);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS(iphc[0] == TF_ELIDED_DSCP, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
    FAIL_UNLESS(3 == ret, test, "Should've returned size of 3, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(comp_notc, comp, (size_t)ret), test, "inline formatting not correct");
    memset(comp, 0, 4);
    memset(iphc, 0, 3);

    TRYING("With evt. set. Should elide nothing and reformat traffic class\n");
    ret = compressor_vtf(ori_inline, comp, iphc);
    OUTPUT();
    dbg_buffer(comp, 4);
    RESULTS();
    FAIL_UNLESS(iphc[0] == TF_INLINE, test, "Should've set the IPHC-bits correctly, %02X", iphc[0]);
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
    ret = decompressor_vtf(ori, comp_fl, iphc_fl);
    OUTPUT();
    dbg_buffer(ori, 4);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned length of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(ori_fl, ori, (size_t)4), test, "Should've formatted IPv6 VTF-field correctly");
    memset(ori, 0, 4);

    TRYING("With flow label compression but with IPHC inline\n");
    ret = decompressor_vtf(ori, comp_dscp, iphc_dscp);
    OUTPUT();
    dbg_buffer(ori, 4);
    RESULTS();
    FAIL_UNLESS(1 == ret, test, "Should've returned length of 1, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(ori_dscp, ori, (size_t)4), test, "Should've formatted IPv6 VTF-field correctly");
    memset(ori, 0, 4);

    TRYING("With flow label inline and DSCP compressed\n");
    ret = decompressor_vtf(ori, comp_notc, iphc_notc);
    OUTPUT();
    dbg_buffer(ori, 4);
    RESULTS();
    FAIL_UNLESS(3 == ret, test, "Should've returned length of 3, ret = %d", ret);
    FAIL_UNLESS(0 == memcmp(ori_notc, ori, (size_t)4), test, "Should've formatted IPv6 VTF-field correctly");
    memset(ori, 0, 4);

    TRYING("With evt. inline\n");
    ret = decompressor_vtf(ori, comp_inline, iphc_inline);
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
    ret = compressor_nh(&nxthdr, &comp, &iphc);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_HOPBYHOP\n");
    nxthdr = PICO_IPV6_EXTHDR_HOPBYHOP;
    ret = compressor_nh(&nxthdr, &comp, &iphc);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_ROUTING\n");
    nxthdr = PICO_IPV6_EXTHDR_ROUTING;
    ret = compressor_nh(&nxthdr, &comp, &iphc);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_FRAG\n");
    nxthdr = PICO_IPV6_EXTHDR_FRAG;
    ret = compressor_nh(&nxthdr, &comp, &iphc);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = EXT_DSTOPT\n");
    nxthdr = PICO_IPV6_EXTHDR_DESTOPT;
    ret = compressor_nh(&nxthdr, &comp, &iphc);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == NH_COMPRESSED, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    TRYING("With next header = TCP\n");
    nxthdr = PICO_PROTO_TCP;
    ret = compressor_nh(&nxthdr, &comp, &iphc);
    OUTPUT();
    printf("IPHC: %02X", iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc == 0, test, "Should've set the IPHC bits correctly");
    FAIL_UNLESS(0 == comp, test, "Shouldn't have changed compressed");

    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_nh)
{
    int test = 1;
    uint8_t iphc = NH_COMPRESSED;
    uint8_t ori = 0;
    uint8_t ret = 0;

    STARTING();

    compressor_dummy(NULL, NULL, NULL);

    TRYING("With NH bit set\n");
    ret = decompressor_nh(&ori, NULL, &iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(NH_COMPRESSED == ori, test, "Should've filled ori with NH_COMPRESSED");

    TRYING("With NH bit cleared\n");
    iphc = 0;
    ret = decompressor_nh(&ori, NULL, &iphc);
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(0 == ori, test, "Should've filled ori with 0");

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
    ret = compressor_hl(&ori, &comp, &iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(HL_COMPRESSED_1 == iphc, test, "Should've set IPHC bits correctly");

    TRYING("With HL set to 64\n");
    ori = 64;
    ret = compressor_hl(&ori, &comp, &iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(HL_COMPRESSED_64 == iphc, test, "Should've set IPHC bits correctly");

    TRYING("With HL set to 255\n");
    ori = 255;
    ret = compressor_hl(&ori, &comp, &iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(HL_COMPRESSED_255 == iphc, test, "Should've set IPHC bits correctly");

    TRYING("With random HL\n");
    ori = 153;
    ret = compressor_hl(&ori, &comp, &iphc);
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
    ret = decompressor_hl(&ori, &comp, &iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d",ret );
    FAIL_UNLESS(1 == ori, test, "Should filled in correct hop limit");

    TRYING("HL 64 compressed\n");
    iphc = HL_COMPRESSED_64;
    ret = decompressor_hl(&ori, &comp, &iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d",ret );
    FAIL_UNLESS(64 == ori, test, "Should filled in correct hop limit");

    TRYING("HL 255 compressed\n");
    iphc = HL_COMPRESSED_255;
    ret = decompressor_hl(&ori, &comp, &iphc);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d",ret );
    FAIL_UNLESS(255 == ori, test, "Should filled in correct hop limit");

    TRYING("HL not compressed\n");
    iphc = 0;
    comp = 125;
    ret = decompressor_hl(&ori, &comp, &iphc);
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
    union pico_ll_addr addr = { .pan = { .addr.data = {1,2,3,4,5,6,7,8}, .mode = AM_802154_SHORT }};
    struct pico_device dev = { .mode = LL_MODE_IEEE802154 };
    pico_string_to_ipv6("ff00:0:0:0:0:0:e801:100", ip.addr);
    pico_string_to_ipv6("fe80:0:0:0:0102:0304:0506:0708", local.addr);
    pico_string_to_ipv6("fe80:0:0:0:0:0ff:fe00:0105", local3.addr);
    pico_string_to_ipv6("fe80:0:0:0:0:0ff:fe00:0102", local2.addr);

    STARTING();

    TRYING("With MAC derived address\n");
    ret = addr_comp_mode(iphc, local2, addr, &dev, SRC_SHIFT);
    OUTPUT();
    dbg_buffer(iphc, 3);
    RESULTS();
    FAIL_UNLESS(0 == ret, test, "Should've returned 0, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & SRC_COMPRESSED, test, "Should've set IPHC bits correctly, %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With wrong device link layer mode\n");
    dev.mode = LL_MODE_ETHERNET;
    ret = addr_comp_mode(iphc, local2, addr, &dev, SRC_SHIFT);
    RESULTS();
    FAIL_UNLESS(-1 == ret, test, "Shoudl've returned error (-1), ret = %d", ret);
    memset(iphc, 0, 3);

    TRYING("With non MAC derived extended address\n");
    dev.mode = LL_MODE_IEEE802154;
    ret = addr_comp_mode(iphc, local, addr, &dev, SRC_SHIFT);
    FAIL_UNLESS(8 == ret, test, "Should've return 8, ret = %d", ret);
    FAIL_UNLESS(SRC_COMPRESSED_64 == iphc[1], test, "Should've set the IPHC bits correctly, iphc = %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With non MAC derived short address\n");
    ret = addr_comp_mode(iphc, local3, addr, &dev, SRC_SHIFT);
    FAIL_UNLESS(2 == ret, test, "should've returned 2, ret = %d", ret);
    FAIL_UNLESS(SRC_COMPRESSED_16 == iphc[1], test, "Should've set the IPHC bits correctly, iphc = %02X", iphc[1]);

    ENDING(test);
}
END_TEST

START_TEST(tc_addr_comp_state)
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
    ret = addr_comp_state(iphc, ip, 1);
    RESULTS();
    FAIL_UNLESS(COMP_MULTICAST == ret, test, "Should've returned COMP_MULTICAST, ret = %d", ret);
    FAIL_UNLESS(!iphc[1], test, "Shouldn't have set any IPHC bytes, iphc = %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With link local destination address\n");
    ret = addr_comp_state(iphc, local, 0);
    RESULTS();
    FAIL_UNLESS(COMP_LINKLOCAL == ret, test, "Should've returned COMP_LINKLOCAL, ret = %d", ret);
    FAIL_UNLESS(!iphc[1], test, "Shouldn't have set any IPHC bytes, iphc = %02X", iphc[1]);
    memset(iphc, 0, 3);

    TRYING("With a unicast address where there's no context available for\n");
    ret = addr_comp_state(iphc, local3, 0);
    RESULTS();
    FAIL_UNLESS(COMP_STATELESS == ret, test, "Should've return COMP_STATELESS, ret = %d", ret);
    FAIL_UNLESS(!iphc[1], test, "Shouldn't have set any IPHC bytes, iphc = %02X", iphc[1]);
    memset(iphc, 0,3);

    TRYING("With a unicast address where there's context available for\n");
    ctx_insert(local3, 13, 64);
    ret = addr_comp_state(iphc, local3, 0);
    FAIL_UNLESS(13 == ret, test, "Should've returned CTX ID of 13, ret = %d", ret);
    FAIL_UNLESS(iphc[1] & DST_STATEFUL, test, "Should've set DAC correctly, iphc = %02X", iphc[1]);
    FAIL_UNLESS(iphc[1] & CTX_EXTENSION, test, "Should've set CTX extension bit correctly, iphc = %02X", iphc[1]);

    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_src)
{
    int test = 1;


    STARTING();



    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_src)
{
    int test = 1;


    STARTING();



    ENDING(test);
}
END_TEST

START_TEST(tc_compressor_dst)
{
    int test = 1;


    STARTING();



    ENDING(test);
}
END_TEST

START_TEST(tc_decompressor_dst)
{
    int test = 1;


    STARTING();



    ENDING(test);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_compare_prefix = tcase_create("Unit test for compare_prefix");
    TCase *TCase_compare_ctx = tcase_create("Unit test for compare_ctx");
    TCase *TCase_ctx_lookup = tcase_create("Unit test for ctx_lookup");
    TCase *TCase_ctx_remove = tcase_create("Unit test for ctx_remove");
    TCase *TCase_compressor_vtf = tcase_create("Unit test for compressor_vtf");
    TCase *TCase_decompressor_vtf = tcase_create("Unit test for decompressor_vtf");
    TCase *TCase_compressor_nh = tcase_create("Unit test for compressor_nh");
    TCase *TCase_decompressor_nh = tcase_create("Unit test for decompressor_nh");
    TCase *TCase_compressor_hl = tcase_create("Unit test for compressor_hl");
    TCase *TCase_decompressor_hl = tcase_create("Unit test for decompressor_hl");
    TCase *TCase_addr_comp_state = tcase_create("Unit test for addr_comp_state");
    TCase *TCase_addr_comp_mode = tcase_create("Unit test for addr_comp_mode");
    TCase *TCase_compressor_src = tcase_create("Unit test for compressor_src");
    TCase *TCase_decompressor_src = tcase_create("Unit test for decompressor_src");
    TCase *TCase_compressor_dst = tcase_create("Unit test for compressor_dst");
    TCase *TCase_decompressor_dst = tcase_create("Unit test for decompressor_dst");

/*******************************************************************************
 *  IPHC
 ******************************************************************************/

    tcase_add_test(TCase_compare_prefix, tc_compare_prefix);
    suite_add_tcase(s, TCase_compare_prefix);
    tcase_add_test(TCase_compare_ctx ,tc_compare_ctx);
    suite_add_tcase(s, TCase_compare_ctx);
    tcase_add_test(TCase_ctx_lookup ,tc_ctx_lookup);
    suite_add_tcase(s, TCase_ctx_lookup);
    tcase_add_test(TCase_ctx_remove ,tc_ctx_remove);
    suite_add_tcase(s, TCase_ctx_remove);
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
    tcase_add_test(TCase_addr_comp_state, tc_addr_comp_state);
    suite_add_tcase(s, TCase_addr_comp_state);
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
