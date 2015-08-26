#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "modules/pico_dev_sixlowpan.c"
#include "check.h"


START_TEST(tc_dbg_ipv6)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void dbg_ipv6(const char *pre, struct pico_ip6 *ip) */
}
END_TEST
START_TEST(tc_dbg_mem)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void dbg_mem(const char *pre, void *buf, uint16_t len) */
}
END_TEST
START_TEST(tc_buf_delete)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static uint16_t buf_delete(void *buf, uint16_t len, range_t r) */
}
END_TEST
START_TEST(tc_*buf_insert)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void *buf_insert(void *buf, uint16_t len, range_t r) */
}
END_TEST
START_TEST(tc_int)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static inline int FRAME_REARRANGE_PTRS(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_*FRAME_BUF_INSERT)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static uint8_t *FRAME_BUF_INSERT(struct sixlowpan_frame *f, uint8_t *buf, range_t r) */
}
END_TEST
START_TEST(tc_*FRAME_BUF_PREPEND)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static uint8_t *FRAME_BUF_PREPEND(struct sixlowpan_frame *f, uint8_t *buf, uint16_t len) */
}
END_TEST
START_TEST(tc_FRAME_BUF_DELETE)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int FRAME_BUF_DELETE(struct sixlowpan_frame *f, uint8_t *buf, range_t r, uint16_t offset) */
}
END_TEST
START_TEST(tc_void)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static void IEEE802154_EUI64_LE(uint8_t EUI64[8]) */
}
END_TEST
START_TEST(tc_uint8_t)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE802154_ADDR_LEN(IEEE802154_address_mode_t am) */
}
END_TEST
START_TEST(tc_uint8_t)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE802154_hdr_len(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_uint8_t)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE802154_len(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_uint8_t)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE802154_hdr_buf_len(IEEE802154_hdr_t *hdr) */
}
END_TEST
START_TEST(tc_IEEE802154_process_address)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void IEEE802154_process_address(uint8_t *buf, struct pico_sixlowpan_addr *addr, IEEE802154_address_mode_t am) */
}
END_TEST
START_TEST(tc_IEEE802154_process_addresses)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void IEEE802154_process_addresses(IEEE802154_hdr_t *hdr, struct pico_sixlowpan_addr *dst, struct pico_sixlowpan_addr *src) */
}
END_TEST
START_TEST(tc_sixlowpan_frame)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static struct sixlowpan_frame *IEEE802154_unbuf(struct pico_device *dev, uint8_t *buf, uint8_t len) */
}
END_TEST
START_TEST(tc_sixlowpan_frame_destroy)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void sixlowpan_frame_destroy(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_int)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int UNUSED sixlowpan_iid_is_derived_64(uint8_t in[8]) */
}
END_TEST
START_TEST(tc_int)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int sixlowpan_iid_is_derived_16(uint8_t in[8]) */
}
END_TEST
START_TEST(tc_int)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static int sixlowpan_iid_from_extended(struct pico_sixlowpan_addr_ext addr, uint8_t out[8]) */
}
END_TEST
START_TEST(tc_int)
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
START_TEST(tc_sixlowpan_ipv6_derive_mcast)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_ipv6_derive_mcast(iphc_dam_mcast_t am, uint8_t *addr) */
}
END_TEST
START_TEST(tc_sixlowpan_nhc_compress)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static frame_status_t sixlowpan_nhc_compress(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_am_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_am_undo(iphc_am_t am, ipv6_addr_id_t id, struct pico_sixlowpan_addr addr, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_range_t)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static range_t sixlowpan_iphc_mcast_dam(iphc_dam_mcast_t am) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_dam_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_dam_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_rearrange_mcast)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_rearrange_mcast(uint8_t *addr, sixlowpan_iphc_t *iphc) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_dam)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_dam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE802154_address_mode_t dam) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_sam_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_sam_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_sam)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static range_t sixlowpan_iphc_sam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE802154_address_mode_t sam) */
}
END_TEST
START_TEST(tc_sixlowpan_iphc_hl_undo)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_iphc_hl_undo(sixlowpan_iphc_t *iphc, struct sixlowpan_frame *f) */
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
START_TEST(tc_range_t)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static range_t sixlowpan_iphc_pl(void) */
}
END_TEST
START_TEST(tc_int)
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
START_TEST(tc_range_t)
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
START_TEST(tc_sixlowpan_frame)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static struct sixlowpan_frame *sixlowpan_frame_translate(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_sixlowpan_send)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_send(struct pico_device *dev, void *buf, int len) */
}
END_TEST
START_TEST(tc_sixlowpan_poll)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static int sixlowpan_poll(struct pico_device *dev, int loop_score) */
}
END_TEST


Suite *pico_suite(void)                       
{
    Suite *s = suite_create("PicoTCP");             

    TCase *TCase_dbg_ipv6 = tcase_create("Unit test for dbg_ipv6");
    TCase *TCase_dbg_mem = tcase_create("Unit test for dbg_mem");
    TCase *TCase_buf_delete = tcase_create("Unit test for buf_delete");
    TCase *TCase_*buf_insert = tcase_create("Unit test for *buf_insert");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_*FRAME_BUF_INSERT = tcase_create("Unit test for *FRAME_BUF_INSERT");
    TCase *TCase_*FRAME_BUF_PREPEND = tcase_create("Unit test for *FRAME_BUF_PREPEND");
    TCase *TCase_FRAME_BUF_DELETE = tcase_create("Unit test for FRAME_BUF_DELETE");
    TCase *TCase_void = tcase_create("Unit test for void");
    TCase *TCase_uint8_t = tcase_create("Unit test for uint8_t");
    TCase *TCase_uint8_t = tcase_create("Unit test for uint8_t");
    TCase *TCase_uint8_t = tcase_create("Unit test for uint8_t");
    TCase *TCase_uint8_t = tcase_create("Unit test for uint8_t");
    TCase *TCase_IEEE802154_process_address = tcase_create("Unit test for IEEE802154_process_address");
    TCase *TCase_IEEE802154_process_addresses = tcase_create("Unit test for IEEE802154_process_addresses");
    TCase *TCase_sixlowpan_frame = tcase_create("Unit test for sixlowpan_frame");
    TCase *TCase_sixlowpan_frame_destroy = tcase_create("Unit test for sixlowpan_frame_destroy");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_sixlowpan_addr_from_iid = tcase_create("Unit test for sixlowpan_addr_from_iid");
    TCase *TCase_sixlowpan_ipv6_derive_mcast = tcase_create("Unit test for sixlowpan_ipv6_derive_mcast");
    TCase *TCase_sixlowpan_nhc_compress = tcase_create("Unit test for sixlowpan_nhc_compress");
    TCase *TCase_sixlowpan_iphc_am_undo = tcase_create("Unit test for sixlowpan_iphc_am_undo");
    TCase *TCase_range_t = tcase_create("Unit test for range_t");
    TCase *TCase_sixlowpan_iphc_dam_undo = tcase_create("Unit test for sixlowpan_iphc_dam_undo");
    TCase *TCase_sixlowpan_iphc_rearrange_mcast = tcase_create("Unit test for sixlowpan_iphc_rearrange_mcast");
    TCase *TCase_sixlowpan_iphc_dam = tcase_create("Unit test for sixlowpan_iphc_dam");
    TCase *TCase_sixlowpan_iphc_sam_undo = tcase_create("Unit test for sixlowpan_iphc_sam_undo");
    TCase *TCase_sixlowpan_iphc_sam = tcase_create("Unit test for sixlowpan_iphc_sam");
    TCase *TCase_sixlowpan_iphc_hl_undo = tcase_create("Unit test for sixlowpan_iphc_hl_undo");
    TCase *TCase_sixlowpan_iphc_hl = tcase_create("Unit test for sixlowpan_iphc_hl");
    TCase *TCase_sixlowpan_iphc_nh_undo = tcase_create("Unit test for sixlowpan_iphc_nh_undo");
    TCase *TCase_sixlowpan_iphc_nh = tcase_create("Unit test for sixlowpan_iphc_nh");
    TCase *TCase_range_t = tcase_create("Unit test for range_t");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_sixlowpan_iphc_pl_undo = tcase_create("Unit test for sixlowpan_iphc_pl_undo");
    TCase *TCase_range_t = tcase_create("Unit test for range_t");
    TCase *TCase_sixlowpan_iphc_tf_undo = tcase_create("Unit test for sixlowpan_iphc_tf_undo");
    TCase *TCase_sixlowpan_iphc_tf = tcase_create("Unit test for sixlowpan_iphc_tf");
    TCase *TCase_sixlowpan_iphc_compress = tcase_create("Unit test for sixlowpan_iphc_compress");
    TCase *TCase_sixlowpan_uncompressed = tcase_create("Unit test for sixlowpan_uncompressed");
    TCase *TCase_sixlowpan_compress = tcase_create("Unit test for sixlowpan_compress");
    TCase *TCase_sixlowpan_decompress_nhc = tcase_create("Unit test for sixlowpan_decompress_nhc");
    TCase *TCase_sixlowpan_decompress_iphc = tcase_create("Unit test for sixlowpan_decompress_iphc");
    TCase *TCase_sixlowpan_decompress_ipv6 = tcase_create("Unit test for sixlowpan_decompress_ipv6");
    TCase *TCase_sixlowpan_decompress = tcase_create("Unit test for sixlowpan_decompress");
    TCase *TCase_sixlowpan_ll_provide = tcase_create("Unit test for sixlowpan_ll_provide");
    TCase *TCase_sixlowpan_frame_convert = tcase_create("Unit test for sixlowpan_frame_convert");
    TCase *TCase_sixlowpan_frame = tcase_create("Unit test for sixlowpan_frame");
    TCase *TCase_sixlowpan_send = tcase_create("Unit test for sixlowpan_send");
    TCase *TCase_sixlowpan_poll = tcase_create("Unit test for sixlowpan_poll");


    tcase_add_test(TCase_dbg_ipv6, tc_dbg_ipv6);
    suite_add_tcase(s, TCase_dbg_ipv6);
    tcase_add_test(TCase_dbg_mem, tc_dbg_mem);
    suite_add_tcase(s, TCase_dbg_mem);
    tcase_add_test(TCase_buf_delete, tc_buf_delete);
    suite_add_tcase(s, TCase_buf_delete);
    tcase_add_test(TCase_*buf_insert, tc_*buf_insert);
    suite_add_tcase(s, TCase_*buf_insert);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_*FRAME_BUF_INSERT, tc_*FRAME_BUF_INSERT);
    suite_add_tcase(s, TCase_*FRAME_BUF_INSERT);
    tcase_add_test(TCase_*FRAME_BUF_PREPEND, tc_*FRAME_BUF_PREPEND);
    suite_add_tcase(s, TCase_*FRAME_BUF_PREPEND);
    tcase_add_test(TCase_FRAME_BUF_DELETE, tc_FRAME_BUF_DELETE);
    suite_add_tcase(s, TCase_FRAME_BUF_DELETE);
    tcase_add_test(TCase_void, tc_void);
    suite_add_tcase(s, TCase_void);
    tcase_add_test(TCase_uint8_t, tc_uint8_t);
    suite_add_tcase(s, TCase_uint8_t);
    tcase_add_test(TCase_uint8_t, tc_uint8_t);
    suite_add_tcase(s, TCase_uint8_t);
    tcase_add_test(TCase_uint8_t, tc_uint8_t);
    suite_add_tcase(s, TCase_uint8_t);
    tcase_add_test(TCase_uint8_t, tc_uint8_t);
    suite_add_tcase(s, TCase_uint8_t);
    tcase_add_test(TCase_IEEE802154_process_address, tc_IEEE802154_process_address);
    suite_add_tcase(s, TCase_IEEE802154_process_address);
    tcase_add_test(TCase_IEEE802154_process_addresses, tc_IEEE802154_process_addresses);
    suite_add_tcase(s, TCase_IEEE802154_process_addresses);
    tcase_add_test(TCase_sixlowpan_frame, tc_sixlowpan_frame);
    suite_add_tcase(s, TCase_sixlowpan_frame);
    tcase_add_test(TCase_sixlowpan_frame_destroy, tc_sixlowpan_frame_destroy);
    suite_add_tcase(s, TCase_sixlowpan_frame_destroy);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_sixlowpan_addr_from_iid, tc_sixlowpan_addr_from_iid);
    suite_add_tcase(s, TCase_sixlowpan_addr_from_iid);
    tcase_add_test(TCase_sixlowpan_ipv6_derive_mcast, tc_sixlowpan_ipv6_derive_mcast);
    suite_add_tcase(s, TCase_sixlowpan_ipv6_derive_mcast);
    tcase_add_test(TCase_sixlowpan_nhc_compress, tc_sixlowpan_nhc_compress);
    suite_add_tcase(s, TCase_sixlowpan_nhc_compress);
    tcase_add_test(TCase_sixlowpan_iphc_am_undo, tc_sixlowpan_iphc_am_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_am_undo);
    tcase_add_test(TCase_range_t, tc_range_t);
    suite_add_tcase(s, TCase_range_t);
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
    tcase_add_test(TCase_range_t, tc_range_t);
    suite_add_tcase(s, TCase_range_t);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_sixlowpan_iphc_pl_undo, tc_sixlowpan_iphc_pl_undo);
    suite_add_tcase(s, TCase_sixlowpan_iphc_pl_undo);
    tcase_add_test(TCase_range_t, tc_range_t);
    suite_add_tcase(s, TCase_range_t);
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
    tcase_add_test(TCase_sixlowpan_ll_provide, tc_sixlowpan_ll_provide);
    suite_add_tcase(s, TCase_sixlowpan_ll_provide);
    tcase_add_test(TCase_sixlowpan_frame_convert, tc_sixlowpan_frame_convert);
    suite_add_tcase(s, TCase_sixlowpan_frame_convert);
    tcase_add_test(TCase_sixlowpan_frame, tc_sixlowpan_frame);
    suite_add_tcase(s, TCase_sixlowpan_frame);
    tcase_add_test(TCase_sixlowpan_send, tc_sixlowpan_send);
    suite_add_tcase(s, TCase_sixlowpan_send);
    tcase_add_test(TCase_sixlowpan_poll, tc_sixlowpan_poll);
    suite_add_tcase(s, TCase_sixlowpan_poll);
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
