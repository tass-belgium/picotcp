#include "pico_dev_sixlowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "modules/pico_dev_sixlowpan.c"
#include "check.h"


START_TEST(tc_buf_delete)
{
    /* Works with not allocated buffers as well, since it doesn't free anything */
    uint8_t *str = "Sing Hello, World!";
    uint16_t len = strlen(str) + 1;
    uint16_t nlen = 0;
    
    /* Test removing the Hello-word including the preceding space */
    struct range r = {.offset = 4, .length = 6};
    
    
    printf("*********************** starting %s * \n", __func__);
    
    nlen = buf_delete(str, len, r);
    
    fail_if(strcmp(str, "Sing, World"), "%s didnt't correctly delete chunk!\n", __func__);
    fail_unless(((strlen(str) + 1 - r.length) == nlen), "%s didn't return the right nlen\n", __func__);
    
    /* Try to break it! */
    fail_if(buf_delete(NULL, 4, r), "%s didn't check params!\n", __func__);
    
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_buf_insert)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static void *buf_insert(void *buf, uint16_t len, range_t r) */
}
END_TEST
START_TEST(tc_FRAME_REARRANGE_PTRS)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static inline int FRAME_REARRANGE_PTRS(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_FRAME_BUF_INSERT)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: static uint8_t *FRAME_BUF_INSERT(struct sixlowpan_frame *f, uint8_t *buf, range_t r) */
}
END_TEST
START_TEST(tc_FRAME_BUF_PREPEND)
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
START_TEST(tc_IEEE802154_EUI64_LE)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static void IEEE802154_EUI64_LE(uint8_t EUI64[8]) */
}
END_TEST
START_TEST(tc_IEEE802154_ADDR_LEN)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE802154_ADDR_LEN(IEEE802154_address_mode_t am) */
}
END_TEST
START_TEST(tc_IEEE802154_hdr_len)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE802154_hdr_len(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_IEEE802154_len)
{
    printf("*********************** starting %s * \n", __func__);
    printf("*********************** ending %s * \n", __func__);
   /* TODO: test this: inline static uint8_t IEEE802154_len(struct sixlowpan_frame *f) */
}
END_TEST
START_TEST(tc_IEEE802154_hdr_buf_len)
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
START_TEST(tc_IEEE802154_unbuf)
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
   /* TODO: test this: static range_t sixlowpan_iphc_dam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE802154_address_mode_t dam) */
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
   /* TODO: test this: static range_t sixlowpan_iphc_sam(sixlowpan_iphc_t *iphc, uint8_t *addr, IEEE802154_address_mode_t sam) */
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
    TCase *TCase_FRAME_REARRANGE_PTRS = tcase_create("Unit test for FRAME_REARRANGE_PTRS");
    TCase *TCase_FRAME_BUF_INSERT = tcase_create("Unit test for FRAME_BUF_INSERT");
    TCase *TCase_FRAME_BUF_PREPEND = tcase_create("Unit test for FRAME_BUF_PREPEND");
    TCase *TCase_FRAME_BUF_DELETE = tcase_create("Unit test for FRAME_BUF_DELETE");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: IEEE802.15.4
    TCase *TCase_IEEE802154_EUI64_LE = tcase_create("Unit test for IEEE802154_EUI64_LE");
    TCase *TCase_IEEE802154_ADDR_LEN = tcase_create("Unit test for IEEE802154_ADDR_LEN");
    TCase *TCase_IEEE802154_hdr_len = tcase_create("Unit test for IEEE802154_hdr_len");
    TCase *TCase_IEEE802154_len = tcase_create("Unit test for IEEE802154_len");
    TCase *TCase_IEEE802154_hdr_buf_len = tcase_create("Unit test for IEEE802154_hdr_buf_len");
    TCase *TCase_IEEE802154_process_address = tcase_create("Unit test for IEEE802154_process_address");
    TCase *TCase_IEEE802154_process_addresses = tcase_create("Unit test for IEEE802154_process_addresses");
    TCase *TCase_IEEE802154_unbuf = tcase_create("Unit test for IEEE802154_unbuf");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: SIXLOWPAN
    TCase *TCase_sixlowpan_frame_destroy = tcase_create("Unit test for sixlowpan_frame_destroy");
    
    /* -------------------------------------------------------------------------------- */
    // MARK: FLAT (ADDRESSES)
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
    tcase_add_test(TCase_FRAME_REARRANGE_PTRS, tc_FRAME_REARRANGE_PTRS);
    suite_add_tcase(s, TCase_FRAME_REARRANGE_PTRS);
    tcase_add_test(TCase_FRAME_BUF_INSERT, tc_FRAME_BUF_INSERT);
    suite_add_tcase(s, TCase_FRAME_BUF_INSERT);
    tcase_add_test(TCase_FRAME_BUF_PREPEND, tc_FRAME_BUF_PREPEND);
    suite_add_tcase(s, TCase_FRAME_BUF_PREPEND);
    tcase_add_test(TCase_FRAME_BUF_DELETE, tc_FRAME_BUF_DELETE);
    suite_add_tcase(s, TCase_FRAME_BUF_DELETE);
    tcase_add_test(TCase_IEEE802154_EUI64_LE, tc_IEEE802154_EUI64_LE);
    suite_add_tcase(s, TCase_IEEE802154_EUI64_LE);
    tcase_add_test(TCase_IEEE802154_ADDR_LEN, tc_IEEE802154_ADDR_LEN);
    suite_add_tcase(s, TCase_IEEE802154_ADDR_LEN);
    tcase_add_test(TCase_IEEE802154_hdr_len, tc_IEEE802154_hdr_len);
    suite_add_tcase(s, TCase_IEEE802154_hdr_len);
    tcase_add_test(TCase_IEEE802154_len, tc_IEEE802154_len);
    suite_add_tcase(s, TCase_IEEE802154_len);
    tcase_add_test(TCase_IEEE802154_hdr_buf_len, tc_IEEE802154_hdr_buf_len);
    suite_add_tcase(s, TCase_IEEE802154_hdr_buf_len);
    tcase_add_test(TCase_IEEE802154_process_address, tc_IEEE802154_process_address);
    suite_add_tcase(s, TCase_IEEE802154_process_address);
    tcase_add_test(TCase_IEEE802154_process_addresses, tc_IEEE802154_process_addresses);
    suite_add_tcase(s, TCase_IEEE802154_process_addresses);
    tcase_add_test(TCase_IEEE802154_unbuf, tc_IEEE802154_unbuf);
    suite_add_tcase(s, TCase_IEEE802154_unbuf);
    tcase_add_test(TCase_sixlowpan_frame_destroy, tc_sixlowpan_frame_destroy);
    suite_add_tcase(s, TCase_sixlowpan_frame_destroy);
    tcase_add_test(TCase_sixlowpan_addr_copy_flat, tc_sixlowpan_addr_copy_flat);
    suite_add_tcase(s, TCase_sixlowpan_addr_copy_flat);
    tcase_add_test(TCase_sixlowpan_iid_is_derived_64, tc_sixlowpan_iid_is_derived_64);
    suite_add_tcase(s, TCase_sixlowpan_iid_is_derived_64);
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
