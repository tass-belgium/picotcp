#include "pico_config.h"
#include "pico_ipv6.h"
#include "pico_icmp6.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_tree.h"
#include "pico_constants.h"
#include "modules/pico_fragments.c"
#include "check.h"

START_TEST(tc_fragments_compare)
{
   uint32_t frag_id_1 = 1;
   uint32_t frag_id_2 = 1;
   pico_fragment_t f1={frag_id_1,PICO_PROTO_IPV4,{0x00000001},{0x00000002},{0},NULL,0};
   pico_fragment_t f2={frag_id_2,PICO_PROTO_IPV4,{0x00000001},{0x00000002},{0},NULL,0};

   /* One of the fragments is NULL */
   fail_unless( fragments_compare(&f1, NULL) == -1);

   /* Fragments are the same */
   fail_unless( fragments_compare(&f1, &f2) == 0);

   /* Frag id is not the same */
   f1.frag_id++;
   fail_unless( fragments_compare(&f1, &f2) > 0);
   f2.frag_id = f1.frag_id;

   /* Proto is not the same */
   f1.proto = PICO_PROTO_IPV6;
   fail_unless( fragments_compare(&f1, &f2) > 0);
   f1.proto = PICO_PROTO_IPV4;

   /* ipv4 src/dest address */
   fail_unless( fragments_compare(&f1, &f2) == 0);

   f1.src.ip4.addr++;
   fail_unless( fragments_compare(&f1, &f2) > 0);

   f1.src = f2.src;
   f1.dst.ip4.addr++;
   fail_unless( fragments_compare(&f1, &f2) > 0);
   f1.dst.ip4.addr = f2.dst.ip4.addr;

   /* ipv6 src/dest address */
   memset(f1.src.ip6.addr, 0, sizeof(f1.src.ip6));
   memset(f2.src.ip6.addr, 0, sizeof(f1.src.ip6));
   memset(f1.dst.ip6.addr, 0, sizeof(f1.src.ip6));
   memset(f2.dst.ip6.addr, 0, sizeof(f1.src.ip6));

   fail_unless( fragments_compare(&f1, &f2) == 0);

   f1.src.ip6.addr[0] = 1;
   fail_unless( fragments_compare(&f1, &f2) > 0);
   memset(f1.src.ip6.addr, 0, sizeof(f1.src.ip6));

   f1.dst.ip6.addr[0] = 1;
   fail_unless( fragments_compare(&f1, &f2) > 0);
   memset(f1.src.ip6.addr, 0, sizeof(f1.src.ip6));
}
END_TEST

START_TEST(tc_hole_compare)
{
   pico_hole_t a;
   pico_hole_t b;

   /* One of the holes is NULL */
   fail_unless( hole_compare(&a, NULL) == -1);

   /* Equal holes */
   a.first=1;
   a.last=2;

   b.first=1;
   b.last=2;

   fail_unless( hole_compare(&a, &b) == 0);

   /* Holes are not equal */
   b.first=2;
   b.last=2;

   fail_unless( hole_compare(&a, &b) < 0);

   a.first=3;
   a.last=3;

   fail_unless( hole_compare(&a, &b) > 0);

}
END_TEST
START_TEST(tc_pico_fragment_alloc)
{
    pico_fragment_t *fragment;

    /* One of the sizes is zero */
    fragment = pico_fragment_alloc(0, 1);
    fail_unless( fragment == NULL);
    fragment = NULL;

    /* Both are greater than zero */
    fragment = pico_fragment_alloc(1, 1);
    fail_if( fragment == NULL);
    pico_fragment_free(fragment);
}
END_TEST

START_TEST(tc_first_fragment_received)
{
    struct pico_tree holes;
    pico_hole_t first_hole;

    holes.root = &LEAF;
    holes.compare = hole_compare;

    /* holes is NULL */
    fail_unless( first_fragment_received(NULL) == -1 );

    /* First fragment has NOT arrived, there is a hole that starts at 0 */
    first_hole = (pico_hole_t){ 0, 1000};
    pico_tree_insert(&holes, &first_hole);

    fail_unless( first_fragment_received(&holes) == PICO_IP_FIRST_FRAG_NOT_RECV);
    pico_tree_delete(&holes, &first_hole);

    /* First fragment has arrived, there is NO hole that starts at 0 */
    first_hole = (pico_hole_t){ 500, 1000};
    pico_tree_insert(&holes, &first_hole);
    fail_unless( first_fragment_received(&holes) == PICO_IP_FIRST_FRAG_RECV);

}
END_TEST

START_TEST(tc_pico_fragment_free)
{
    pico_fragment_t *fragment = NULL;

    /* fragment is NULL */
    fail_unless(pico_fragment_free(NULL) == NULL);

    /* fragment is not NULL */
    fragment = pico_fragment_alloc( 1, 1);
    fail_if(!fragment);
    fail_unless(pico_fragment_free(fragment) == NULL);
}
END_TEST

static int pico_timer_add_called = 0;

struct pico_timer *pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    pico_timer_add_called++;
    return NULL;
}

START_TEST(tc_pico_fragment_arrived)
{
    /* We don't check for non fragmented packages,
     *this is handled in pico_ipv4/6_process_frag
     */
    pico_fragment_t *fragment = NULL;
    struct pico_frame *frame = NULL;
    unsigned char *old_frame_buffer = NULL;
    uint16_t offset;
    uint16_t more;
    int frame_transport_size = 2;

    /* Fragment or frame is NULL */
    frame = pico_frame_alloc(frame_transport_size);
    fail_if(!frame);
    fail_unless(pico_fragment_arrived(NULL, frame, offset, more) == -1);
    fragment = pico_fragment_alloc( 1, 1);
    fail_if(!fragment);
    fail_unless(pico_fragment_arrived(fragment, NULL, offset, more) == -1);

    /* First fragment arrived:
     * - is it copied properly?
     * - global fragment timer should be initiated.
     * - fragment->holes should be intantiated and the hole where the recv frame is should be 'deleted'
     * - fragment->frame->buffer should be large enough so no reallocation
     */

    /* Init of frame and fragment
     * pico_fragment_arrived uses the transport_len and hdr
     * we set these to the buffer_len and buffer for testing purposes
     */
    frame->transport_hdr = frame->buffer;
    frame->transport_len = frame_transport_size;
    fragment->frame->transport_len = fragment->frame->buffer_len;
    fragment->frame->transport_hdr = fragment->frame->buffer;

    frame->transport_hdr[0] = '0';
    frame->transport_hdr[1] = '1';

    old_frame_buffer = fragment->frame->buffer;

    /* Is the packet copied to the fragment frame? */
    fail_unless(pico_fragment_arrived(fragment, frame, 0, 1) == frame_transport_size);
    fail_unless(memcmp(fragment->frame->buffer, frame->transport_hdr, frame_transport_size) == 0);

    /* Is the global expiration timer added? */
    fail_unless(pico_timer_add_called == 1);
    pico_timer_add_called = 0;

    /* Are the holes initiated */
    fail_unless(((pico_hole_t*)(fragment->holes.root->keyValue))->first == (frame_transport_size + 1));
    fail_unless(((pico_hole_t*)(fragment->holes.root->keyValue))->last == INFINITY);

    /* Is the buffer reallocated? it was big enough so we expect it not to be */
    fail_unless(old_frame_buffer == fragment->frame->buffer);

    /* Second fragment arrived:
     * - is it copied properly to the fragment->frame?
     * - is the frame properly reallocd?
     * - is the hole deleted from the fragment->holes?
     */

    /* Init of frame and fragment
     * pico_fragment_arrived uses the transport_len and hdr
     * we set these to the buffer_len and buffer for testing purposes
     */
    frame->transport_hdr = frame->buffer;
    frame->transport_len = frame_transport_size;
    old_frame_buffer = fragment->frame->buffer;

    /* Is the packet copied to the fragment frame? */
    fail_unless(pico_fragment_arrived(fragment, frame, frame_transport_size, 1) == frame_transport_size);
    fail_unless(memcmp(fragment->frame->buffer + frame_transport_size, frame->transport_hdr, frame_transport_size) == 0);

    /* There was already a pico expiration timer, so we don't have to add it again. */
    fail_unless(pico_timer_add_called == 0);

    /* Are the holes updated? */
    fail_unless(((pico_hole_t*)(fragment->holes.root->keyValue))->first == (frame_transport_size * 2 + 1));
    fail_unless(((pico_hole_t*)(fragment->holes.root->keyValue))->last == INFINITY);

    /* Is the buffer reallocated? it should be because it was not big enough*/
    fail_unless(old_frame_buffer != fragment->frame->buffer);


    /* Third fragment arrived:
     * - is it copied properly?
     * - is the frame properly reallocd?
     * - is the return value LAST_FRAG_RECV?
     */

    /* Init of frame and fragment
     * pico_fragment_arrived uses the transport_len and hdr
     * we set these to the buffer_len and buffer for testing purposes
     */
    frame->transport_hdr = frame->buffer;
    frame->transport_len = frame_transport_size;
    old_frame_buffer = fragment->frame->buffer;

    /* Is the packet copied to the fragment frame? */
    fail_unless(pico_fragment_arrived(fragment, frame, frame_transport_size * 2, 0) == PICO_IP_LAST_FRAG_RECV);
    fail_unless(memcmp(fragment->frame->buffer + (frame_transport_size * 2), frame->transport_hdr, frame_transport_size) == 0);

    /* There was already a pico expiration timer, so we don't have to add it again. */
    fail_unless(pico_timer_add_called == 0);

    /* Are the holes updated?
     * This was the last packet so fragment->holes
     */
    fail_unless(fragment->holes.root == &LEAF);

    /* Is the buffer reallocated? it should be because it was not big enough*/
    fail_unless(old_frame_buffer != fragment->frame->buffer);

    /* pico_fragment_free(fragment); */
    /* pico_frame_discard(frame); */

}
END_TEST
START_TEST(tc_pico_hole_free)
{
    pico_hole_t *hole = NULL;

    fail_unless(pico_hole_free(NULL) == NULL);
    hole = pico_hole_alloc(0, 100);
    fail_if(!hole);
    fail_unless(pico_hole_free(hole) == NULL);
}
END_TEST
START_TEST(tc_pico_hole_alloc)
{
    pico_hole_t *hole = NULL;

    /* first should be greater than last */
    hole = pico_hole_alloc(100, 0);
    fail_if(hole);

    /* Normal case */
    hole = pico_hole_alloc(0, 100);
    fail_if(!hole);
    pico_hole_free(hole);
}
END_TEST

START_TEST(tc_pico_ip_frag_expired)
{
    /* TODO */
}
END_TEST

START_TEST(tc_pico_ipv4_process_frag)
{
    /* TODO */
}
END_TEST

START_TEST(tc_pico_ipv6_process_frag)
{
    /* TODO */
}
END_TEST

START_TEST(tc_copy_eth_hdr)
{
    struct pico_frame *dst=NULL, *src=NULL;

    fail_unless(copy_eth_hdr(NULL, NULL) == -1);
    dst = pico_frame_alloc(40);
    fail_if(!dst);
    fail_unless(copy_eth_hdr(dst, NULL) == -1);
    src = pico_frame_alloc(40);
    fail_if(!src);
    fail_unless(copy_eth_hdr(NULL, src) == -1);

    /* datalink headers are not set */
    fail_unless(copy_eth_hdr(dst, src) == -1);

    /* datalink headers set */
    dst->datalink_hdr = dst->buffer;
    src->datalink_hdr = src->buffer;
    fail_unless(copy_eth_hdr(dst, src) == 0);

    pico_frame_discard(dst);
    pico_frame_discard(src);
}
END_TEST

START_TEST(tc_copy_ipv6_hdrs_nofrag)
{
    struct pico_frame *dst=NULL, *src=NULL;
    struct pico_ipv6_hdr *srchdr = NULL;
    struct pico_ipv6_hdr *dsthdr = NULL;
    int udp_size = 1;
    int frame_size = PICO_SIZE_ETHHDR + PICO_SIZE_IP6HDR + sizeof(struct pico_ipv6_exthdr) + 8 + udp_size; /* 8 is the size of a fragment header */

    fail_unless(copy_ipv6_hdrs_nofrag(NULL, NULL) == -1);
    dst = pico_frame_alloc(frame_size);
    fail_if(!dst);
    fail_unless(copy_ipv6_hdrs_nofrag(dst, NULL) == -1);
    src = pico_frame_alloc(frame_size);
    fail_if(!src);
    fail_unless(copy_ipv6_hdrs_nofrag(NULL, src) == -1);

    /* Case 1 : net headers are not set */
    fail_unless(copy_eth_hdr(dst, src) == -1);

    /* reset buffers */
    memset(dst->buffer, 0, frame_size);
    memset(src->buffer, 0, frame_size);

    /* Case 2 : net headers set, with fragment header */
    dst->net_hdr = dst->buffer;
    src->net_hdr = src->buffer;
    src->net_len = frame_size - udp_size;
    srchdr = (struct pico_ipv6_hdr *)src->net_hdr;
    dsthdr = (struct pico_ipv6_hdr *)dst->net_hdr;

    /* Set nxthdr to frag header */
    srchdr->nxthdr= PICO_IPV6_EXTHDR_ROUTING;
    srchdr->extensions[1] = 1;  /* Size of the routing header in 8-octets (so 1*8 bytes long) */
    /* Set the nxthdr after the routing header */
    srchdr->extensions[8] = PICO_IPV6_EXTHDR_FRAG;
    srchdr->extensions[16] = PICO_PROTO_UDP;

    /* copy_ipv6_hdrs_nofrag returns the length of the net header, this should not contain the fragment header (so PICO_SIZE-8) */
    fail_unless(copy_ipv6_hdrs_nofrag(dst, src) == src->net_len - 8);

    /* first ip6hdr should be the same */
    fail_unless(memcmp(dst->buffer, src->buffer, PICO_SIZE_IP6HDR) == 0);
    /* routing header should be copied*/
    fail_unless(memcmp(dst->buffer + PICO_SIZE_IP6HDR, src->buffer + PICO_SIZE_IP6HDR, 8) == 0);
    /* Everything past the fragment header should be copied
     *(right after the routing header, so dst should not contain the fragment header)
     */
    fail_unless(memcmp(dst->buffer + PICO_SIZE_IP6HDR + 8, src->buffer +PICO_SIZE_IP6HDR + 8 + 8, frame_size - PICO_SIZE_IP6HDR - 8 - PICO_SIZE_ETHHDR) == 0);

    /* reset buffers */
    memset(dst->buffer, 0, frame_size);
    memset(src->buffer, 0, frame_size);

    /* Case 3: net headers set, WITHOUT fragment header */
    dst->net_hdr = dst->buffer;
    src->net_hdr = src->buffer;
    src->net_len = frame_size - 8 - udp_size; /* We implied a fragment header in the frame_size so -8 for this case */
    srchdr = (struct pico_ipv6_hdr *)src->net_hdr;
    dsthdr = (struct pico_ipv6_hdr *)dst->net_hdr;

    /* Set nxthdr to frag header */
    srchdr->nxthdr= PICO_IPV6_EXTHDR_ROUTING;
    srchdr->extensions[1] = 1;  /* Size of the routing header in 8-octets (so 1*8 bytes long) */
    /* Set the nxthdr after the routing header */
    srchdr->extensions[8] = PICO_ICMP6_ECHO_REQUEST;

    /* copy_ipv6_hdrs_nofrag returns the length of the net header
     * There is no frag header so the length should not have changed.
     */
    fail_unless(copy_ipv6_hdrs_nofrag(dst, src) == src->net_len);

    /* everything but the udp should be copied since there was no fragment header */
    fail_unless(memcmp(dst->buffer, src->buffer, src->net_len) == 0);

    /* Cleanup */
    pico_frame_discard(dst);
    pico_frame_discard(src);
}
END_TEST



Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_fragments_compare = tcase_create("Unit test for fragments_compare");
    TCase *TCase_hole_compare = tcase_create("Unit test for hole_compare");
    TCase *TCase_first_fragment_received = tcase_create("Unit test for first_fragment_received");
    TCase *TCase_pico_fragment_alloc = tcase_create("Unit test for *pico_fragment_alloc");
    TCase *TCase_pico_fragment_free = tcase_create("Unit test for *pico_fragment_free");
    TCase *TCase_pico_fragment_arrived = tcase_create("Unit test for pico_fragment_arrived");
    TCase *TCase_pico_hole_free = tcase_create("Unit test for pico_hole_free");
    TCase *TCase_pico_hole_alloc = tcase_create("Unit test for pico_hole_alloc");
    TCase *TCase_pico_ip_frag_expired = tcase_create("Unit test for pico_ip_frag_expired");
    TCase *TCase_pico_ipv6_process_frag = tcase_create("Unit test for pico_ipv6_process_frag");
    TCase *TCase_pico_ipv4_process_frag = tcase_create("Unit test for pico_ipv4_process_frag");
    TCase *TCase_copy_eth_hdr = tcase_create("Unit test for copy_eth_hdr");
    TCase *TCase_copy_ipv6_hdrs_nofrag = tcase_create("Unit test for copy_ipv6_hdrs_nofrag");


    tcase_add_test(TCase_fragments_compare, tc_fragments_compare);
    suite_add_tcase(s, TCase_fragments_compare);
    tcase_add_test(TCase_hole_compare, tc_hole_compare);
    suite_add_tcase(s, TCase_hole_compare);
    tcase_add_test(TCase_fragments_compare, tc_first_fragment_received);
    suite_add_tcase(s, TCase_first_fragment_received);
    tcase_add_test(TCase_pico_fragment_alloc, tc_pico_fragment_alloc);
    suite_add_tcase(s, TCase_pico_fragment_alloc);
    tcase_add_test(TCase_pico_fragment_free, tc_pico_fragment_free);
    suite_add_tcase(s, TCase_pico_fragment_free);
    /* tcase_add_test(TCase_pico_fragment_arrived, tc_pico_fragment_arrived); */
    /* suite_add_tcase(s, TCase_pico_fragment_arrived); */
    tcase_add_test(TCase_pico_hole_free, tc_pico_hole_free);
    suite_add_tcase(s, TCase_pico_hole_free);
    tcase_add_test(TCase_pico_hole_alloc, tc_pico_hole_alloc);
    suite_add_tcase(s, TCase_pico_hole_alloc);
    tcase_add_test(TCase_pico_ip_frag_expired, tc_pico_ip_frag_expired);
    suite_add_tcase(s, TCase_pico_ip_frag_expired);
    tcase_add_test(TCase_pico_ipv6_process_frag, tc_pico_ipv6_process_frag);
    suite_add_tcase(s, TCase_pico_ipv6_process_frag);
    tcase_add_test(TCase_pico_ipv4_process_frag, tc_pico_ipv4_process_frag);
    suite_add_tcase(s, TCase_pico_ipv4_process_frag);
    tcase_add_test(TCase_copy_eth_hdr, tc_copy_eth_hdr);
    suite_add_tcase(s, TCase_copy_eth_hdr);
    tcase_add_test(TCase_copy_ipv6_hdrs_nofrag, tc_copy_ipv6_hdrs_nofrag);
    suite_add_tcase(s, TCase_copy_ipv6_hdrs_nofrag);


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
