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
     * fragment->frame->buffer should be large enough so no reallocation
     */

    /* Is the packet copied to the fragment frame? */
    /* fail_unless(pico_fragment_arrived(fragment, frame, 0, 1) == frame_transport_size); */
    /* Is the global expiration timer added? */
    /* fail_unless(pico_timer_add_called == 1); */
    /* Are the holes initiated */

    /* Second fragment arrived:
     * - is it copied properly to the fragment->frame?
     * - is the frame properly reallocd?
     * - is the hole deleted from the fragment->holes?
     */

    /* Third fragment arrived:
     * - is it copied properly?
     * - is the frame properly reallocd?
     * - is the return value LAST_FRAG_RECV?
     */


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

    hole = pico_hole_alloc(0, 100);
    fail_if(!hole);
    pico_hole_free(hole);
}
END_TEST
START_TEST(tc_pico_ip_frag_expired)
{
   /* TODO: test this: static void pico_ip_frag_expired(pico_time now, void *arg) */
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
    tcase_add_test(TCase_pico_fragment_arrived, tc_pico_fragment_arrived);
    suite_add_tcase(s, TCase_pico_fragment_arrived);
    tcase_add_test(TCase_pico_hole_free, tc_pico_hole_free);
    suite_add_tcase(s, TCase_pico_hole_free);
    tcase_add_test(TCase_pico_hole_alloc, tc_pico_hole_alloc);
    suite_add_tcase(s, TCase_pico_hole_alloc);
    tcase_add_test(TCase_pico_ip_frag_expired, tc_pico_ip_frag_expired);
    suite_add_tcase(s, TCase_pico_ip_frag_expired);
return s;
}


#if 0
#include "pico_icmp4.h"
#define NUM_PING 1
int ping_test_var = 0;

void cb_ping(struct pico_icmp4_stats *s)
{
    char host[30];
    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("%lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
        if (s->seq == NUM_PING) {
            ping_test_var++;
        }

        fail_if (s->seq > NUM_PING);
    } else {
        dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
        exit(1);
    }
}
#include "pico_dev_null.c"
#include "pico_dev_mock.c"

#endif




int main(void)
{

#if 1
    int fails;
    Suite *s = pico_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);
    return fails;
#else
   /* TODO: test this: static pico_fragment_t *pico_fragment_alloc( uint16_t iphdrsize, uint16_t bufsize); */

    struct pico_ip4 local = {
        0
    };
    struct pico_ip4 remote = {
        0
    };
    struct pico_ip4 netmask = {
        0
    };
    struct mock_device *mock = NULL;
    char local_address[] = {
        "192.168.1.102"
    };
    char remote_address[] = {
        "192.168.1.103"
    };
    uint16_t interval = 1000;
    uint16_t timeout  = 5000;
    uint8_t size  = 48;

    int bufferlen = 80;
    uint8_t buffer[bufferlen];
    int len;
    uint8_t temp_buf[4];

    printf("*********************** starting %s * \n", __func__);

    pico_string_to_ipv4(local_address, &(local.addr));
    pico_string_to_ipv4("255.255.255.0", &(netmask.addr));

    pico_string_to_ipv4(remote_address, &(remote.addr));
    pico_string_to_ipv4("255.255.255.0", &(netmask.addr));

    pico_stack_init();

    mock = pico_mock_create(NULL);
    fail_if(mock == NULL, "No device created");

    pico_ipv4_link_add(mock->dev, local, netmask);

    fail_if(pico_icmp4_ping(local_address, NUM_PING, interval, timeout, size, cb_ping) < 0);
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    fail_if(ping_test_var != 1);

    pico_icmp4_ping(remote_address, NUM_PING, interval, timeout, size, cb_ping);
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    /* get the packet from the mock_device */
    memset(buffer, 0, bufferlen);
printf("[LUM:%s%d]  buffer:%p bufferlen:%d\n",__FILE__,__LINE__,buffer,bufferlen);
    len = pico_mock_network_read(mock, buffer, bufferlen);
    fail_if(len < 20);
printf("[LUM:%s%d]  buffer:%p len:%d\n",__FILE__,__LINE__,buffer,len);
    /* inspect it */
    fail_unless(mock_ip_protocol(mock, buffer, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer, len) == 8);
    fail_unless(mock_icmp_code(mock, buffer, len) == 0);
printf("[LUM:%s%d]  buffer:%p len:%d\n",__FILE__,__LINE__,buffer,len);
printf("[LUM:%s%d]  buffer \n",__FILE__,__LINE__);
{
    int i;
    for(i=0;i < bufferlen;i++)
    {
        if((i%16) ==0) printf("\n");
        printf("0x%02X ",buffer[i]);
    }
}
    fail_unless(pico_checksum(&buffer[20], len - 20) == 0);

    /* cobble up a reply */
    buffer[20] = 0; /* type 0 : reply */
    memcpy(temp_buf, buffer + 12, 4);
    memcpy(buffer + 12, buffer + 16, 4);
    memcpy(&buffer[16], temp_buf, 4);

    /* using the mock-device because otherwise I have to put everything in a pico_frame correctly myself. */
    pico_mock_network_write(mock, buffer, len);
    /* check if it is received */

    pico_check_timers();

    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    fail_unless(ping_test_var == 2);

    /* repeat but make it an invalid reply... */

    pico_icmp4_ping(remote_address, NUM_PING, interval, timeout, size, cb_ping);
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();

    /* get the packet from the mock_device */
    memset(buffer, 0, bufferlen);
    len = pico_mock_network_read(mock, buffer, bufferlen);
    /* inspect it */
    fail_unless(mock_ip_protocol(mock, buffer, len) == 1);
    fail_unless(mock_icmp_type(mock, buffer, len) == 8);
    fail_unless(mock_icmp_code(mock, buffer, len) == 0);
    fail_unless(pico_checksum(buffer + 20, len - 20) == 0);

    /* cobble up a reply */
    buffer[20] = 0; /* type 0 : reply */
    memcpy(temp_buf, buffer + 12, 4);
    memcpy(buffer + 12, buffer + 16, 4);
    memcpy(buffer + 16, temp_buf, 4);
    buffer[26] = ~buffer[26]; /* flip some bits in the sequence number, to see if the packet gets ignored properly */

    /* using the mock-device because otherwise I have to put everything in a pico_frame correctly myself. */
    pico_mock_network_write(mock, buffer, len);
    /* check if it is received */
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    fail_unless(ping_test_var == 2);
#endif
}
