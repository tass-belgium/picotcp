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
#include "pico_fragments.h"
#include "./modules/pico_fragments.c"
#include "check.h"

Suite *pico_suite(void);
/* Mock! */
static int transport_recv_called = 0;
static uint32_t buffer_len_transport_receive = 0;
#define TESTPROTO 0x99
#define TESTID    0x11
int32_t pico_transport_receive(struct pico_frame *f, uint8_t proto)
{
    fail_if(proto != TESTPROTO);
    transport_recv_called++;
    buffer_len_transport_receive = f->buffer_len;
    pico_frame_discard(f);
    return 0;
}

static int timer_add_called = 0;
uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    IGNORE_PARAMETER(expire);
    IGNORE_PARAMETER(arg);
    fail_if(timer != pico_frag_expire);
    timer_add_called++;
    return 0;
}

static int timer_cancel_called = 0;
void pico_timer_cancel(uint32_t id)
{
    IGNORE_PARAMETER(id);
    timer_cancel_called++;
}

static int icmp4_frag_expired_called = 0;
int pico_icmp4_frag_expired(struct pico_frame *f)
{
    fail_unless(IS_IPV4(f));
    icmp4_frag_expired_called++;
    return 0;
}

static int icmp6_frag_expired_called = 0;
int pico_icmp6_frag_expired(struct pico_frame *f)
{
    fail_unless(IS_IPV6(f));
    icmp6_frag_expired_called++;
    return 0;
}


START_TEST(tc_pico_ipv6_frag_compare)
{
    struct pico_frame *a, *b;
    a = pico_frame_alloc(10);
    fail_if(!a);
    b = pico_frame_alloc(10);
    fail_if(!b);
    a->frag = 0xaa00;
    b->frag = 0xbb00;
    fail_unless(pico_ipv6_frag_compare(a, b) < 0);
    fail_unless(pico_ipv6_frag_compare(b, a) > 0);
    b->frag = 0xaa00;
    fail_unless(pico_ipv6_frag_compare(a, b) == 0);
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST

START_TEST(tc_pico_ipv4_frag_compare)
{
    struct pico_frame *a, *b;
    a = pico_frame_alloc(10);
    fail_if(!a);
    b = pico_frame_alloc(10);
    fail_if(!b);
    a->frag = 0xaa00;
    b->frag = 0xbb00;
    fail_unless(pico_ipv4_frag_compare(a, b) < 0);
    fail_unless(pico_ipv4_frag_compare(b, a) > 0);
    b->frag = 0xaa00;
    fail_unless(pico_ipv4_frag_compare(a, b) == 0);
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST

START_TEST(tc_pico_ipv6_fragments_complete)
{
    struct pico_frame *a, *b;
    transport_recv_called = 0;
    timer_cancel_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = 1; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20; /* off = 32 */

    pico_tree_insert(&ipv6_fragments, a);
    pico_tree_insert(&ipv6_fragments, b);

    pico_set_mm_failure(1);
    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV6);
    fail_if(transport_recv_called != 0);
    fail_if(timer_cancel_called != 0);

    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV6);
    fail_if(transport_recv_called != 1);
    fail_if(timer_cancel_called != 1);
}
END_TEST

START_TEST(tc_pico_ipv4_fragments_complete)
{
    struct pico_frame *a, *b;
    transport_recv_called = 0;
    timer_cancel_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u; /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);
    pico_tree_insert(&ipv4_fragments, b);

    pico_set_mm_failure(1);
    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV4);
    fail_if(transport_recv_called != 0);
    fail_if(timer_cancel_called != 0);

    pico_fragments_complete(64, TESTPROTO, PICO_PROTO_IPV4);
    fail_if(transport_recv_called != 1);
    fail_if(timer_cancel_called != 1);
}
END_TEST

START_TEST(tc_pico_fragments_complete)
{
    /* Done in the two tests above */
}
END_TEST

START_TEST(tc_pico_fragments_empty_tree)
{
    PICO_TREE_DECLARE(tree, pico_ipv4_frag_compare);
    struct pico_frame *a = NULL, *b = NULL;

    pico_fragments_empty_tree(NULL);

    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* Make sure we have different frames a and b (because of compare functions in PICO_TREE_DECLARE) */
    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u; /* off = 32 */

    /* Insert them in the tree */
    pico_tree_insert(&tree, a);
    pico_tree_insert(&tree, b);

    pico_fragments_empty_tree(&tree);

    /* Is tree empty? */
    fail_if(!pico_tree_empty(&tree));
}
END_TEST

START_TEST(tc_pico_fragments_check_complete)
{
    struct pico_frame *a, *b;
    fail_if(pico_fragments_check_complete(&ipv4_fragments, TESTPROTO, PICO_PROTO_IPV4) != 1);
    fail_if(pico_fragments_check_complete(&ipv6_fragments, TESTPROTO, PICO_PROTO_IPV6) != 1);

    /* Case 1: IPV4 all packets received */
    transport_recv_called = 0;
    timer_cancel_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u; /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);
    pico_tree_insert(&ipv4_fragments, b);

    fail_if(pico_fragments_check_complete(&ipv4_fragments, TESTPROTO, PICO_PROTO_IPV4) != 0);
    fail_if(transport_recv_called != 1);
    fail_if(timer_cancel_called != 1);

    /* Case 2: IPV6 all packets received */
    transport_recv_called = 0;
    timer_cancel_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = 1; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20; /* off = 32 */

    pico_tree_insert(&ipv6_fragments, a);
    pico_tree_insert(&ipv6_fragments, b);

    fail_if(pico_fragments_check_complete(&ipv6_fragments, TESTPROTO, PICO_PROTO_IPV6) != 0);
    fail_if(transport_recv_called != 1);
    fail_if(timer_cancel_called != 1);


    /* Case 3: IPV4 NOT all packets received */
    transport_recv_called = 0;
    timer_cancel_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u | PICO_IPV4_MOREFRAG; /* off = 32 + more frags */
    /* b->frag = PICO_IPV4_MOREFRAG; /\* more frags *\/ */

    pico_tree_insert(&ipv4_fragments, a);
    pico_tree_insert(&ipv4_fragments, b);

    fail_if(pico_fragments_check_complete(&ipv4_fragments, TESTPROTO, PICO_PROTO_IPV4) == 0);
    fail_if(transport_recv_called != 0);
    fail_if(timer_cancel_called != 0);

    /* Case 4: IPV6 NOT all packets received */
    transport_recv_called = 0;
    timer_cancel_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = 1; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 1; /* more frags */

    pico_tree_insert(&ipv6_fragments, a);
    pico_tree_insert(&ipv6_fragments, b);

    fail_if(pico_fragments_check_complete(&ipv6_fragments, TESTPROTO, PICO_PROTO_IPV6) == 0);
    fail_if(transport_recv_called != 0);
    fail_if(timer_cancel_called != 0);
}
END_TEST

START_TEST(tc_pico_fragments_send_notify)
{
    struct pico_frame *a = NULL;
    char ipv4_multicast_address[] = {
        "224.0.0.1"
    };

    icmp4_frag_expired_called = 0;

    /* Case 1: NULL fragment */

    pico_fragments_send_notify(NULL);

    /* Notify should not be send when supplied a NULL argument */
    fail_if(icmp4_frag_expired_called);

    /* Case 2: fragment with offset > 0 */
    a = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);

    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv4_hdr);
    a->buffer[0] = 0x40;        /* IPV4 */
    a->frag = 0x20 >> 3u;       /* off = 32 */

    pico_fragments_send_notify(a);

    /* fragment has offset > 0, no notify should be sent */
    fail_if(icmp4_frag_expired_called);

    /* Case 3: fragment with offset > 0 & multicast address */
    pico_string_to_ipv4(ipv4_multicast_address, &((struct pico_ipv4_hdr*)(a->net_hdr))->dst.addr);
    pico_fragments_send_notify(a);

    /* fragment has offset > 0 AND multicast address, no notify should be sent */
    fail_if(icmp4_frag_expired_called);

    /* Case 4: fragment with offset == 0 */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv4_hdr);
    a->buffer[0] = 0x40;        /* IPV4 */
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */
    pico_string_to_ipv4("127.0.0.1", &((struct pico_ipv4_hdr*)(a->net_hdr))->dst.addr); /* Set a non-nulticast address */

    pico_fragments_send_notify(a);

    /* fragment has offset == 0, notify should be sent */
    fail_if(!icmp4_frag_expired_called);

    /* Case 5: fragment with offset == 0 & multicast address */
    icmp4_frag_expired_called = 0; /* reset flag */
    pico_string_to_ipv4(ipv4_multicast_address, &((struct pico_ipv4_hdr*)(a->net_hdr))->dst.addr);

    pico_fragments_send_notify(a);

    /* fragment has offset == 0 but multicast address, notify should NOT sent */
    fail_if(icmp4_frag_expired_called);

    /* Cleanup */
    pico_frame_discard(a);
}
END_TEST


START_TEST(tc_pico_frag_expire)
{
    struct pico_frame *a, *b;
    /* Addr setup, choose a unicast addr */
    struct pico_ip6 addr_1 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    char ipv4_multicast_address[] = {
        "224.0.0.1"
    };
    struct pico_ip6 ipv6_multicast_addr = {{ 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};

    /* Clear env vars */
    icmp4_frag_expired_called = 0;
    icmp6_frag_expired_called = 0;

    /* Common tests */
    /* Case 1: tree is NULL */
    pico_frag_expire(0, NULL);
    fail_if(icmp4_frag_expired_called);
    fail_if(icmp6_frag_expired_called);

    /* IPV4 TESTS */
    /* Initial setup */
    a = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* Case 1: first fragment was not received, do not send notify + empty tree */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv4_hdr);
    a->buffer[0] = 0x40;        /* IPV4 */
    a->frag = 0x20 >> 3u;       /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);

    pico_frag_expire(0, (void*)(&ipv4_fragments));
    fail_if(icmp4_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv4_fragments));

    /* Case 2: first fragment was received, send notify + empty tree */

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);
    b->buffer[0] = 0x40;        /* IPV4 */
    b->frag = PICO_IPV4_MOREFRAG; /* more frags */

    pico_tree_insert(&ipv4_fragments, b);

    pico_frag_expire(0, (void*)(&ipv4_fragments));
    fail_if(!icmp4_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv4_fragments));

    /* Case 3: first fragment was received but it is multicast, do not send notify + empty tree */
    /* Reallocate frame, it was discarded in the last pico_frag_expire() */
    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);
    /* Reset env vars */
    icmp4_frag_expired_called = 0;

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);
    b->buffer[0] = 0x40;        /* IPV4 */
    b->frag = PICO_IPV4_MOREFRAG; /* more frags */

    pico_string_to_ipv4(ipv4_multicast_address, &((struct pico_ipv4_hdr*)(b->net_hdr))->dst.addr);

    pico_tree_insert(&ipv4_fragments, b);

    pico_frag_expire(0, (void*)(&ipv4_fragments));
    fail_if(icmp4_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv4_fragments));


    /* IPV6 TESTS */
    /* re-allocate frames, they were discarded in pico_frag_expire */
    a = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* Case 4: first fragment was not received, do not send notify + empty tree */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv6_hdr);
    a->buffer[0] = 0x60;        /* IPV6 */
    a->frag = 0x20;             /* off = 32 */
    memcpy(((struct pico_ipv6_hdr*)(a->net_hdr))->dst.addr, addr_1.addr, PICO_SIZE_IP6);

    pico_tree_insert(&ipv6_fragments, a);

    pico_frag_expire(0, (void*)(&ipv6_fragments));
    fail_if(icmp6_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv6_fragments));

    /* Case 5: first fragment was received, send notify + empty tree */

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv6_hdr);
    b->buffer[0] = 0x60;        /* IPV6 */
    b->frag = 1;
    memcpy(((struct pico_ipv6_hdr*)(b->net_hdr))->dst.addr, addr_1.addr, PICO_SIZE_IP6);

    pico_tree_insert(&ipv6_fragments, b);

    pico_frag_expire(0, (void*)(&ipv6_fragments));
    fail_if(!icmp6_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv6_fragments));

    /* Case 6: first fragment was received but it is multicast, do not send notify + empty tree */
    /* Reallocate frame, it was discarded in the last pico_frag_expire() */
    b = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);
    /* Reset env vars */
    icmp6_frag_expired_called = 0;

    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);
    b->buffer[0] = 0x60;        /* IPV4 */
    b->frag = 1;

    memcpy(((struct pico_ipv6_hdr*)(b->net_hdr))->dst.addr, ipv6_multicast_addr.addr, PICO_SIZE_IP6);

    pico_tree_insert(&ipv6_fragments, b);

    pico_frag_expire(0, (void*)(&ipv6_fragments));
    fail_if(icmp6_frag_expired_called);
    fail_if(!pico_tree_empty(&ipv6_fragments));

}
END_TEST
START_TEST(tc_pico_ipv6_frag_timer_on)
{
    /* Reset env variable */
    timer_add_called = 0;

    pico_ipv6_frag_timer_on();

    /* Was timer added? */
    fail_if(!timer_add_called);
}
END_TEST
START_TEST(tc_pico_ipv4_frag_timer_on)
{
    /* Reset env variable */
    timer_add_called = 0;

    pico_ipv4_frag_timer_on();

    /* Was timer added? */
    fail_if(!timer_add_called);
}
END_TEST
START_TEST(tc_pico_ipv6_frag_match)
{
    struct pico_frame *a, *b;
    struct pico_ipv6_hdr *ha, *hb;

    /* Addr setup */
    struct pico_ip6 addr_1 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }};
    struct pico_ip6 addr_2 = {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8 }};

    /* Inital setup */
    a = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* Case 1: net hdr(s) are NULL */
    a->net_hdr = NULL;
    b->net_hdr = NULL;

    fail_if(pico_ipv6_frag_match(a, b) != -2);

    /* Init a frame */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv6_hdr);

    fail_if(pico_ipv6_frag_match(a, b) != -2);

    /* Init b frame */
    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv6_hdr);

    /* Init hdrs for rest of tests*/
    ha = (struct pico_ipv6_hdr *)a->net_hdr;
    hb = (struct pico_ipv6_hdr *)b->net_hdr;

    /* Case 2: src addr are different*/
    /* Init a and b net hdr adresses */
    memcpy(ha->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(ha->dst.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->src.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->dst.addr, addr_2.addr, PICO_SIZE_IP6);

    fail_if(pico_ipv6_frag_match(a, b) != 1);

    /* Case 3: dst addr are different*/
    /* Init a and b net hdr adresses */
    memcpy(ha->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(ha->dst.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(hb->dst.addr, addr_1.addr, PICO_SIZE_IP6);

    fail_if(pico_ipv6_frag_match(a, b) != 2);

    /* Case 4: fragments are the same (src and dst are the same)*/
    /* Init a and b net hdr adresses */
    memcpy(ha->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(ha->dst.addr, addr_2.addr, PICO_SIZE_IP6);
    memcpy(hb->src.addr, addr_1.addr, PICO_SIZE_IP6);
    memcpy(hb->dst.addr, addr_2.addr, PICO_SIZE_IP6);

    fail_if(pico_ipv6_frag_match(a, b) != 0);

    /* Cleanup */
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST
START_TEST(tc_pico_ipv4_frag_match)
{
    struct pico_frame *a, *b;
    struct pico_ipv4_hdr *ha, *hb;

    /* Addr setup */
    struct pico_ip4 addr_1 = {
        .addr = long_be(0x0a280064)
    };

    struct pico_ip4 addr_2 = {
        .addr = long_be(0x0a280312)
    };

    /* Case 1: frames are NULL */
    a = NULL;
    b = NULL;

    fail_if(pico_ipv4_frag_match(a, b) != -1);

    /* setup */
    a = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);


    /* Case 2: net hdr(s) are NULL */
    a->net_hdr = NULL;
    b->net_hdr = NULL;

    fail_if(pico_ipv4_frag_match(a, b) != -2);

    /* Init a frame */
    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv4_hdr);

    fail_if(pico_ipv4_frag_match(a, b) != -2);

    /* Init b frame */
    b->net_hdr = b->buffer;
    b->net_len = sizeof(struct pico_ipv4_hdr);

    /* Init hdrs for rest of tests*/
    ha = (struct pico_ipv4_hdr *)a->net_hdr;
    hb = (struct pico_ipv4_hdr *)b->net_hdr;

    /* Case 3: src addr are different*/
    /* Init a and b net hdr adresses */
    ha->src = addr_1;
    ha->dst = addr_2;
    hb->src = addr_2;
    hb->dst = addr_2;

    fail_if(pico_ipv4_frag_match(a, b) != 1);

    /* Case 4: dst addr are different*/
    /* Init a and b net hdr adresses */
    ha->src = addr_1;
    ha->dst = addr_2;
    hb->src = addr_1;
    hb->dst = addr_1;

    fail_if(pico_ipv4_frag_match(a, b) != 2);

    /* Case 5: fragments are the same (src and dst are the same)*/
    /* Init a and b net hdr adresses */
    ha->src = addr_1;
    ha->dst = addr_2;
    hb->src = addr_1;
    hb->dst = addr_2;

    fail_if(pico_ipv4_frag_match(a, b) != 0);

    /* Cleanup */
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST

START_TEST(tc_pico_fragments_get_header_length)
{
    fail_unless(pico_fragments_get_header_length(PICO_PROTO_IPV4) == PICO_SIZE_IP4HDR);

    fail_unless(pico_fragments_get_header_length(PICO_PROTO_IPV6) == PICO_SIZE_IP6HDR);

    fail_unless(pico_fragments_get_header_length(1) == 0);
}
END_TEST

START_TEST(tc_pico_fragments_get_more_flag)
{
    struct pico_frame *a = NULL, *b = NULL;

    a = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);

    a->net_hdr = a->buffer;
    a->net_len = sizeof(struct pico_ipv4_hdr);
    a->buffer[0] = 0x40;        /* IPV4 */
    a->frag = PICO_IPV4_MOREFRAG; /* Set more flag */

    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    b->net_hdr = a->buffer;
    b->net_len = sizeof(struct pico_ipv6_hdr);
    b->buffer[0] = 0x60;        /* IPV6 */
    b->frag = 0x1;              /* set more flag */

    fail_unless(pico_fragments_get_more_flag(NULL, PICO_PROTO_IPV4) == 0);
    fail_unless(pico_fragments_get_more_flag(NULL, PICO_PROTO_IPV6) == 0);

    /* More flag set in IPV4 */
    fail_unless(pico_fragments_get_more_flag(a, PICO_PROTO_IPV4) == 1);

    /* More flag set in IPV6 */
    fail_unless(pico_fragments_get_more_flag(b, PICO_PROTO_IPV6) == 1);

    /* More flag NOT set in IPV4 */
    a->frag = 0;
    fail_unless(pico_fragments_get_more_flag(a, PICO_PROTO_IPV4) == 0);

    /* More flag NOT set in IPV6 */
    b->frag = 0;
    fail_unless(pico_fragments_get_more_flag(b, PICO_PROTO_IPV6) == 0);

    /* Invalid net argument */
    fail_unless(pico_fragments_get_more_flag(a, 1) == 0);
    fail_unless(pico_fragments_get_more_flag(b, 1) == 0);

    /* Cleanup */
    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST

START_TEST(tc_pico_fragments_get_offset)
{
    struct pico_frame *a=NULL, *b = NULL;

    b = pico_frame_alloc(sizeof(struct pico_ipv4_hdr));
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    /* IPV4 with fragment offset > 0 */
    b->frag = 0x20 >> 3u; /* off = 32 */
    fail_unless(pico_fragments_get_offset(b, PICO_PROTO_IPV4) == 32);

    /* IPV4 with fragment offset == 0 */
    b->frag = 0; /* off = 0 */
    fail_unless(pico_fragments_get_offset(b, PICO_PROTO_IPV4) == 0);

    /* Invalid net argument */
    fail_unless(pico_fragments_get_offset(b, 1) == 0);

    a = pico_frame_alloc(sizeof(struct pico_ipv6_hdr));
    fail_if(!a);
    printf("Allocated frame, %p\n", a);

    /* IPV6 with fragment offset > 0 */
    a->frag = 0x20; /* off = 32 */
    fail_unless(pico_fragments_get_offset(a, PICO_PROTO_IPV6) == 32);

    /* IPV6 with fragment offset == 0 */
    a->frag = 1; /* off = 0 */
    fail_unless(pico_fragments_get_offset(a, PICO_PROTO_IPV6) == 0);

    /* Invalid net argument */
    fail_unless(pico_fragments_get_offset(a, 1) == 0);

    /* Invalid frame argument */
    fail_unless(pico_fragments_get_offset(NULL, PICO_PROTO_IPV4) == 0);
    fail_unless(pico_fragments_get_offset(NULL, PICO_PROTO_IPV6) == 0);
    fail_unless(pico_fragments_get_offset(NULL, 1) == 0);

    pico_frame_discard(a);
    pico_frame_discard(b);
}
END_TEST

START_TEST(tc_pico_fragments_reassemble)
{
    struct pico_frame *a, *b;

    /* NULL tree */
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    fail_if(pico_fragments_reassemble(NULL, 0, TESTPROTO, PICO_PROTO_IPV4) != -1);
    fail_if(transport_recv_called);

    /* Empty tree */
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    fail_if(pico_fragments_reassemble(&ipv4_fragments, 0, TESTPROTO, PICO_PROTO_IPV4) != -2);
    fail_if(transport_recv_called);

    /* Empty tree */
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    fail_if(pico_fragments_reassemble(&ipv6_fragments, 0, TESTPROTO, PICO_PROTO_IPV6) != -2);
    fail_if(transport_recv_called);

    /* Case 1: IPV4 , everything good */
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u; /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);
    pico_tree_insert(&ipv4_fragments, b);

    fail_if(pico_fragments_reassemble(&ipv4_fragments, 64, TESTPROTO, PICO_PROTO_IPV4) != 0);
    fail_if(transport_recv_called != 1);
    fail_if(buffer_len_transport_receive != 64 + PICO_SIZE_IP4HDR);
    fail_if(!pico_tree_empty(&ipv4_fragments));

    /* Case 2: IPV6 , everything good */
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = 1; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20; /* off = 32 */

    pico_tree_insert(&ipv6_fragments, a);
    pico_tree_insert(&ipv6_fragments, b);

    fail_if(pico_fragments_reassemble(&ipv6_fragments, 64, TESTPROTO, PICO_PROTO_IPV6) != 0);
    fail_if(transport_recv_called != 1);
    fail_if(buffer_len_transport_receive != 64 + PICO_SIZE_IP6HDR);
    fail_if(!pico_tree_empty(&ipv4_fragments));

    /* Case 3: IPV4 with mm failure*/
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u; /* off = 32 */

    pico_tree_insert(&ipv4_fragments, a);
    pico_tree_insert(&ipv4_fragments, b);

    pico_set_mm_failure(1);
    fail_if(pico_fragments_reassemble(&ipv4_fragments, 64, TESTPROTO, PICO_PROTO_IPV4) != 1);
    fail_if(transport_recv_called == 1);
    fail_if(buffer_len_transport_receive != 0);
    fail_if(pico_tree_empty(&ipv4_fragments));

    /* Case 4: IPV6 with mm failure */
    transport_recv_called = 0;
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = 1; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20; /* off = 32 */

    pico_tree_insert(&ipv6_fragments, a);
    pico_tree_insert(&ipv6_fragments, b);

    pico_set_mm_failure(1);
    fail_if(pico_fragments_reassemble(&ipv6_fragments, 64, TESTPROTO, PICO_PROTO_IPV6) != 1);
    fail_if(transport_recv_called == 1);
    fail_if(buffer_len_transport_receive != 0);
    fail_if(pico_tree_empty(&ipv6_fragments));
}
END_TEST

START_TEST(tc_pico_ipv6_process_frag)
{
    struct pico_ipv6_exthdr *hdr = NULL;
    struct pico_frame *a = NULL, *b = NULL, *c = NULL;

    /* NULL args provided */
    ipv6_cur_frag_id = 0;
    timer_add_called = 0;
    pico_ipv6_process_frag(hdr, a, TESTPROTO);
    fail_if(ipv6_cur_frag_id != 0);
    fail_if(timer_add_called != 0);

    /* init hdr */
    hdr = PICO_ZALLOC(sizeof(struct pico_ipv6_exthdr));
    hdr->ext.frag.id[0]= 0xF;

    /* NULL frame provided */
    ipv6_cur_frag_id = 0;
    timer_add_called = 0;
    pico_ipv6_process_frag(hdr, a, TESTPROTO);
    fail_if(ipv6_cur_frag_id != 0);
    fail_if(timer_add_called != 0);

    /* init frame */
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);
    c = pico_frame_alloc(64 + 20);
    fail_if(!c);
    printf("Allocated frame, %p\n", c);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = 1; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 | 0x1; /* off = 32 */

    c->net_hdr = c->buffer;
    c->net_len = 20;
    c->transport_len = 32;
    c->transport_hdr = c->buffer + 20;
    c->frag = 0x40; /* off = 64 */

    /* Case 1: Empty fragments tree */
    ipv6_cur_frag_id = 0;
    timer_add_called = 0;
    /* make sure tree is empty */
    fail_if(!pico_tree_empty(&ipv6_fragments));

    pico_ipv6_process_frag(hdr, a, TESTPROTO);
    fail_if(ipv6_cur_frag_id != IP6_FRAG_ID(hdr));
    fail_if(timer_add_called != 1);
    fail_if(pico_tree_empty(&ipv6_fragments));
    /* make sure we added the fragment to the tree */
    fail_if(((struct pico_frame *)pico_tree_first(&ipv6_fragments))->buffer != a->buffer);

    /* Case 2: Adding second fragment */
    timer_add_called = 0;
    pico_ipv6_process_frag(hdr, b, TESTPROTO);
    fail_if(ipv6_cur_frag_id != IP6_FRAG_ID(hdr));
    fail_if(timer_add_called != 0);
    fail_if(pico_tree_empty(&ipv6_fragments));
    /* make sure we added the fragment to the tree */
    fail_if(((struct pico_frame *)pico_tree_last(&ipv6_fragments))->buffer != b->buffer);

    /* Case 3: Adding final fragment */
    timer_cancel_called = 0;
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    pico_ipv6_process_frag(hdr, c, TESTPROTO);
    fail_if(ipv6_cur_frag_id != IP6_FRAG_ID(hdr));
    fail_if(timer_cancel_called != 1);
    fail_if(transport_recv_called != 1);
    fail_if(buffer_len_transport_receive != 96 + PICO_SIZE_IP6HDR);
    /* Everything was received, tree should be empty */
    fail_if(!pico_tree_empty(&ipv6_fragments));

    /* Cleanup */
    pico_fragments_empty_tree(&ipv6_fragments);
    pico_frame_discard(a);
    pico_frame_discard(b);
    pico_frame_discard(c);
}
END_TEST

START_TEST(tc_pico_ipv4_process_frag)
{
    struct pico_ipv4_hdr *hdr = NULL;
    struct pico_frame *a = NULL, *b = NULL, *c = NULL;

    /* NULL args provided */
    ipv4_cur_frag_id = 0;
    timer_add_called = 0;
    pico_ipv4_process_frag(hdr, a, TESTPROTO);
    fail_if(ipv4_cur_frag_id != 0);
    fail_if(timer_add_called != 0);

    /* init hdr */
    hdr = PICO_ZALLOC(sizeof(struct pico_ipv4_hdr));
    hdr->id = TESTID;

    /* NULL frame provided */
    ipv4_cur_frag_id = 0;
    timer_add_called = 0;
    pico_ipv4_process_frag(hdr, a, TESTPROTO);
    fail_if(ipv4_cur_frag_id != 0);
    fail_if(timer_add_called != 0);

    /* init frame */
    a = pico_frame_alloc(32 + 20);
    fail_if(!a);
    printf("Allocated frame, %p\n", a);
    b = pico_frame_alloc(32 + 20);
    fail_if(!b);
    printf("Allocated frame, %p\n", b);
    c = pico_frame_alloc(64 + 20);
    fail_if(!c);
    printf("Allocated frame, %p\n", c);

    a->net_hdr = a->buffer;
    a->net_len = 20;
    a->transport_len = 32;
    a->transport_hdr = a->buffer + 20;
    a->frag = PICO_IPV4_MOREFRAG; /* more frags */

    b->net_hdr = b->buffer;
    b->net_len = 20;
    b->transport_len = 32;
    b->transport_hdr = b->buffer + 20;
    b->frag = 0x20 >> 3u | PICO_IPV4_MOREFRAG; /* off = 32 + more frags*/

    c->net_hdr = c->buffer;
    c->net_len = 20;
    c->transport_len = 32;
    c->transport_hdr = c->buffer + 20;
    c->frag = 0x40 >> 3u; /* off = 64 */

    /* Case 1: Empty fragments tree */
    ipv4_cur_frag_id = 0;
    timer_add_called = 0;
    /* make sure tree is empty */
    fail_if(!pico_tree_empty(&ipv4_fragments));

    pico_ipv4_process_frag(hdr, a, TESTPROTO);
    fail_if(ipv4_cur_frag_id != TESTID);
    fail_if(timer_add_called != 1);
    fail_if(pico_tree_empty(&ipv4_fragments));
    /* make sure we added the fragment to the tree */
    fail_if(((struct pico_frame *)pico_tree_first(&ipv4_fragments))->buffer != a->buffer);

    /* Case 2: Adding second fragment */
    timer_add_called = 0;
    pico_ipv4_process_frag(hdr, b, TESTPROTO);
    fail_if(ipv4_cur_frag_id != TESTID);
    fail_if(timer_add_called != 0);
    fail_if(pico_tree_empty(&ipv4_fragments));
    /* make sure we added the fragment to the tree */
    fail_if(((struct pico_frame *)pico_tree_last(&ipv4_fragments))->buffer != b->buffer);

    /* Case 3: Adding final fragment */
    timer_cancel_called = 0;
    transport_recv_called = 0;
    buffer_len_transport_receive = 0;
    pico_ipv4_process_frag(hdr, c, TESTPROTO);
    fail_if(ipv4_cur_frag_id != TESTID);
    fail_if(timer_cancel_called != 1);
    fail_if(transport_recv_called != 1);
    fail_if(buffer_len_transport_receive != 96 + PICO_SIZE_IP4HDR);
    /* Everything was received, tree should be empty */
    fail_if(!pico_tree_empty(&ipv4_fragments));

    /* Cleanup */
    pico_fragments_empty_tree(&ipv4_fragments);
    pico_frame_discard(a);
    pico_frame_discard(b);
    pico_frame_discard(c);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_ipv6_process_frag = tcase_create("Unit test for pico_ipv6_process_frag");
    TCase *TCase_pico_ipv4_process_frag = tcase_create("Unit test for pico_ipv4_process_frag");

    TCase *TCase_pico_fragments_reassemble = tcase_create("Unit test for pico_fragments_reassemble");
    TCase *TCase_pico_fragments_get_offset = tcase_create("Unit test for pico_fragments_get_offset");
    TCase *TCase_pico_fragments_get_more_flag = tcase_create("Unit test for pico_fragments_get_more_flag");
    TCase *TCase_pico_fragments_get_header_length = tcase_create("Unit test for pico_fragments_get_header_length");

    TCase *TCase_pico_fragments_empty_tree = tcase_create("Unit test for pico_fragments_empty_tree");
    TCase *TCase_pico_fragments_send_notify = tcase_create("Unit test for pico_fragments_send_notify");
    TCase *TCase_pico_ipv6_frag_compare = tcase_create("Unit test for pico_ipv6_frag_compare");
    TCase *TCase_pico_ipv4_frag_compare = tcase_create("Unit test for pico_ipv4_frag_compare");
    TCase *TCase_pico_ipv6_fragments_complete = tcase_create("Unit test for pico_ipv6_fragments_complete");
    TCase *TCase_pico_ipv4_fragments_complete = tcase_create("Unit test for pico_ipv4_fragments_complete");
    TCase *TCase_pico_fragments_complete = tcase_create("Unit test for pico_fragments_complete");
    TCase *TCase_pico_fragments_check_complete = tcase_create("Unit test for pico_fragments_check_complete");
    TCase *TCase_pico_frag_expire = tcase_create("Unit test for pico_frag_expire");
    TCase *TCase_pico_ipv6_frag_timer_on = tcase_create("Unit test for pico_ipv6_frag_timer_on");
    TCase *TCase_pico_ipv4_frag_timer_on = tcase_create("Unit test for pico_ipv4_frag_timer_on");
    TCase *TCase_pico_ipv6_frag_match = tcase_create("Unit test for pico_ipv6_frag_match");
    TCase *TCase_pico_ipv4_frag_match = tcase_create("Unit test for pico_ipv4_frag_match");

    tcase_add_test(TCase_pico_ipv4_process_frag, tc_pico_ipv4_process_frag);
    suite_add_tcase(s, TCase_pico_ipv4_process_frag);
    tcase_add_test(TCase_pico_ipv6_process_frag, tc_pico_ipv6_process_frag);
    suite_add_tcase(s, TCase_pico_ipv6_process_frag);
    tcase_add_test(TCase_pico_fragments_reassemble, tc_pico_fragments_reassemble);
    suite_add_tcase(s, TCase_pico_fragments_reassemble);
    tcase_add_test(TCase_pico_fragments_get_offset, tc_pico_fragments_get_offset);
    suite_add_tcase(s, TCase_pico_fragments_get_offset);
    tcase_add_test(TCase_pico_fragments_get_more_flag, tc_pico_fragments_get_more_flag);
    suite_add_tcase(s, TCase_pico_fragments_get_more_flag);
    tcase_add_test(TCase_pico_fragments_get_header_length, tc_pico_fragments_get_header_length);
    suite_add_tcase(s, TCase_pico_fragments_get_header_length);
    tcase_add_test(TCase_pico_fragments_send_notify, tc_pico_fragments_send_notify);
    suite_add_tcase(s, TCase_pico_fragments_send_notify);
    tcase_add_test(TCase_pico_fragments_empty_tree, tc_pico_fragments_empty_tree);
    suite_add_tcase(s, TCase_pico_fragments_empty_tree);
    tcase_add_test(TCase_pico_ipv6_frag_compare, tc_pico_ipv6_frag_compare);
    suite_add_tcase(s, TCase_pico_ipv6_frag_compare);
    tcase_add_test(TCase_pico_ipv4_frag_compare, tc_pico_ipv4_frag_compare);
    suite_add_tcase(s, TCase_pico_ipv4_frag_compare);
    tcase_add_test(TCase_pico_ipv6_fragments_complete, tc_pico_ipv6_fragments_complete);
    suite_add_tcase(s, TCase_pico_ipv6_fragments_complete);
    tcase_add_test(TCase_pico_ipv4_fragments_complete, tc_pico_ipv4_fragments_complete);
    suite_add_tcase(s, TCase_pico_ipv4_fragments_complete);
    tcase_add_test(TCase_pico_fragments_complete, tc_pico_fragments_complete);
    suite_add_tcase(s, TCase_pico_fragments_complete);
    tcase_add_test(TCase_pico_fragments_check_complete, tc_pico_fragments_check_complete);
    suite_add_tcase(s, TCase_pico_fragments_check_complete);
    tcase_add_test(TCase_pico_frag_expire, tc_pico_frag_expire);
    suite_add_tcase(s, TCase_pico_frag_expire);
    tcase_add_test(TCase_pico_ipv6_frag_timer_on, tc_pico_ipv6_frag_timer_on);
    suite_add_tcase(s, TCase_pico_ipv6_frag_timer_on);
    tcase_add_test(TCase_pico_ipv4_frag_timer_on, tc_pico_ipv4_frag_timer_on);
    suite_add_tcase(s, TCase_pico_ipv4_frag_timer_on);
    tcase_add_test(TCase_pico_ipv6_frag_match, tc_pico_ipv6_frag_match);
    suite_add_tcase(s, TCase_pico_ipv6_frag_match);
    tcase_add_test(TCase_pico_ipv4_frag_match, tc_pico_ipv4_frag_match);
    suite_add_tcase(s, TCase_pico_ipv4_frag_match);
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
