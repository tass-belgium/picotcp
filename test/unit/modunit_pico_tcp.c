#include "pico_tcp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_stack.h"
#include "pico_socket.h"
#include "pico_queue.h"
#include "pico_tree.h"
#include "modules/pico_tcp.c"
#include "check.h"

uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg) 
{
    return NULL;
}

START_TEST(tc_input_segment_compare)
{
    struct tcp_input_segment A =  {
        .seq = 0xFFFFFFFF
    };
    struct tcp_input_segment B =  {
        .seq = 0xFFFFFFFe
    };
    struct tcp_input_segment a =  {
        .seq = 0x01
    };
    struct tcp_input_segment b =  {
        .seq = 0x02
    };

    fail_if(input_segment_compare(&A, &B) <= 0);
    fail_if(input_segment_compare(&a, &b) >= 0);
    fail_if(input_segment_compare(&A, &b) >= 0);
    fail_if(input_segment_compare(&A, &A) != 0);
}
END_TEST
START_TEST(tc_tcp_input_segment)
{
    /* TODO: test this: static struct tcp_input_segment *segment_from_frame(struct pico_frame *f) */
    struct pico_frame *f = pico_frame_alloc(60);
    struct tcp_input_segment *seg;

    fail_if(!f);
    f->payload = f->start;
    f->payload_len = 60;
    f->transport_hdr = f->payload;
    f->transport_len = f->payload_len - 40;
    memset(f->payload, 'c', f->payload_len);
    ((struct pico_tcp_hdr *)((f)->transport_hdr))->seq = long_be(0xdeadbeef);

    seg = segment_from_frame(f);
    fail_if(!seg);
    fail_if(seg->seq != 0xdeadbeef);
    fail_if(seg->payload_len != f->payload_len);
    fail_if(memcmp(seg->payload, f->payload, f->payload_len) != 0);

#ifdef PICO_FAULTY
    printf("Testing with faulty memory in segment_from_frame (1)\n");
    pico_set_mm_failure(1);
    seg = segment_from_frame(f);
    fail_if(seg);

    printf("Testing with faulty memory in segment_from_frame (2)\n");
    pico_set_mm_failure(2);
    seg = segment_from_frame(f);
    fail_if(seg);
#endif
    printf("Testing segment_from_frame with empty payload\n");
    f->payload_len = 0;
    seg = segment_from_frame(f);
    fail_if(seg);

}
END_TEST
START_TEST(tc_segment_compare)
{
    /* TODO: test this: static int segment_compare(void *ka, void *kb) */
    struct pico_frame *a =   pico_frame_alloc(40);
    struct pico_frame *b =   pico_frame_alloc(60);
    a->transport_hdr = a->start;
    b->transport_hdr = b->start;

    ((struct pico_tcp_hdr *)((b)->transport_hdr))->seq = long_be(0xaa00);
    ((struct pico_tcp_hdr *)((a)->transport_hdr))->seq = long_be(0xffffaa00);
    fail_if(segment_compare(a, b) >= 0);
    fail_if(segment_compare(a, a) != 0);


}
END_TEST
START_TEST(tc_tcp_discard_all_segments)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)pico_tcp_open(PICO_PROTO_IPV4);
    struct pico_frame *f = pico_frame_alloc(80);
    struct tcp_input_segment *is;
    fail_if(!t);
    fail_if(!f);

    printf("Testing enqueuing bogus frame\n");
    f->buffer_len = 0;
    fail_if(pico_enqueue_segment(&t->tcpq_out, f) >= 0);
    f->buffer_len = 80;
    f->transport_hdr = f->start;
    f->transport_len = f->buffer_len - 40;
    f->payload = f->start + 40;
    f->payload_len = 40;
    memset(f->payload, 'c', f->payload_len);
    is = segment_from_frame(f);
    fail_if(!is);
    is->payload_len = 0;
    fail_if(pico_enqueue_segment(&t->tcpq_in, is) >= 0);
    is->payload_len = 40;

    /* Successfull cases */
    fail_if(pico_enqueue_segment(&t->tcpq_out, f) <= 0);
    fail_if(pico_enqueue_segment(&t->tcpq_in, is) <= 0);

    /* Fail because size exceeded. Must return 0. */
    t->tcpq_out.max_size = 50;
    t->tcpq_in.max_size = 50;
    fail_if(pico_enqueue_segment(&t->tcpq_out, f) != 0);
    fail_if(pico_enqueue_segment(&t->tcpq_in, is) != 0);


#ifdef PICO_FAULTY
    /* Fail because the tree cannot allocate a new node. Should return 0 */
    printf("Testing with faulty memory (1)\n");
    pico_set_mm_failure(1);
    fail_if(pico_enqueue_segment(&t->tcpq_out, f) > 0);
    pico_set_mm_failure(1);
    fail_if(pico_enqueue_segment(&t->tcpq_in, is) > 0);

    printf("Testing input segment conversion with faulty mm(1)\n");
    pico_set_mm_failure(1);
    is = segment_from_frame(f);
    fail_if(is);
    printf("Testing input segment conversion with faulty mm(2)\n");
    pico_set_mm_failure(2);
    is = segment_from_frame(f);
    fail_if(is);
#endif

    /* Discard all segments */
    fail_if(t->tcpq_out.size == 0);
    fail_if(t->tcpq_out.frames == 0);
    tcp_discard_all_segments(&t->tcpq_out);
    fail_if(t->tcpq_out.size != 0);
    fail_if(t->tcpq_out.frames != 0);

    fail_if(t->tcpq_in.size == 0);
    fail_if(t->tcpq_in.frames == 0);
    fail_if(pico_tcp_queue_in_is_empty(&t->sock));

    tcp_discard_all_segments(&t->tcpq_in);
    fail_if(t->tcpq_in.size != 0);
    fail_if(t->tcpq_in.frames != 0);
    fail_unless(pico_tcp_queue_in_is_empty(&t->sock));


    /* Testing next_segment with NULLS */
    fail_if(next_segment(NULL, NULL) != NULL);
}
END_TEST

START_TEST(tc_release_until)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)pico_tcp_open(PICO_PROTO_IPV6);
    struct pico_frame *f;
    int i = 0, ret;
    struct tcp_input_segment *is;
    fail_if(!t);
    ret = release_until(&t->tcpq_out, 0);
    fail_unless(ret == 0);

    /* Test with output queue */
    for (i = 0; i < 32; i++) {
        f = pico_frame_alloc(84);
        fail_if(!f);
        f->transport_hdr = f->start;
        f->transport_len = f->buffer_len;
        f->payload_len = f->transport_len;
        ((struct pico_tcp_hdr *)((f)->transport_hdr))->seq = long_be(0xaa00 + f->buffer_len * i);
        printf("inserting frame seq = %08x len = %d\n", 0xaa00 + f->buffer_len * i, f->buffer_len);
        fail_if(pico_enqueue_segment(&t->tcpq_out, f) <= 0);
    }
    ret = release_until(&t->tcpq_out, 0xaa00 + f->buffer_len * 30);
    printf("Release until %08x\n", 0xaa00 + f->buffer_len * 30);
    fail_if(ret != 30);
    printf("Ret is %d\n", ret);
    printf("Remaining is %d\n", t->tcpq_out.frames);
    fail_if(t->tcpq_out.frames != 2);

    /* Test with input queue */
    for (i = 0; i < 32; i++) {
        f = pico_frame_alloc(84);
        fail_if(!f);
        f->transport_hdr = f->start;
        f->transport_len = f->buffer_len;
        f->payload_len = f->transport_len;
        f->payload = f->start;
        ((struct pico_tcp_hdr *)((f)->transport_hdr))->seq = long_be(0xaa00 + f->buffer_len * i);
        is = segment_from_frame(f);
        fail_if(!is);
        printf("inserting Input frame seq = %08x len = %d\n", long_be(is->seq), is->payload_len);
        fail_if(!is);
        fail_if(pico_enqueue_segment(&t->tcpq_in, is) <= 0);
    }
    ret = release_until(&t->tcpq_in, 0xaa00 + f->buffer_len * 30);
    printf("Release until %08x\n", 0xaa00 + f->buffer_len * 30);
    fail_if(ret != 30);
    printf("Ret is %d\n", ret);
    printf("Remaining is %d\n", t->tcpq_out.frames);
    fail_if(t->tcpq_out.frames != 2);
}
END_TEST

START_TEST(tc_release_all_until)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)pico_tcp_open(PICO_PROTO_IPV4);
    struct pico_frame *f;
    int i = 0, ret;
    struct tcp_input_segment *is;
    pico_time tm;
    fail_if(!t);
    ret = release_all_until(&t->tcpq_out, 0, &tm);
    fail_unless(ret == 0);

    /* Test with output queue */
    for (i = 0; i < 32; i++) {
        f = pico_frame_alloc(84);
        fail_if(!f);
        f->transport_hdr = f->start;
        f->transport_len = f->buffer_len;
        f->payload_len = f->transport_len;
        ((struct pico_tcp_hdr *)((f)->transport_hdr))->seq = long_be(0xaa00 + f->buffer_len * i);
        printf("inserting frame seq = %08x len = %d\n", 0xaa00 + f->buffer_len * i, f->buffer_len);
        fail_if(pico_enqueue_segment(&t->tcpq_out, f) <= 0);
    }
    ret = release_all_until(&t->tcpq_out, 0xaa00 + f->buffer_len * 30, &tm);
    printf("Release until %08x\n", 0xaa00 + f->buffer_len * 30);
    fail_if(ret != 30);
    printf("Ret is %d\n", ret);
    printf("Remaining is %d\n", t->tcpq_out.frames);
    fail_if(t->tcpq_out.frames != 2);

    /* Test with input queue */
    for (i = 0; i < 32; i++) {
        f = pico_frame_alloc(84);
        fail_if(!f);
        f->transport_hdr = f->start;
        f->transport_len = f->buffer_len;
        f->payload_len = f->transport_len;
        f->payload = f->start;
        ((struct pico_tcp_hdr *)((f)->transport_hdr))->seq = long_be(0xaa00 + f->buffer_len * i);
        is = segment_from_frame(f);
        fail_if(!is);
        printf("inserting Input frame seq = %08x len = %d\n", long_be(is->seq), is->payload_len);
        fail_if(!is);
        fail_if(pico_enqueue_segment(&t->tcpq_in, is) <= 0);
    }
    ret = release_all_until(&t->tcpq_in, 0xaa00 + f->buffer_len * 30, &tm);
    printf("Release until %08x\n", 0xaa00 + f->buffer_len * 30);
    fail_if(ret != 30);
    printf("Ret is %d\n", ret);
    printf("Remaining is %d\n", t->tcpq_out.frames);
    fail_if(t->tcpq_out.frames != 2);

    /* Test enqueue_segment with NULL segment */
    fail_if(pico_enqueue_segment(NULL, NULL) != -1);


}
END_TEST
START_TEST(tc_tcp_send_fin)
{
    /* TODO: test this: static void tcp_send_fin(struct pico_socket_tcp *t); */
}
END_TEST
START_TEST(tc_pico_tcp_process_out)
{
    /* TODO: test this: static int pico_tcp_process_out(struct pico_protocol *self, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_pico_paws)
{
    pico_paws();
    /* Nothing to test for a random function...*/
}
END_TEST


START_TEST(tc_tcp_add_options)
{
    /* TODO: test this: static void tcp_add_options(struct pico_socket_tcp *ts, struct pico_frame *f, uint16_t flags, uint16_t optsiz) */
    struct pico_socket_tcp ts = { };
    struct pico_frame *f = pico_frame_alloc(100);
    uint16_t flags = 0;
    uint16_t optsiz = 50;
    uint8_t *frame_opt_buff;
    int i;
    struct tcp_sack_block *a, *b, *c;
    uint32_t al = 0xa0,
             ar = 0xaf,
             bl = 0xb0,
             br = 0xbf,
             cl = 0xc0,
             cr = 0xcf;
    f->transport_hdr = f->start;
    f->transport_len = f->buffer_len;
    f->payload_len = f->transport_len;
    frame_opt_buff =  f->transport_hdr + PICO_SIZE_TCPHDR;

    /* Window scale only */
    printf("Testing window scale option\n");
    ts.wnd_scale = 66;
    tcp_add_options(&ts, f, flags, optsiz);
    fail_if(frame_opt_buff[0] != PICO_TCP_OPTION_WS);
    fail_if(frame_opt_buff[1] != PICO_TCPOPTLEN_WS);
    fail_if(frame_opt_buff[2] != 66);
    for (i = 3; i < optsiz - 1; i++)
        fail_if(frame_opt_buff[i] != PICO_TCP_OPTION_NOOP);
    fail_if(frame_opt_buff[optsiz - 1] != PICO_TCP_OPTION_END);

    /* MSS + SACK_OK + WS + TIMESTAMPS */
    printf("Testing full SYN options\n");
    flags = PICO_TCP_SYN;
    ts.wnd_scale = 66;
    ts.mss = 0xAA88;
    tcp_add_options(&ts, f, flags, optsiz);
    fail_if(frame_opt_buff[0] != PICO_TCP_OPTION_MSS);
    fail_if(frame_opt_buff[1] != PICO_TCPOPTLEN_MSS);
    fail_if(frame_opt_buff[2] != 0xAA);
    fail_if(frame_opt_buff[3] != 0x88);
    fail_if(frame_opt_buff[4] != PICO_TCP_OPTION_SACK_OK);
    fail_if(frame_opt_buff[5] != PICO_TCPOPTLEN_SACK_OK);
    fail_if(frame_opt_buff[6] != PICO_TCP_OPTION_WS);
    fail_if(frame_opt_buff[7] != PICO_TCPOPTLEN_WS);
    fail_if(frame_opt_buff[8] != 66);
    fail_if(frame_opt_buff[9] != PICO_TCP_OPTION_TIMESTAMP);
    fail_if(frame_opt_buff[10] != PICO_TCPOPTLEN_TIMESTAMP);
    /* Timestamps: up to byte 18 */
    for (i = 19; i < optsiz - 1; i++)
        fail_if(frame_opt_buff[i] != PICO_TCP_OPTION_NOOP);
    fail_if(frame_opt_buff[optsiz - 1] != PICO_TCP_OPTION_END);

    /* Testing SACKs */
    printf("Testing full SACK options\n");
    a = PICO_ZALLOC(sizeof (struct tcp_sack_block));
    b = PICO_ZALLOC(sizeof (struct tcp_sack_block));
    c = PICO_ZALLOC(sizeof (struct tcp_sack_block));
    a->left = al;
    a->right = ar;
    a->next = b;
    b->left = bl;
    b->right = br;
    b->next = c;
    c->left = cl;
    c->right = cr;
    c->next = NULL;

    ts.sack_ok = 1;
    ts.sacks = a;
    flags = PICO_TCP_ACK;
    tcp_add_options(&ts, f, flags, optsiz);
    fail_if(frame_opt_buff[0] != PICO_TCP_OPTION_WS);
    fail_if(frame_opt_buff[1] != PICO_TCPOPTLEN_WS);
    fail_if(frame_opt_buff[2] != 66);
    fail_if(frame_opt_buff[3] != PICO_TCP_OPTION_SACK);
    fail_if(frame_opt_buff[4] != PICO_TCPOPTLEN_SACK + 6 * (sizeof(uint32_t)));
    fail_if(memcmp(frame_opt_buff + 5,  &al, 4) != 0);
    fail_if(memcmp(frame_opt_buff + 9,  &ar, 4) != 0);
    fail_if(memcmp(frame_opt_buff + 13, &bl, 4) != 0);
    fail_if(memcmp(frame_opt_buff + 17, &br, 4) != 0);
    fail_if(memcmp(frame_opt_buff + 21, &cl, 4) != 0);
    fail_if(memcmp(frame_opt_buff + 25, &cr, 4) != 0);
    fail_if(ts.sacks != NULL);
    for (i = 29; i < optsiz - 1; i++)
        fail_if(frame_opt_buff[i] != PICO_TCP_OPTION_NOOP);
    fail_if(frame_opt_buff[optsiz - 1] != PICO_TCP_OPTION_END);






}
END_TEST
START_TEST(tc_tcp_options_size_frame)
{
    /* TODO: test this: static uint16_t tcp_options_size_frame(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_add_options_frame)
{
    /* TODO: test this: static void tcp_add_options_frame(struct pico_socket_tcp *ts, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_send_ack)
{
    /* TODO: test this: static void tcp_send_ack(struct pico_socket_tcp *t); */
}
END_TEST
START_TEST(tc_tcp_set_space)
{
    /* TODO: test this: static void tcp_set_space(struct pico_socket_tcp *t) */
}
END_TEST
START_TEST(tc_tcp_options_size)
{
    /* TODO: test this: static uint16_t tcp_options_size(struct pico_socket_tcp *t, uint16_t flags) */
}
END_TEST
START_TEST(tc_tcp_process_sack)
{
    /* TODO: test this: static void tcp_process_sack(struct pico_socket_tcp *t, uint32_t start, uint32_t end) */
}
END_TEST
START_TEST(tc_tcp_rcv_sack)
{
    /* TODO: test this: static void tcp_rcv_sack(struct pico_socket_tcp *t, uint8_t *opt, int len) */
}
END_TEST
START_TEST(tc_tcp_parse_options)
{
    /* TODO: test this: static void tcp_parse_options(struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_send)
{
    /* TODO: test this: static int tcp_send(struct pico_socket_tcp *ts, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_sock_stats)
{
    /* TODO: test this: static void sock_stats(uint32_t when, void *arg) */
}
END_TEST
START_TEST(tc_initconn_retry)
{
    /* TODO: test this: static void initconn_retry(pico_time when, void *arg) */
}
END_TEST
START_TEST(tc_tcp_send_synack)
{
    /* TODO: test this: static int tcp_send_synack(struct pico_socket *s) */
}
END_TEST
START_TEST(tc_tcp_send_empty)
{
    /* TODO: test this: static void tcp_send_empty(struct pico_socket_tcp *t, uint16_t flags, int is_keepalive) */
}
END_TEST
START_TEST(tc_tcp_send_probe)
{
    /* TODO: test this: static void tcp_send_probe(struct pico_socket_tcp *t) */
}
END_TEST
START_TEST(tc_tcp_send_rst)
{
    /* TODO: test this: static int tcp_send_rst(struct pico_socket *s, struct pico_frame *fr) */
}
END_TEST
START_TEST(tc_tcp_nosync_rst)
{
    /* TODO: test this: static int tcp_nosync_rst(struct pico_socket *s, struct pico_frame *fr) */
}
END_TEST
START_TEST(tc_tcp_sack_prepare)
{
    /* TODO: test this: static void tcp_sack_prepare(struct pico_socket_tcp *t) */
}
END_TEST
START_TEST(tc_tcp_data_in)
{
    /* TODO: test this: static int tcp_data_in(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_ack_advance_una)
{
    /* TODO: test this: static int tcp_ack_advance_una(struct pico_socket_tcp *t, struct pico_frame *f, pico_time *timestamp) */
}
END_TEST
START_TEST(tc_time_diff)
{
    /* TODO: test this: static uint16_t time_diff(pico_time a, pico_time b) */
}
END_TEST
START_TEST(tc_tcp_rtt)
{
    /* TODO: test this: static void tcp_rtt(struct pico_socket_tcp *t, uint32_t rtt) */

}
END_TEST
START_TEST(tc_tcp_congestion_control)
{
    /* TODO: test this: static void tcp_congestion_control(struct pico_socket_tcp *t) */
}
END_TEST
START_TEST(tc_add_retransmission_timer)
{
    /* TODO: test this: static void add_retransmission_timer(struct pico_socket_tcp *t, pico_time next_ts); */
}
END_TEST
START_TEST(tc_tcp_first_timeout)
{
    /* TODO: test this: static void tcp_first_timeout(struct pico_socket_tcp *t) */
}
END_TEST
START_TEST(tc_tcp_rto_xmit)
{
    /* TODO: test this: static int tcp_rto_xmit(struct pico_socket_tcp *t, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_next_zerowindow_probe)
{
    /* TODO: test this: static void tcp_next_zerowindow_probe(struct pico_socket_tcp *t) */
}
END_TEST
START_TEST(tc_tcp_is_allowed_to_send)
{
    /* TODO: test this: static int tcp_is_allowed_to_send(struct pico_socket_tcp *t) */
}
END_TEST
START_TEST(tc_tcp_retrans_timeout)
{
    /* TODO: test this: static void tcp_retrans_timeout(pico_time val, void *sock) */
}
END_TEST
START_TEST(tc_tcp_retrans)
{
    /* TODO: test this: static int tcp_retrans(struct pico_socket_tcp *t, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_ack_dbg)
{
    /* TODO: test this: static void tcp_ack_dbg(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_ack)
{
    /* TODO: test this: static int tcp_ack(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_finwaitack)
{
    /* TODO: test this: static int tcp_finwaitack(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_deltcb)
{
    /* TODO: test this: static void tcp_deltcb(pico_time when, void *arg) */
}
END_TEST
START_TEST(tc_tcp_finwaitfin)
{
    /* TODO: test this: static int tcp_finwaitfin(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_closewaitack)
{
    /* TODO: test this: static int tcp_closewaitack(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_lastackwait)
{
    /* TODO: test this: static int tcp_lastackwait(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_syn)
{
    /* TODO: test this: static int tcp_syn(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_set_init_point)
{
    /* TODO: test this: static void tcp_set_init_point(struct pico_socket *s) */
}
END_TEST
START_TEST(tc_tcp_synack)
{
    /* TODO: test this: static int tcp_synack(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_first_ack)
{
    /* TODO: test this: static int tcp_first_ack(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_closewait)
{
    /* TODO: test this: static int tcp_closewait(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_fin)
{
    /* TODO: test this: static int tcp_fin(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_rcvfin)
{
    /* TODO: test this: static int tcp_rcvfin(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_finack)
{
    /* TODO: test this: static int tcp_finack(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_force_closed)
{
    /* TODO: test this: static void tcp_force_closed(struct pico_socket *s) */
}
END_TEST
START_TEST(tc_tcp_wakeup_pending)
{
    /* TODO: test this: static void tcp_wakeup_pending(struct pico_socket *s, uint16_t ev) */
}
END_TEST
START_TEST(tc_tcp_rst)
{
    /* TODO: test this: static int tcp_rst(struct pico_socket *s, struct pico_frame *f) */
}
END_TEST
START_TEST(tc_tcp_halfopencon)
{
    /* TODO: test this: static int tcp_halfopencon(struct pico_socket *s, struct pico_frame *fr) */
}
END_TEST
START_TEST(tc_tcp_closeconn)
{
    /* TODO: test this: static int tcp_closeconn(struct pico_socket *s, struct pico_frame *fr) */
}
END_TEST
START_TEST(tc_invalid_flags)
{
    /* TODO: test this: static uint8_t invalid_flags(struct pico_socket *s, uint8_t flags) */
}
END_TEST
START_TEST(tc_checkLocalClosing)
{
    /* TODO: test this: static int checkLocalClosing(struct pico_socket *s) */
}
END_TEST
START_TEST(tc_checkRemoteClosing)
{
    /* TODO: test this: static int checkRemoteClosing(struct pico_socket *s) */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_input_segment_compare = tcase_create("Unit test for input_segment_compare");
    TCase *TCase_tcp_input_segment = tcase_create("Unit test for tcp_input_segment");
    TCase *TCase_segment_compare = tcase_create("Unit test for segment_compare");
    TCase *TCase_tcp_discard_all_segments = tcase_create("Unit test for tcp_discard_all_segments");
    TCase *TCase_release_until = tcase_create("Unit test for release_until");
    TCase *TCase_release_all_until = tcase_create("Unit test for release_all_until");
    TCase *TCase_tcp_send_fin = tcase_create("Unit test for tcp_send_fin");
    TCase *TCase_pico_tcp_process_out = tcase_create("Unit test for pico_tcp_process_out");
    TCase *TCase_pico_paws = tcase_create("Unit test for pico_paws");
    TCase *TCase_tcp_add_options = tcase_create("Unit test for tcp_add_options");
    TCase *TCase_tcp_options_size_frame = tcase_create("Unit test for tcp_options_size_frame");
    TCase *TCase_tcp_add_options_frame = tcase_create("Unit test for tcp_add_options_frame");
    TCase *TCase_tcp_send_ack = tcase_create("Unit test for tcp_send_ack");
    TCase *TCase_tcp_set_space = tcase_create("Unit test for tcp_set_space");
    TCase *TCase_tcp_options_size = tcase_create("Unit test for tcp_options_size");
    TCase *TCase_tcp_process_sack = tcase_create("Unit test for tcp_process_sack");
    TCase *TCase_tcp_rcv_sack = tcase_create("Unit test for tcp_rcv_sack");
    TCase *TCase_tcp_parse_options = tcase_create("Unit test for tcp_parse_options");
    TCase *TCase_tcp_send = tcase_create("Unit test for tcp_send");
    TCase *TCase_sock_stats = tcase_create("Unit test for sock_stats");
    TCase *TCase_initconn_retry = tcase_create("Unit test for initconn_retry");
    TCase *TCase_tcp_send_synack = tcase_create("Unit test for tcp_send_synack");
    TCase *TCase_tcp_send_empty = tcase_create("Unit test for tcp_send_empty");
    TCase *TCase_tcp_send_probe = tcase_create("Unit test for tcp_send_probe");
    TCase *TCase_tcp_send_rst = tcase_create("Unit test for tcp_send_rst");
    TCase *TCase_tcp_nosync_rst = tcase_create("Unit test for tcp_nosync_rst");
    TCase *TCase_tcp_sack_prepare = tcase_create("Unit test for tcp_sack_prepare");
    TCase *TCase_tcp_data_in = tcase_create("Unit test for tcp_data_in");
    TCase *TCase_tcp_ack_advance_una = tcase_create("Unit test for tcp_ack_advance_una");
    TCase *TCase_time_diff = tcase_create("Unit test for time_diff");
    TCase *TCase_tcp_rtt = tcase_create("Unit test for tcp_rtt");
    TCase *TCase_tcp_congestion_control = tcase_create("Unit test for tcp_congestion_control");
    TCase *TCase_add_retransmission_timer = tcase_create("Unit test for add_retransmission_timer");
    TCase *TCase_tcp_first_timeout = tcase_create("Unit test for tcp_first_timeout");
    TCase *TCase_tcp_rto_xmit = tcase_create("Unit test for tcp_rto_xmit");
    TCase *TCase_tcp_next_zerowindow_probe = tcase_create("Unit test for tcp_next_zerowindow_probe");
    TCase *TCase_tcp_is_allowed_to_send = tcase_create("Unit test for tcp_is_allowed_to_send");
    TCase *TCase_tcp_retrans_timeout = tcase_create("Unit test for tcp_retrans_timeout");
    TCase *TCase_tcp_retrans = tcase_create("Unit test for tcp_retrans");
    TCase *TCase_tcp_ack_dbg = tcase_create("Unit test for tcp_ack_dbg");
    TCase *TCase_tcp_ack = tcase_create("Unit test for tcp_ack");
    TCase *TCase_tcp_finwaitack = tcase_create("Unit test for tcp_finwaitack");
    TCase *TCase_tcp_deltcb = tcase_create("Unit test for tcp_deltcb");
    TCase *TCase_tcp_finwaitfin = tcase_create("Unit test for tcp_finwaitfin");
    TCase *TCase_tcp_closewaitack = tcase_create("Unit test for tcp_closewaitack");
    TCase *TCase_tcp_lastackwait = tcase_create("Unit test for tcp_lastackwait");
    TCase *TCase_tcp_syn = tcase_create("Unit test for tcp_syn");
    TCase *TCase_tcp_set_init_point = tcase_create("Unit test for tcp_set_init_point");
    TCase *TCase_tcp_synack = tcase_create("Unit test for tcp_synack");
    TCase *TCase_tcp_first_ack = tcase_create("Unit test for tcp_first_ack");
    TCase *TCase_tcp_closewait = tcase_create("Unit test for tcp_closewait");
    TCase *TCase_tcp_fin = tcase_create("Unit test for tcp_fin");
    TCase *TCase_tcp_rcvfin = tcase_create("Unit test for tcp_rcvfin");
    TCase *TCase_tcp_finack = tcase_create("Unit test for tcp_finack");
    TCase *TCase_tcp_force_closed = tcase_create("Unit test for tcp_force_closed");
    TCase *TCase_tcp_wakeup_pending = tcase_create("Unit test for tcp_wakeup_pending");
    TCase *TCase_tcp_rst = tcase_create("Unit test for tcp_rst");
    TCase *TCase_tcp_halfopencon = tcase_create("Unit test for tcp_halfopencon");
    TCase *TCase_tcp_closeconn = tcase_create("Unit test for tcp_closeconn");
    TCase *TCase_invalid_flags = tcase_create("Unit test for invalid_flags");
    TCase *TCase_checkLocalClosing = tcase_create("Unit test for checkLocalClosing");
    TCase *TCase_checkRemoteClosing = tcase_create("Unit test for checkRemoteClosing");


    tcase_add_test(TCase_input_segment_compare, tc_input_segment_compare);
    suite_add_tcase(s, TCase_input_segment_compare);
    tcase_add_test(TCase_tcp_input_segment, tc_tcp_input_segment);
    suite_add_tcase(s, TCase_tcp_input_segment);
    tcase_add_test(TCase_segment_compare, tc_segment_compare);
    suite_add_tcase(s, TCase_segment_compare);
    tcase_add_test(TCase_tcp_discard_all_segments, tc_tcp_discard_all_segments);
    suite_add_tcase(s, TCase_tcp_discard_all_segments);
    tcase_add_test(TCase_release_until, tc_release_until);
    suite_add_tcase(s, TCase_release_until);
    tcase_add_test(TCase_release_all_until, tc_release_all_until);
    suite_add_tcase(s, TCase_release_all_until);
    tcase_add_test(TCase_tcp_send_fin, tc_tcp_send_fin);
    suite_add_tcase(s, TCase_tcp_send_fin);
    tcase_add_test(TCase_pico_tcp_process_out, tc_pico_tcp_process_out);
    suite_add_tcase(s, TCase_pico_tcp_process_out);
    tcase_add_test(TCase_pico_paws, tc_pico_paws);
    suite_add_tcase(s, TCase_pico_paws);
    tcase_add_test(TCase_tcp_add_options, tc_tcp_add_options);
    suite_add_tcase(s, TCase_tcp_add_options);
    tcase_add_test(TCase_tcp_options_size_frame, tc_tcp_options_size_frame);
    suite_add_tcase(s, TCase_tcp_options_size_frame);
    tcase_add_test(TCase_tcp_add_options_frame, tc_tcp_add_options_frame);
    suite_add_tcase(s, TCase_tcp_add_options_frame);
    tcase_add_test(TCase_tcp_send_ack, tc_tcp_send_ack);
    suite_add_tcase(s, TCase_tcp_send_ack);
    tcase_add_test(TCase_tcp_set_space, tc_tcp_set_space);
    suite_add_tcase(s, TCase_tcp_set_space);
    tcase_add_test(TCase_tcp_options_size, tc_tcp_options_size);
    suite_add_tcase(s, TCase_tcp_options_size);
    tcase_add_test(TCase_tcp_process_sack, tc_tcp_process_sack);
    suite_add_tcase(s, TCase_tcp_process_sack);
    tcase_add_test(TCase_tcp_rcv_sack, tc_tcp_rcv_sack);
    suite_add_tcase(s, TCase_tcp_rcv_sack);
    tcase_add_test(TCase_tcp_parse_options, tc_tcp_parse_options);
    suite_add_tcase(s, TCase_tcp_parse_options);
    tcase_add_test(TCase_tcp_send, tc_tcp_send);
    suite_add_tcase(s, TCase_tcp_send);
    tcase_add_test(TCase_sock_stats, tc_sock_stats);
    suite_add_tcase(s, TCase_sock_stats);
    tcase_add_test(TCase_initconn_retry, tc_initconn_retry);
    suite_add_tcase(s, TCase_initconn_retry);
    tcase_add_test(TCase_tcp_send_synack, tc_tcp_send_synack);
    suite_add_tcase(s, TCase_tcp_send_synack);
    tcase_add_test(TCase_tcp_send_empty, tc_tcp_send_empty);
    suite_add_tcase(s, TCase_tcp_send_empty);
    tcase_add_test(TCase_tcp_send_probe, tc_tcp_send_probe);
    suite_add_tcase(s, TCase_tcp_send_probe);
    tcase_add_test(TCase_tcp_send_rst, tc_tcp_send_rst);
    suite_add_tcase(s, TCase_tcp_send_rst);
    tcase_add_test(TCase_tcp_nosync_rst, tc_tcp_nosync_rst);
    suite_add_tcase(s, TCase_tcp_nosync_rst);
    tcase_add_test(TCase_tcp_sack_prepare, tc_tcp_sack_prepare);
    suite_add_tcase(s, TCase_tcp_sack_prepare);
    tcase_add_test(TCase_tcp_data_in, tc_tcp_data_in);
    suite_add_tcase(s, TCase_tcp_data_in);
    tcase_add_test(TCase_tcp_ack_advance_una, tc_tcp_ack_advance_una);
    suite_add_tcase(s, TCase_tcp_ack_advance_una);
    tcase_add_test(TCase_time_diff, tc_time_diff);
    suite_add_tcase(s, TCase_time_diff);
    tcase_add_test(TCase_tcp_rtt, tc_tcp_rtt);
    suite_add_tcase(s, TCase_tcp_rtt);
    tcase_add_test(TCase_tcp_congestion_control, tc_tcp_congestion_control);
    suite_add_tcase(s, TCase_tcp_congestion_control);
    tcase_add_test(TCase_add_retransmission_timer, tc_add_retransmission_timer);
    suite_add_tcase(s, TCase_add_retransmission_timer);
    tcase_add_test(TCase_tcp_first_timeout, tc_tcp_first_timeout);
    suite_add_tcase(s, TCase_tcp_first_timeout);
    tcase_add_test(TCase_tcp_rto_xmit, tc_tcp_rto_xmit);
    suite_add_tcase(s, TCase_tcp_rto_xmit);
    tcase_add_test(TCase_tcp_next_zerowindow_probe, tc_tcp_next_zerowindow_probe);
    suite_add_tcase(s, TCase_tcp_next_zerowindow_probe);
    tcase_add_test(TCase_tcp_is_allowed_to_send, tc_tcp_is_allowed_to_send);
    suite_add_tcase(s, TCase_tcp_is_allowed_to_send);
    tcase_add_test(TCase_tcp_retrans_timeout, tc_tcp_retrans_timeout);
    suite_add_tcase(s, TCase_tcp_retrans_timeout);
    tcase_add_test(TCase_tcp_retrans, tc_tcp_retrans);
    suite_add_tcase(s, TCase_tcp_retrans);
    tcase_add_test(TCase_tcp_ack_dbg, tc_tcp_ack_dbg);
    suite_add_tcase(s, TCase_tcp_ack_dbg);
    tcase_add_test(TCase_tcp_ack, tc_tcp_ack);
    suite_add_tcase(s, TCase_tcp_ack);
    tcase_add_test(TCase_tcp_finwaitack, tc_tcp_finwaitack);
    suite_add_tcase(s, TCase_tcp_finwaitack);
    tcase_add_test(TCase_tcp_deltcb, tc_tcp_deltcb);
    suite_add_tcase(s, TCase_tcp_deltcb);
    tcase_add_test(TCase_tcp_finwaitfin, tc_tcp_finwaitfin);
    suite_add_tcase(s, TCase_tcp_finwaitfin);
    tcase_add_test(TCase_tcp_closewaitack, tc_tcp_closewaitack);
    suite_add_tcase(s, TCase_tcp_closewaitack);
    tcase_add_test(TCase_tcp_lastackwait, tc_tcp_lastackwait);
    suite_add_tcase(s, TCase_tcp_lastackwait);
    tcase_add_test(TCase_tcp_syn, tc_tcp_syn);
    suite_add_tcase(s, TCase_tcp_syn);
    tcase_add_test(TCase_tcp_set_init_point, tc_tcp_set_init_point);
    suite_add_tcase(s, TCase_tcp_set_init_point);
    tcase_add_test(TCase_tcp_synack, tc_tcp_synack);
    suite_add_tcase(s, TCase_tcp_synack);
    tcase_add_test(TCase_tcp_first_ack, tc_tcp_first_ack);
    suite_add_tcase(s, TCase_tcp_first_ack);
    tcase_add_test(TCase_tcp_closewait, tc_tcp_closewait);
    suite_add_tcase(s, TCase_tcp_closewait);
    tcase_add_test(TCase_tcp_fin, tc_tcp_fin);
    suite_add_tcase(s, TCase_tcp_fin);
    tcase_add_test(TCase_tcp_rcvfin, tc_tcp_rcvfin);
    suite_add_tcase(s, TCase_tcp_rcvfin);
    tcase_add_test(TCase_tcp_finack, tc_tcp_finack);
    suite_add_tcase(s, TCase_tcp_finack);
    tcase_add_test(TCase_tcp_force_closed, tc_tcp_force_closed);
    suite_add_tcase(s, TCase_tcp_force_closed);
    tcase_add_test(TCase_tcp_wakeup_pending, tc_tcp_wakeup_pending);
    suite_add_tcase(s, TCase_tcp_wakeup_pending);
    tcase_add_test(TCase_tcp_rst, tc_tcp_rst);
    suite_add_tcase(s, TCase_tcp_rst);
    tcase_add_test(TCase_tcp_halfopencon, tc_tcp_halfopencon);
    suite_add_tcase(s, TCase_tcp_halfopencon);
    tcase_add_test(TCase_tcp_closeconn, tc_tcp_closeconn);
    suite_add_tcase(s, TCase_tcp_closeconn);
    tcase_add_test(TCase_invalid_flags, tc_invalid_flags);
    suite_add_tcase(s, TCase_invalid_flags);
    tcase_add_test(TCase_checkLocalClosing, tc_checkLocalClosing);
    suite_add_tcase(s, TCase_checkLocalClosing);
    tcase_add_test(TCase_checkRemoteClosing, tc_checkRemoteClosing);
    suite_add_tcase(s, TCase_checkRemoteClosing);
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
