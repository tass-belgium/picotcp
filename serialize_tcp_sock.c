#include <stdio.h>
#include <stdint.h>

#include "pico_tree.h"
#include "pico_tcp.h"
#include "pico_socket.h"

#define MAX_SIZE 100

struct pico_tcp_queue {
    struct pico_tree pool;
    uint32_t max_size;
    uint32_t size;
    uint32_t frames;
};
struct tcp_sack_block {
    uint32_t left;
    uint32_t right;
    struct tcp_sack_block *next;
};
typedef struct pico_socket_tcp {
    struct pico_socket sock;

    /* Tree/queues */
    struct pico_tcp_queue tcpq_in;  /* updated the input queue to hold input segments not the full frame. */
    struct pico_tcp_queue tcpq_out;
    struct pico_tcp_queue tcpq_hold; /* buffer to hold delayed frames according to Nagle */

    /* tcp_output */
    uint32_t snd_nxt;
    uint32_t snd_last;
    uint32_t snd_old_ack;
    uint32_t snd_retry;
    uint32_t snd_last_out;

    /* congestion control */
    uint32_t avg_rtt;
    uint32_t rttvar;
    uint32_t rto;
    uint32_t in_flight;
    uint32_t retrans_tmr;
    pico_time retrans_tmr_due;
    uint16_t cwnd_counter;
    uint16_t cwnd;
    uint16_t ssthresh;
    uint16_t recv_wnd;
    uint16_t recv_wnd_scale;

    /* tcp_input */
    uint32_t rcv_nxt;
    uint32_t rcv_ackd;
    uint32_t rcv_processed;
    uint16_t wnd;
    uint16_t wnd_scale;
    uint16_t remote_closed;

    /* options */
    uint32_t ts_nxt;
    uint16_t mss;
    uint8_t sack_ok;
    uint8_t ts_ok;
    uint8_t mss_ok;
    uint8_t scale_ok;
    struct tcp_sack_block *sacks;
    uint8_t jumbo;
    uint32_t linger_timeout;

    /* Transmission */
    uint8_t x_mode;
    uint8_t dupacks;
    uint8_t backoff;
    uint8_t localZeroWindow;

    /* Keepalive */
    uint32_t keepalive_tmr;
    pico_time ack_timestamp;
    uint32_t ka_time;
    uint32_t ka_intvl;
    uint32_t ka_probes;
    uint32_t ka_retries_count;

    /* FIN timer */
    uint32_t fin_tmr;
} pico_socket_tcp;

size_t serialize(pico_socket_tcp* sock);
void deserialize(pico_socket_tcp* sock);

// Returns the size of the data serialized
size_t serialize(pico_socket_tcp* sock) {
    // Convert into JSON format (using cJSON)
    // Store ints as straight up fields in the top level

    FILE* data = fopen("data", "w");
    fwrite(&sock->snd_nxt, sizeof(uint32_t), 1, data);
    fwrite(&sock->snd_last, sizeof(uint32_t), 1, data);
    fwrite(&sock->snd_old_ack, sizeof(uint32_t), 1, data);
    fwrite(&sock->snd_retry, sizeof(uint32_t), 1, data);
    fwrite(&sock->snd_last_out, sizeof(uint32_t), 1, data);

    fwrite(&sock->avg_rtt, sizeof(uint32_t), 1, data);
    fwrite(&sock->rttvar, sizeof(uint32_t), 1, data);
    fwrite(&sock->rto, sizeof(uint32_t), 1, data);
    fwrite(&sock->in_flight, sizeof(uint32_t), 1, data);
    fwrite(&sock->retrans_tmr, sizeof(uint32_t), 1, data);
    fwrite(&sock->retrans_tmr_due, sizeof(pico_time), 1, data);
    fwrite(&sock->cwnd_counter, sizeof(uint16_t), 1, data);
    fwrite(&sock->cwnd, sizeof(uint16_t), 1, data);
    fwrite(&sock->ssthresh, sizeof(uint16_t), 1, data);
    fwrite(&sock->recv_wnd, sizeof(uint16_t), 1, data);
    fwrite(&sock->recv_wnd_scale, sizeof(uint16_t), 1, data);

    fwrite(&sock->rcv_nxt, sizeof(uint32_t), 1, data);
    fwrite(&sock->rcv_ackd, sizeof(uint32_t), 1, data);
    fwrite(&sock->rcv_processed, sizeof(uint32_t), 1, data);
    fwrite(&sock->wnd, sizeof(uint16_t), 1, data);
    fwrite(&sock->wnd_scale, sizeof(uint16_t), 1, data);
    fwrite(&sock->remote_closed, sizeof(uint16_t), 1, data);

    fwrite(&sock->ts_nxt, sizeof(uint32_t), 1, data);
    fwrite(&sock->mss, sizeof(uint16_t), 1, data);
    fwrite(&sock->sack_ok, sizeof(uint8_t), 1, data);
    fwrite(&sock->ts_ok, sizeof(uint8_t), 1, data);
    fwrite(&sock->mss_ok, sizeof(uint8_t), 1, data);
    fwrite(&sock->scale_ok, sizeof(uint8_t), 1, data);
    fwrite(&sock->jumbo, sizeof(uint8_t), 1, data);
    fwrite(&sock->linger_timeout, sizeof(uint32_t), 1, data);

    fwrite(&sock->x_mode, sizeof(uint8_t), 1, data);
    fwrite(&sock->dupacks, sizeof(uint8_t), 1, data);
    fwrite(&sock->backoff, sizeof(uint8_t), 1, data);
    fwrite(&sock->localZeroWindow, sizeof(uint8_t), 1, data);

    fwrite(&sock->keepalive_tmr, sizeof(uint32_t), 1, data);
    fwrite(&sock->ack_timestamp, sizeof(pico_time), 1, data);
    fwrite(&sock->ka_time, sizeof(uint32_t), 1, data);
    fwrite(&sock->ka_intvl, sizeof(uint32_t), 1, data);
    fwrite(&sock->ka_probes, sizeof(uint32_t), 1, data);
    fwrite(&sock->ka_retries_count, sizeof(uint32_t), 1, data);

    fwrite(&sock->fin_tmr, sizeof(uint32_t), 1, data);

    // Types to consider specially
        // 1-> pico_tcp_queue
        // 2-> tcp_sack_block

    /* Special Formats */

    // pico_tcp_queue: pico_tree, ->->-> uints->->->
    //     JSON array, add each element obtained in the order using for_each iterator


    // tcp_sack_block
    //     just iterate over the list and store as an Array of two field objects

    size_t size = (size_t) ftell(data);
    fclose(data);
    return size;
}

void deserialize(pico_socket_tcp* sock) {
    FILE* data = fopen("data", "r");
    fread(&sock->snd_nxt, sizeof(uint32_t), 1, data);
    fread(&sock->snd_last, sizeof(uint32_t), 1, data);
    fread(&sock->snd_old_ack, sizeof(uint32_t), 1, data);
    fread(&sock->snd_retry, sizeof(uint32_t), 1, data);
    fread(&sock->snd_last_out, sizeof(uint32_t), 1, data);

    fread(&sock->avg_rtt, sizeof(uint32_t), 1, data);
    fread(&sock->rttvar, sizeof(uint32_t), 1, data);
    fread(&sock->rto, sizeof(uint32_t), 1, data);
    fread(&sock->in_flight, sizeof(uint32_t), 1, data);
    fread(&sock->retrans_tmr, sizeof(uint32_t), 1, data);
    fread(&sock->retrans_tmr_due, sizeof(pico_time), 1, data);
    fread(&sock->cwnd_counter, sizeof(uint16_t), 1, data);
    fread(&sock->cwnd, sizeof(uint16_t), 1, data);
    fread(&sock->ssthresh, sizeof(uint16_t), 1, data);
    fread(&sock->recv_wnd, sizeof(uint16_t), 1, data);
    fread(&sock->recv_wnd_scale, sizeof(uint16_t), 1, data);

    fread(&sock->rcv_nxt, sizeof(uint32_t), 1, data);
    fread(&sock->rcv_ackd, sizeof(uint32_t), 1, data);
    fread(&sock->rcv_processed, sizeof(uint32_t), 1, data);
    fread(&sock->wnd, sizeof(uint16_t), 1, data);
    fread(&sock->wnd_scale, sizeof(uint16_t), 1, data);
    fread(&sock->remote_closed, sizeof(uint16_t), 1, data);

    fread(&sock->ts_nxt, sizeof(uint32_t), 1, data);
    fread(&sock->mss, sizeof(uint16_t), 1, data);
    fread(&sock->sack_ok, sizeof(uint8_t), 1, data);
    fread(&sock->ts_ok, sizeof(uint8_t), 1, data);
    fread(&sock->mss_ok, sizeof(uint8_t), 1, data);
    fread(&sock->scale_ok, sizeof(uint8_t), 1, data);
    fread(&sock->jumbo, sizeof(uint8_t), 1, data);
    fread(&sock->linger_timeout, sizeof(uint32_t), 1, data);

    fread(&sock->x_mode, sizeof(uint8_t), 1, data);
    fread(&sock->dupacks, sizeof(uint8_t), 1, data);
    fread(&sock->backoff, sizeof(uint8_t), 1, data);
    fread(&sock->localZeroWindow, sizeof(uint8_t), 1, data);

    fread(&sock->keepalive_tmr, sizeof(uint32_t), 1, data);
    fread(&sock->ack_timestamp, sizeof(pico_time), 1, data);
    fread(&sock->ka_time, sizeof(uint32_t), 1, data);
    fread(&sock->ka_intvl, sizeof(uint32_t), 1, data);
    fread(&sock->ka_probes, sizeof(uint32_t), 1, data);
    fread(&sock->ka_retries_count, sizeof(uint32_t), 1, data);

    fread(&sock->fin_tmr, sizeof(uint32_t), 1, data);
    fclose(data);
}


int main(int argc, char** argv) {
    struct pico_socket_tcp sock;
    void* buf;

    // Snapshot
    if (argc == 1) {
        sock.snd_nxt = 1;
        sock.snd_last = 2;
        size_t size = serialize(&sock);
        printf("Snapshot: snd_nxt %u\n", sock.snd_nxt);
        printf("Snapshot: snd_last %u\n", sock.snd_last);
        printf("Snapshot: snd_old_ack %u\n", sock.snd_old_ack);

    } else {
        deserialize(&sock);
        printf("Restore: snd_nxt %u\n", sock.snd_nxt);
        printf("Restore: snd_last %u\n", sock.snd_last);
        printf("Restore: snd_old_ack %u\n", sock.snd_old_ack);

    }
}
