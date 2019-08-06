#include <stdio.h>
#include <stdint.h>

#include "serialize_tcp_sock.h"

#include "pico_tree.h"
#include "pico_tcp.h"
#include "pico_socket.h"


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

