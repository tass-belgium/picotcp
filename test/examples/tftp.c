#include "utils.h"
#include <pico_stack.h>
#include <pico_tftp.h>
#include <pico_ipv4.h>

/* Let's use linux fs */
#include <fcntl.h>

/*** START TFTP ***/
#ifdef PICO_SUPPORT_TFTP
#define TFTP_MODE_SRV 0
#define TFTP_MODE_CLI 1
#define TFTP_MODE_PSH 2
#define TFTP_TX_COUNT 2000
#define TFTP_PAYLOAD_SIZE 512
unsigned char tftp_txbuf[TFTP_PAYLOAD_SIZE];

int cb_tftp_tx(uint16_t err, uint8_t *block, uint32_t len)
{
    static int fd = -1;
    static int count = 1;
    (void)block;

    if (fd == -1) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            perror("open");
            exit(1);
        }
    }

    if (err != PICO_TFTP_ERR_OK) {
        printf("TFTP: Error %d: %s\n", err, block);
        exit(1);
    }

    if (count++ == TFTP_TX_COUNT) {
        len = 0;
        close(fd);
        pico_timer_add(2000, deferred_exit, NULL);
    } else {
        len = read(fd, tftp_txbuf, PICO_TFTP_SIZE);
    }

    if (len >= 0) {
        pico_tftp_send(tftp_txbuf, len);
    }

    return len;
}

int cb_tftp(uint16_t err, uint8_t *block, uint32_t len)
{
    static int fd = -1;
    static int count = 1;

    if (fd == -1) {
        fd = open("/tmp/tftp_recv", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            perror("open");
            exit(1);
        }
    }

    if (err != PICO_TFTP_ERR_OK) {
        printf("TFTP: Error %d: %s\n", err, block);
        exit(1);
    }

    if (len > 0)
        write(fd, block, len);

    if (len == PICO_TFTP_SIZE) {
        /* printf("Received block %d, size: %d\n", count++, len); */
    } else {
        printf("Received last block, size:%d. Transfer complete.\n", len);
        close(fd);
        pico_timer_add(2000, deferred_exit, NULL);
    }

    return len;

}

int tftp_listen_cb(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename)
{
    printf("TFTP listen callback.\n");
    if (opcode == PICO_TFTP_RRQ) {
        printf("Received TFTP get request for %s\n", filename);
        if(pico_tftp_start_tx(addr, port, PICO_PROTO_IPV4, filename, cb_tftp_tx) < 0) {
            fprintf(stderr, "TFTP: Error in initialization\n");
            exit(1);
        }
    } else if (opcode == PICO_TFTP_WRQ) {
        printf("Received TFTP put request for %s\n", filename);
        if(pico_tftp_start_rx(addr, port, PICO_PROTO_IPV4, filename, cb_tftp) < 0) {
            fprintf(stderr, "TFTP: Error in initialization\n");
            exit(1);
        }
    } else {
        printf ("Received invalid TFTP request %d\n", opcode);
        return -1;
    }

    return 0;

}

void app_tftp(char *arg)
{
    char *nxt;
    char *mode, *addr, *file;
    int tftp_mode;
    struct pico_ip4 server;
    nxt = cpy_arg(&mode, arg);

    if ((*mode == 's') || (*mode == 'c') || (*mode == 'p')) { /* TEST BENCH SEND MODE */
        if (*mode == 's') {
            tftp_mode = TFTP_MODE_SRV;
            printf("tftp> Server\n");
        } else {
            if (*mode == 'c')
                tftp_mode = TFTP_MODE_CLI;

            if (*mode == 'p')
                tftp_mode = TFTP_MODE_PSH;

            printf("tftp> Client\n");
            if (!nxt) {
                printf("Usage: tftp:client:host:file:\n");
                exit(1);
            }

            nxt = cpy_arg(&addr, nxt);
            if (pico_string_to_ipv4(addr, &server.addr) < 0) {
                printf("invalid host %s\n", addr);
                exit(1);
            }

            if (!nxt) {
                printf("Usage: tftp:client:host:file:\n");
                exit(1);
            }

            nxt = cpy_arg(&file, nxt);
        }
    } else {
        printf("Usage: tftp:tx|rx|p:...\n");
    }



    if (tftp_mode == TFTP_MODE_SRV)
    {
        pico_tftp_listen(PICO_PROTO_IPV4, tftp_listen_cb);
    } else if (tftp_mode == TFTP_MODE_CLI)
    {
        if(pico_tftp_start_rx((union pico_address *)&server, short_be(PICO_TFTP_PORT), PICO_PROTO_IPV4, file, cb_tftp) < 0) {
            fprintf(stderr, "TFTP: Error in initialization\n");
            exit(1);
        }
    } else if (tftp_mode == TFTP_MODE_PSH)
    {
        if(pico_tftp_start_tx((union pico_address *)&server, short_be(PICO_TFTP_PORT), PICO_PROTO_IPV4, file, cb_tftp_tx) < 0) {
            fprintf(stderr, "TFTP: Error in initialization\n");
            exit(1);
        }
    } else {
        printf("Usage: tftp:tx|rx|p:...\n");
    }
}
#endif
/* END TFTP */
