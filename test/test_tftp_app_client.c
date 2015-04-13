#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <inttypes.h>
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_socket.h"
#include "pico_stack.h"
#include "pico_device.h"
#include "pico_dev_vde.h"
#include "pico_tftp.h"

static struct pico_device *pico_dev;

int32_t get_filesize(const char *filename)
{
    int ret;
    struct stat buf;

    ret = stat(filename, &buf);
    if (ret)
        return -1;

    return buf.st_size;
}

void start_rx(struct pico_tftp_session *session, int *synchro, const char *filename, int options)
{
    int ret;
    int fd;
    int32_t len;
    uint8_t buf[PICO_TFTP_PAYLOAD_SIZE];
    int left = 1000;
    int countdown = 0;

    printf("Start receiving file %s with options set to %d\n", filename, options);

    if (options) {
        ret = pico_tftp_set_option(session, PICO_TFTP_OPTION_FILE, 0);
        if (ret) {
            fprintf(stderr, "Error in pico_tftp_set_option\n");
            exit(1);
        }
    }

    ret = pico_tftp_app_start_rx(session, filename);
    if (ret) {
        fprintf(stderr, "Error in pico_tftp_app_start_rx\n");
        exit(1);
    }

    fd = open(filename, O_WRONLY | O_EXCL | O_CREAT, 0664);
    if (!fd) {
        fprintf(stderr, "Error in open\n");
        countdown = 1;
    }

    for(; left; left -= countdown) {
        usleep(2000); /* PICO_IDLE(); */
        pico_stack_tick();
        if (countdown)
            continue;

        if (*synchro) {
            len = pico_tftp_get(session, buf, PICO_TFTP_PAYLOAD_SIZE);
            if (len < 0) {
                fprintf(stderr, "Failure in pico_tftp_get\n");
                close(fd);
                countdown = 1;
                continue;
            }

            ret = write(fd, buf, len);
            if (ret < 0) {
                fprintf(stderr, "Error in write\n");
                pico_tftp_abort(session, TFTP_ERR_EXCEEDED, "File write error");
                close(fd);
                countdown = 1;
                continue;
            }

            printf("Written %" PRId32 " bytes to file (synchro=%d)\n", len, *synchro);

            if (len != PICO_TFTP_PAYLOAD_SIZE) {
                close(fd);
                printf("Transfer complete!\n");
                countdown = 1;
            }
        }
    }
}

void start_tx(struct pico_tftp_session *session, int *synchro, const char *filename, int options)
{
    int ret;
    int fd;
    int32_t len;
    uint8_t buf[PICO_TFTP_PAYLOAD_SIZE];
    int left = 1000;
    int countdown = 0;

    printf("Start sending file %s with options set to %d\n", filename, options);

    if (options) {
        ret = get_filesize(filename);
        if (ret < 0) {
            fprintf(stderr, "Error in get_filesize\n");
            exit(1);
        }

        ret = pico_tftp_set_option(session, PICO_TFTP_OPTION_FILE, ret);
        if (ret) {
            fprintf(stderr, "Error in pico_tftp_set_option\n");
            exit(1);
        }
    }

    ret = pico_tftp_app_start_tx(session, filename);
    if (ret) {
        fprintf(stderr, "Error in pico_tftp_app_start_rx\n");
        exit(1);
    }

    fd = open(filename, O_RDONLY, 0444);
    if (!fd) {
        fprintf(stderr, "Error in open\n");
        pico_tftp_abort(session, TFTP_ERR_EACC, "Error opening file");
        countdown = 1;
    }

    for(; left; left -= countdown) {
        usleep(2000); /* PICO_IDLE(); */
        pico_stack_tick();
        if (countdown)
            continue;

        if (*synchro) {
            ret = read(fd, buf, PICO_TFTP_PAYLOAD_SIZE);
            if (ret < 0) {
                fprintf(stderr, "Error in read\n");
                pico_tftp_abort(session, TFTP_ERR_EACC, "File read error");
                close(fd);
                countdown = 1;
                continue;
            }

            printf("Read %" PRId32 " bytes from file (synchro=%d)\n", len, *synchro);

            len = pico_tftp_put(session, buf, ret);
            if (len < 0) {
                fprintf(stderr, "Failure in pico_tftp_put\n");
                close(fd);
                countdown = 1;
                continue;
            }

            if (len != PICO_TFTP_PAYLOAD_SIZE) {
                close(fd);
                printf("Transfer complete!\n");
                countdown = 1;
            }
        }
    }
}

void usage(const char *text)
{
    fprintf(stderr, "%s\nArguments must be <filename> <mode>\n"
            "<mode> can be:\n"
            "\tg => GET request without options\n"
            "\tG => GET request WITH options\n"
            "\tp => PUT request without options\n"
            "\tP => PUT request WITH options\n\n",
            text);
    exit(1);
}

int main(int argc, char**argv)
{
    struct pico_ip4 my_ip;
    union pico_address server_address;
    struct pico_ip4 netmask;
    struct pico_tftp_session *session;
    int synchro;
    int options = 0;
    void (*operation)(struct pico_tftp_session *session, int *synchro, const char *filename, int options);

    unsigned char macaddr[6] = {
        0, 0, 0, 0xa, 0xb, 0x0
    };

    uint16_t *macaddr_low = (uint16_t *) (macaddr + 2);
    *macaddr_low = *macaddr_low ^ (uint16_t)((uint16_t)getpid() & (uint16_t)0xFFFFU);
    macaddr[4] ^= (uint8_t)(getpid() >> 8);
    macaddr[5] ^= (uint8_t) (getpid() & 0xFF);

    pico_string_to_ipv4("10.40.0.10", &my_ip.addr);
    pico_string_to_ipv4("255.255.255.0", &netmask.addr);
    pico_string_to_ipv4("10.40.0.2", &server_address.ip4.addr);

    if (argc != 3) {
        usage("Invalid number or arguments");
    }

    switch (argv[2][0]) {
    case 'G':
        options = 1;
    case 'g':
        operation = start_rx;
        break;
    case 'P':
        options = 1;
    case 'p':
        operation = start_tx;
        break;
    default:
        usage("Invalid mode");
    }

    printf("%s start!\n", argv[0]);
    pico_stack_init();
    pico_dev = (struct pico_device *) pico_vde_create("/tmp/vde_switch", "tap0", macaddr);

    if(!pico_dev) {
        fprintf(stderr, "Error creating pico device, got enough privileges? Exiting...\n");
        exit(1);
    }

    pico_ipv4_link_add(pico_dev, my_ip, netmask);
    printf("Starting picoTCP loop\n");

    session = pico_tftp_app_setup(&server_address, short_be(PICO_TFTP_PORT), PICO_PROTO_IPV4, &synchro);
    if (!session) {
        fprintf(stderr, "Error in pico_tftp_app_setup\n");
        exit(1);
    }

    printf("synchro %d\n", synchro);

    operation(session, &synchro, argv[1], options);
}
