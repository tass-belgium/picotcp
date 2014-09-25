#include "utils.h"
#include <pico_stack.h>
#include <pico_tftp.h>
#include <pico_ipv4.h>
#include <pico_ipv6.h>

/* Let's use linux fs */
#include <fcntl.h>

#include<ctype.h>

/*** START TFTP ***/
#ifdef PICO_SUPPORT_TFTP
#define TFTP_MODE_SRV 0
#define TFTP_MODE_CLI 1
#define TFTP_MODE_PSH 2
#define TFTP_TX_COUNT 2000
#define TFTP_PAYLOAD_SIZE 512
unsigned char tftp_txbuf[TFTP_PAYLOAD_SIZE];
static uint16_t family;

struct command_t {
    char operation;
    char *filename;
    union pico_address server_address;
    struct command_t *next;
};

struct note_t {
    char *filename;
    int fd;
    char direction;
    uint32_t filesize;
    struct note_t *next;
};

struct note_t *clipboard = NULL;

struct note_t * add_note(const char *filename, int fd, char direction)
{
    struct note_t *note = PICO_ZALLOC(sizeof(struct note_t));

    note->filename = strdup(filename);
    note->fd = fd;
    note->direction = direction;
    note->filesize = 0;
    note->next = clipboard;
    clipboard = note;
    return note;
}

void del_note(struct note_t *note)
{
    struct note_t *prev;

    if (note == clipboard)
        clipboard = clipboard->next;
    else {
        for (prev = clipboard; prev->next; prev = prev->next)
            if (prev->next == note) {
                prev->next = note->next;
                break;
            }
        }
    free(note->filename);
    free(note);
}

struct command_t * add_command(struct command_t * commands, char operation,
                               char *filename, union pico_address *server_address)
{
    struct command_t *command = PICO_ZALLOC(sizeof(struct command_t));

    command->operation = operation;
    command->filename = filename;
    memcpy(&command->server_address, server_address, sizeof(union pico_address));
    command->next = commands;
    return command;
}

struct note_t * setup_transfer(char operation, char *filename)
{
    int fd;
    fd = open(filename, (operation == 'T')? O_RDONLY: O_WRONLY | O_EXCL | O_CREAT, 0666);
    if (fd < 0) {
        perror("open");
        fprintf(stderr, "Unable to handle file %s\n", filename);
        exit(3);
    }
    return add_note(filename, fd, operation);
}

int cb_tftp_tx(struct pico_tftp_session *session, uint16_t err, uint8_t *block, uint32_t len, void *arg)
{
    struct note_t *note = (struct note_t *) arg;

    if (err != PICO_TFTP_ERR_OK) {
        fprintf(stderr, "TFTP: Error %d: %s\n", err, block);
        exit(1);
    }

    len = read(note->fd, tftp_txbuf, PICO_TFTP_SIZE);

    if (len >= 0) {
        note->filesize += len;
        pico_tftp_send(session, tftp_txbuf, len);
        if (len < PICO_TFTP_SIZE) {
            printf("TFTP: file %s (%u bytes) TX transfer complete!\n", note->filename, note->filesize);
            close(note->fd);
            del_note(note);
        }
    } else {
        perror("read");
        fprintf(stderr, "Filesystem error reading file %s, cancelling current transfer\n", note->filename);
        pico_tftp_abort(session);
        del_note(note);
    }

    if (!clipboard)
        pico_timer_add(3000, deferred_exit, NULL);

    return len;
}

int cb_tftp_rx(struct pico_tftp_session *session, uint16_t err, uint8_t *block, uint32_t len, void *arg)
{
    struct note_t *note = (struct note_t *) arg;
    int ret;

    if (err != PICO_TFTP_ERR_OK) {
        fprintf(stderr, "TFTP: Error %d: %s\n", err, block);
        exit(1);
    }

    note->filesize += len;
    if (write(note->fd, block, len) < 0) {
        perror("write");
        fprintf(stderr, "Filesystem error writing file %s, cancelling current transfer\n", note->filename);
        pico_tftp_abort(session);
        del_note(note);
    } else {
        if (len != PICO_TFTP_SIZE) {
            printf("TFTP: file %s (%u bytes) RX transfer complete!\n", note->filename, note->filesize);
            close(note->fd);
            del_note(note);
        }
    }

    if (!clipboard)
        pico_timer_add(3000, deferred_exit, NULL);

    return len;
}

int tftp_listen_cb(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename)
{
    struct note_t *note;
    printf("TFTP listen callback from remote port %d.\n", short_be(port));
    if (opcode == PICO_TFTP_RRQ) {
        note = setup_transfer('T', filename);
        printf("Received TFTP get request for %s\n", filename);
        if(!pico_tftp_start_tx(addr, port, family, filename, cb_tftp_tx, (void *)note)) {
            fprintf(stderr, "TFTP: Error in initialization\n");
            exit(1);
        }
    } else if (opcode == PICO_TFTP_WRQ) {
        note = setup_transfer('R', filename);
        printf("Received TFTP put request for %s\n", filename);
        if(!pico_tftp_start_rx(addr, port, family, filename, cb_tftp_rx, (void *)note)) {
            fprintf(stderr, "TFTP: Error in initialization\n");
            exit(1);
        }
    } else {
        fprintf (stderr, "Received invalid TFTP request %d\n", opcode);
        return -1;
    }

    return 0;
}

void print_usage(int exit_code)
{
    printf("\nUsage: tftp:OPTION:[OPTION]...\n"
            "\nOtions can be repeated. Every option may be one of the following:\n"
            "\tS\t\t\t starts the server\n"
            "\tT:file:ip\t\t PUT request for file to server ip\n"
            "\tR:file:ip\t\t GET request for file to server ip\n"
            "Example:\n"
            "\t\t tftp:S:T:firstFile:10.40.0.2:R:another.file:10.40.0.5:T:secondFile:10.40.0.2\n\n");
    exit(exit_code);
}

struct command_t * parse_arguments_recursive(struct command_t *commands, char *arg)
{
    char *next;
    char *operation;
    char *filename;
    char *address;
    static union pico_address remote_address;
    int ret;
    char opcode;

    if (!arg)
        return commands;

    next = cpy_arg(&operation, arg);
    opcode = toupper(*operation);
    switch (opcode) {
    case 'S':
        filename = address = NULL;
        break;
    case 'T':
    case 'R':
        if (!next) {
            fprintf(stderr, "Incomplete client command %s (filename componet is missing)\n", arg);
            return NULL;
        }
        next = cpy_arg(&filename, next);
        if (!next) {
            fprintf(stderr, "Incomplete client command %s (address component is missing)\n", arg);
            return NULL;
        }
        next = cpy_arg(&address, next);
        if (!IPV6_MODE)
            ret = pico_string_to_ipv4(address, &remote_address.ip4.addr);
        else
            ret = pico_string_to_ipv6(address, remote_address.ip6.addr);

        if (ret < 0) {
                fprintf(stderr, "Invalid IP address %s\n", address);
                print_usage(2);
            }
        break;
    default:
        fprintf(stderr, "Invalid command %s\n", operation);
        return NULL;
    };

    return parse_arguments_recursive(add_command(commands, opcode, filename, &remote_address), next);
}

struct command_t * parse_arguments(char *arg)
{
    struct command_t *reversed = parse_arguments_recursive(NULL, arg);
    struct command_t *commands = NULL;
    struct command_t *current;

    if (!reversed) {
        fprintf(stderr, "Wrong command line!\n");
        print_usage(1);
    }

    while (reversed) {
        current = reversed;
        reversed = reversed->next;
        current->next = commands;
        commands = current;
    }

    return commands;
}

void app_tftp(char *arg)
{
    struct command_t *commands;
    struct note_t *note;
    int is_server_enabled = 0;

    family = IPV6_MODE? PICO_PROTO_IPV6: PICO_PROTO_IPV4;

    commands = parse_arguments(arg);
    while (commands) {
        switch (commands->operation) {
        case 'S':
            if (!is_server_enabled) {
                pico_tftp_listen(PICO_PROTO_IPV4, tftp_listen_cb);
                is_server_enabled = 1;
            }
            break;
        case 'T':
            note = setup_transfer(commands->operation, commands->filename);
            if (!pico_tftp_start_tx(&commands->server_address, short_be(PICO_TFTP_PORT),
                family, commands->filename, cb_tftp_tx, (void *)note)) {
                fprintf(stderr, "TFTP: Error in initialization\n");
                exit(3);
            }
            break;
        case 'R':
            note = setup_transfer(commands->operation, commands->filename);
            if (!pico_tftp_start_rx(&commands->server_address, short_be(PICO_TFTP_PORT),
                family, commands->filename, cb_tftp_rx, (void *)note)) {
                fprintf(stderr, "TFTP: Error in initialization\n");
                exit(3);
            }
        }
        commands = commands->next;
    }
}

#endif
/* END TFTP */
