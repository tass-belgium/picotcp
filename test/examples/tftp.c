#include "utils.h"
#include <pico_stack.h>
#include <pico_tftp.h>
#include <pico_ipv4.h>
#include <pico_ipv6.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>

/* Let's use linux fs */
#include <fcntl.h>

#include <ctype.h>

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
    int32_t filesize;
    struct note_t *next;
};

struct note_t *clipboard = NULL;

struct note_t *add_note(const char *filename, int fd, char direction)
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
    {
        clipboard = clipboard->next;
        if (note->filename)
            free (note->filename);

        PICO_FREE(note);
    } else {
        for (prev = clipboard; prev->next; prev = prev->next)
            if (prev->next == note) {
                prev->next = note->next;
                if (note->filename)
                    free (note->filename);

                PICO_FREE(note);
                break;
            }

    }
}

struct command_t *add_command(struct command_t *commands, char operation,
                              char *filename, union pico_address *server_address)
{
    struct command_t *command = PICO_ZALLOC(sizeof(struct command_t));

    command->operation = operation;
    command->filename = filename;
    memcpy(&command->server_address, server_address, sizeof(union pico_address));
    command->next = commands;
    return command;
}

int32_t get_filesize(const char *filename)
{
    int ret;
    struct stat buf;

    ret = stat(filename, &buf);
    if (ret)
        return -1;

    return buf.st_size;
}

struct note_t *setup_transfer(char operation, const char *filename)
{
    int fd;

    printf("operation %c\n", operation);
    fd = open(filename, (toupper(operation) == 'T') ? O_RDONLY : O_WRONLY | O_EXCL | O_CREAT, 0666);
    if (fd < 0) {
        perror("open");
        fprintf(stderr, "Unable to handle file %s\n", filename);
        return NULL;
    }

    return add_note(filename, fd, operation);
}

int cb_tftp_tx(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg)
{
    struct note_t *note = (struct note_t *) arg;

    if (event != PICO_TFTP_EV_OK) {
        fprintf(stderr, "TFTP: Error %" PRIu16 ": %s\n", event, block);
        exit(1);
    }

    len = read(note->fd, tftp_txbuf, PICO_TFTP_PAYLOAD_SIZE);

    if (len >= 0) {
        note->filesize += len;
        pico_tftp_send(session, tftp_txbuf, len);
        if (len < PICO_TFTP_PAYLOAD_SIZE) {
            printf("TFTP: file %s (%" PRId32 " bytes) TX transfer complete!\n", note->filename, note->filesize);
            close(note->fd);
            del_note(note);
        }
    } else {
        perror("read");
        fprintf(stderr, "Filesystem error reading file %s, cancelling current transfer\n", note->filename);
        pico_tftp_abort(session, TFTP_ERR_EACC, "Error on read");
        del_note(note);
    }

    if (!clipboard) {
        if (!pico_timer_add(3000, deferred_exit, NULL)) {
            printf("Failed to start exit timer, exiting now\n");
            exit(1);
        }
    }

    return len;
}

int cb_tftp_tx_opt(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg)
{
    int ret;
    int32_t filesize;

    if (event == PICO_TFTP_EV_OPT) {
        ret = pico_tftp_get_option(session, PICO_TFTP_OPTION_FILE, &filesize);
        if (ret)
            printf("TFTP: Option filesize is not used\n");
        else
            printf("TFTP: We expect to transmit %" PRId32 " bytes\n", filesize);

        event = PICO_TFTP_EV_OK;
    }

    return cb_tftp_tx(session, event, block, len, arg);
}

int cb_tftp_rx(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg)
{
    struct note_t *note = (struct note_t *) arg;
    int ret;

    if (event != PICO_TFTP_EV_OK) {
        fprintf(stderr, "TFTP: Error %" PRIu16 ": %s\n", event, block);
        exit(1);
    }

    if (!note)
        return 0;

    note->filesize += len;
    if (write(note->fd, block, len) < 0) {
        perror("write");
        fprintf(stderr, "Filesystem error writing file %s, cancelling current transfer\n", note->filename);
        pico_tftp_abort(session, TFTP_ERR_EACC, "Error on write");
        del_note(note);
    } else {
        if (len != PICO_TFTP_PAYLOAD_SIZE) {
            printf("TFTP: file %s (%" PRId32 " bytes) RX transfer complete!\n", note->filename, note->filesize);
            close(note->fd);
            del_note(note);
        }
    }

    if (!clipboard) {
        if (!pico_timer_add(3000, deferred_exit, NULL)) {
            printf("Failed to start exit timer, exiting now\n");
            exit(1);
        }
    }

    return len;
}

int cb_tftp_rx_opt(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg)
{
    int ret;
    int32_t filesize;

    if (event == PICO_TFTP_EV_OPT) {
        ret = pico_tftp_get_option(session, PICO_TFTP_OPTION_FILE, &filesize);
        if (ret)
            printf("TFTP: Option filesize is not used\n");
        else
            printf("TFTP: We expect to receive %" PRId32 " bytes\n", filesize);

        return 0;
    }

    return cb_tftp_rx(session, event, block, len, arg);
}

struct pico_tftp_session *make_session_or_die(union pico_address *addr, uint16_t family)
{
    struct pico_tftp_session *session;

    session = pico_tftp_session_setup(addr, family);
    if (!session) {
        fprintf(stderr, "TFTP: Error in session setup\n");
        exit(3);
    }

    return session;
}

struct note_t *transfer_prepare(struct pico_tftp_session **psession, char operation, const char *filename, union pico_address *addr, uint16_t family)
{
    struct note_t *note;

    note = setup_transfer(operation, filename);
    *psession = make_session_or_die(addr, family);
    return note;
}

void start_rx(struct pico_tftp_session *session, const char *filename, uint16_t port,
              int (*rx_callback)(struct pico_tftp_session *session, uint16_t err, uint8_t *block, int32_t len, void *arg),
              struct note_t *note)
{
    if (pico_tftp_start_rx(session, port, filename, rx_callback, note)) {
        fprintf(stderr, "TFTP: Error in initialization\n");
        exit(1);
    }
}

void start_tx(struct pico_tftp_session *session, const char *filename, uint16_t port,
              int (*tx_callback)(struct pico_tftp_session *session, uint16_t err, uint8_t *block, int32_t len, void *arg),
              struct note_t *note)
{
    if (pico_tftp_start_tx(session, port, filename, tx_callback, note)) {
        fprintf(stderr, "TFTP: Error in initialization\n");
        exit(1);
    }
}

void tftp_listen_cb(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename, int32_t len)
{
    struct note_t *note;
    struct pico_tftp_session *session;

    printf("TFTP listen callback (BASIC) from remote port %" PRIu16 ".\n", short_be(port));
    if (opcode == PICO_TFTP_RRQ) {
        printf("Received TFTP get request for %s\n", filename);
        note = transfer_prepare(&session, 't', filename, addr, family);
        start_tx(session, filename, port, cb_tftp_tx, note);
    } else if (opcode == PICO_TFTP_WRQ) {
        printf("Received TFTP put request for %s\n", filename);
        note = transfer_prepare(&session, 'r', filename, addr, family);
        start_rx(session, filename, port, cb_tftp_rx, note);
    }
}

void tftp_listen_cb_opt(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename, int32_t len)
{
    struct note_t *note;
    struct pico_tftp_session *session;
    int options;
    uint8_t timeout;
    int32_t filesize;
    int ret;

    printf("TFTP listen callback (OPTIONS) from remote port %" PRIu16 ".\n", short_be(port));
    /* declare the options we want to support */
    ret = pico_tftp_parse_request_args(filename, len, &options, &timeout, &filesize);
    if (ret)
        pico_tftp_reject_request(addr, port, TFTP_ERR_EOPT, "Malformed request");

    if (opcode == PICO_TFTP_RRQ) {
        printf("Received TFTP get request for %s\n", filename);
        note = transfer_prepare(&session, 'T', filename, addr, family);

        if (options & PICO_TFTP_OPTION_TIME)
            pico_tftp_set_option(session, PICO_TFTP_OPTION_TIME, timeout);

        if (options & PICO_TFTP_OPTION_FILE) {
            ret = get_filesize(filename);
            if (ret < 0) {
                pico_tftp_reject_request(addr, port, TFTP_ERR_ENOENT, "File not found");
                return;
            }

            pico_tftp_set_option(session, PICO_TFTP_OPTION_FILE, ret);
        }

        start_tx(session, filename, port, cb_tftp_tx_opt, note);
    } else { /* opcode == PICO_TFTP_WRQ */
        printf("Received TFTP put request for %s\n", filename);

        note = transfer_prepare(&session, 'R', filename, addr, family);
        if (options & PICO_TFTP_OPTION_TIME)
            pico_tftp_set_option(session, PICO_TFTP_OPTION_TIME, timeout);

        if (options & PICO_TFTP_OPTION_FILE)
            pico_tftp_set_option(session, PICO_TFTP_OPTION_FILE, filesize);

        start_rx(session, filename, port, cb_tftp_rx_opt, note);
    }
}

void print_usage(int exit_code)
{
    printf("\nUsage: tftp:OPTION:[OPTION]...\n"
           "\nOtions can be repeated. Every option may be one of the following:\n"
           "\ts\t\t\t starts the basic server (RFC1350)\n"
           "\tS\t\t\t starts the server with option handling capability\n"
           "\tt:file:ip\t\t PUT request (without options) for file to server ip\n"
           "\tT:file:ip\t\t PUT request for file to server ip\n"
           "\tr:file:ip\t\t GET request (without options) for file to server ip\n"
           "\tR:file:ip\t\t GET request for file to server ip\n"
           "Example:\n"
           "\t\t tftp:S:T:firstFile:10.40.0.2:R:another.file:10.40.0.5:T:secondFile:10.40.0.2\n\n");
    exit(exit_code);
}

struct command_t *parse_arguments_recursive(struct command_t *commands, char *arg)
{
    char *next;
    char *operation;
    char *filename;
    char *address;
    static union pico_address remote_address;
    int ret;
    struct command_t *new_cmd = NULL;

    if (!arg)
        return commands;

    next = cpy_arg(&operation, arg);
    switch (*operation) {
    case 'S':
    case 's':
        filename = address = NULL;
        break;
    case 'T':
    case 'R':
    case 't':
    case 'r':
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

        if (address)
            free(address);

        break;
    default:
        fprintf(stderr, "Invalid command %s\n", operation);
        return NULL;
    };

    new_cmd = add_command(commands, *operation, filename, &remote_address);
    free(operation);
    return parse_arguments_recursive(new_cmd, next);
}

struct command_t *parse_arguments(char *arg)
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
    struct command_t *commands, *old_cmd;
    struct note_t *note;
    struct pico_tftp_session *session;
    int is_server_enabled = 0;
    int filesize;

    family = IPV6_MODE ? PICO_PROTO_IPV6 : PICO_PROTO_IPV4;

    commands = parse_arguments(arg);
    while (commands) {

        if (toupper(commands->operation) != 'S')
            note = transfer_prepare(&session, commands->operation, commands->filename, &commands->server_address, family);

        switch (commands->operation) {
        case 'S':
        case 's':
            if (!is_server_enabled) {
                pico_tftp_listen(PICO_PROTO_IPV4, (commands->operation == 'S') ? tftp_listen_cb_opt : tftp_listen_cb);
                is_server_enabled = 1;
            }

            break;
        case 'T':
            filesize = get_filesize(commands->filename);
            if (filesize < 0) {
                fprintf(stderr, "TFTP: unable to read size of file %s\n", commands->filename);
                exit(3);
            }

            pico_tftp_set_option(session, PICO_TFTP_OPTION_FILE, filesize);
            start_tx(session, commands->filename, short_be(PICO_TFTP_PORT), cb_tftp_tx_opt, note);
            break;
        case 't':
            start_tx(session, commands->filename, short_be(PICO_TFTP_PORT), cb_tftp_tx, note);
            break;
        case 'R':
            pico_tftp_set_option(session, PICO_TFTP_OPTION_FILE, 0);
            start_rx(session, commands->filename, short_be(PICO_TFTP_PORT), cb_tftp_rx_opt, note);
            break;
        case 'r':
            start_rx(session, commands->filename, short_be(PICO_TFTP_PORT), cb_tftp_rx, note);
        }
        old_cmd = commands;
        commands = commands->next;
        if (old_cmd->filename)
            free(old_cmd->filename);

        /* commands are allocated using PICO_ZALLOC, so use PICO_FREE */
        PICO_FREE(old_cmd);
    }
}

#endif
/* END TFTP */
