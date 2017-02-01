/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   .

   Author: Daniele Lacamera
 *********************************************************************/

#include <pico_defines.h>
#include <pico_stack.h>
#include <pico_socket.h>
#include <pico_tftp.h>
#include <pico_strings.h>

#ifdef DEBUG_TFTP
#define tftp_dbg dbg
#else
#define tftp_dbg(...) do {} while(0)
#endif

/* a zero value means adaptative timeout! (2, 4, 8) */
#define PICO_TFTP_TIMEOUT 2000U

#define TFTP_MAX_RETRY 3

#define TFTP_STATE_READ_REQUESTED   0
#define TFTP_STATE_RX               1
#define TFTP_STATE_LAST_ACK_SENT    2
#define TFTP_STATE_WRITE_REQUESTED  3
#define TFTP_STATE_TX               4
#define TFTP_STATE_WAIT_OPT_CONFIRM 5
#define TFTP_STATE_WAIT_LAST_ACK    6
#define TFTP_STATE_CLOSING          7

#define AUTOMA_STATES (TFTP_STATE_CLOSING + 1)

/* MAX_OPTIONS_SIZE: "timeout" 255 "tsize" filesize =>  8 + 4 + 6 + 11 */
#define MAX_OPTIONS_SIZE 29

/* RRQ and WRQ packets (opcodes 1 and 2 respectively) */
PACKED_STRUCT_DEF pico_tftp_hdr
{
    uint16_t opcode;
};

/* DATA or ACK (opcodes 3 and 4 respectively)*/
PACKED_STRUCT_DEF pico_tftp_data_hdr
{
    uint16_t opcode;
    uint16_t block;
};

/* ERROR (opcode 5) */
PACKED_STRUCT_DEF pico_tftp_err_hdr
{
    uint16_t opcode;
    uint16_t error_code;
};

#define PICO_TFTP_TOTAL_BLOCK_SIZE (PICO_TFTP_PAYLOAD_SIZE + (int32_t)sizeof(struct pico_tftp_data_hdr))
#define tftp_payload(p) (((uint8_t *)(p)) + sizeof(struct pico_tftp_data_hdr))

/* STATUS FLAGS */
#define SESSION_STATUS_CLOSED       1
#define SESSION_STATUS_APP_PENDING  2
#define SESSION_STATUS_IN_CALLBACK  4
#define SESSION_STATUS_APP_ACK     64

struct pico_tftp_session {
    int state;
    int status;
    int options;
    int retry;
    uint16_t packet_counter;
    /* Current connection */
    struct pico_socket *socket;
    union pico_address remote_address;
    uint16_t remote_port;
    uint16_t localport;
    pico_time wallclock_timeout;
    pico_time bigger_wallclock;
    struct pico_tftp_session *next;
    uint32_t timer;
    unsigned int active_timers;
    void *argument;
    int (*callback)(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg);
    int32_t file_size;
    int32_t len;
    uint8_t option_timeout;
    uint8_t tftp_block[PICO_TFTP_TOTAL_BLOCK_SIZE];
    int32_t block_len;
};

struct server_t {
    void (*listen_callback)(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename, int32_t len);
    struct pico_socket *listen_socket;
    uint8_t tftp_block[PICO_TFTP_TOTAL_BLOCK_SIZE];
};

struct automa_events {
    void (*ack)(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port);
    void (*data)(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port);
    void (*error)(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port);
    void (*oack)(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port);
    void (*timeout)(struct pico_tftp_session *session, pico_time t);
};

static struct server_t server;

static struct pico_tftp_session *tftp_sessions = NULL;

static inline void session_status_set(struct pico_tftp_session *session, int status)
{
    session->status |= status;
}

static inline void session_status_clear(struct pico_tftp_session *session, int status)
{
    session->status &= ~status;
}

static char *extract_arg_pointer(char *arg, char *end_arg, char **value)
{
    char *pos;

    pos = get_string_terminator_position(arg, (size_t)(end_arg - arg));
    if (!pos)
        return NULL;

    if (end_arg == ++pos)
        return NULL;

    arg = get_string_terminator_position(pos, (size_t)(end_arg - pos));

    if (!arg)
        return NULL;

    *value = pos;
    return arg + 1;
}

static int extract_value(char *str, uint32_t *value, uint32_t max)
{
    char *endptr;
    unsigned long num;

    num = strtoul(str, &endptr, 10);

    if (endptr == str || *endptr || num > max)
        return -1;

    *value = (uint32_t)num;
    return 0;
}

static int parse_optional_arguments(char *option_string, int32_t len, int *options, uint8_t *timeout, int32_t *filesize)
{
    char *pos;
    char *end_args = option_string + len;
    char *current_option;
    int ret;
    uint32_t value;

    *options = 0;

    while (option_string < end_args) {
        current_option = option_string;
        option_string = extract_arg_pointer(option_string, end_args, &pos);
        if (!option_string)
            return 0;

        if (!pico_strncasecmp("timeout", current_option, (size_t)(pos - current_option))) {
            ret = extract_value(pos, &value, PICO_TFTP_MAX_TIMEOUT);
            if (ret)
                return -1;

            *timeout = (uint8_t)value;
            *options |= PICO_TFTP_OPTION_TIME;
        } else {
            if (!pico_strncasecmp("tsize", current_option, (size_t)(pos - current_option))) {
                ret = extract_value(pos, (uint32_t *)filesize, PICO_TFTP_MAX_FILESIZE);
                if (ret)
                    return -1;

                if (*filesize < 0)
                    return -1;

                *options |= PICO_TFTP_OPTION_FILE;
            }
        }
    }
    return 0;
}

static inline struct pico_tftp_session *pico_tftp_session_create(struct pico_socket *sock, union pico_address *remote_addr)
{
    struct pico_tftp_session *session;

    session = (struct pico_tftp_session *) PICO_ZALLOC(sizeof (struct pico_tftp_session));

    if (!session)
        pico_err = PICO_ERR_ENOMEM;
    else {
        session->state = 0;
        session->status = 0;
        session->options = 0;
        session->packet_counter = 0u;
        session->socket = sock;
        session->wallclock_timeout = 0;
        session->bigger_wallclock = 0;
        session->active_timers = 0;
        session->next = NULL;
        session->localport = 0;
        session->callback = NULL;
        session->argument = NULL;
        memcpy(&session->remote_address, remote_addr, sizeof(union pico_address));
        session->remote_port = 0;
        session->len = 0;
    }

    return session;
}

static struct pico_tftp_session *find_session_by_socket(struct pico_socket *tftp_socket)
{
    struct pico_tftp_session *pos = tftp_sessions;

    for (; pos; pos = pos->next)
        if (pos->socket == tftp_socket)
            return pos;

    return NULL;
}

/* **************** for future use...
   static struct pico_tftp_session * find_session_by_localport(uint16_t localport)
   {
    struct pico_tftp_session *idx = tftp_sessions;

    for (; idx; idx = idx->next)
        if (idx->localport == localport)
            return idx;

    return NULL;
   } *********************/

static void add_session(struct pico_tftp_session *idx)
{
    struct pico_tftp_session *prev = NULL;
    struct pico_tftp_session *pos;

    for (pos = tftp_sessions; pos; prev = pos, pos = pos->next)
        if (pos->localport > idx->localport)
            break;

    if (prev) {
        idx->next = prev->next;
        prev->next = idx;
    } else {
        idx->next = tftp_sessions;
        tftp_sessions = idx;
    }
}

/* Returns 0 if OK and -1 in case of errors */
static int del_session(struct pico_tftp_session *idx)
{
    struct pico_tftp_session *prev = NULL;
    struct pico_tftp_session *pos;

    for (pos = tftp_sessions; pos; pos = pos->next) {
        if (pos == idx) {
            if (pos == tftp_sessions)
                tftp_sessions = tftp_sessions->next;
            else
                prev->next = pos->next;

            PICO_FREE(idx);
            return 0;
        }

        prev = pos;
    }
    return -1;
}

static inline int do_callback(struct pico_tftp_session *session, uint16_t err, uint8_t *data, int32_t len)
{
    int ret;

    session_status_set(session, SESSION_STATUS_IN_CALLBACK);
    ret = session->callback(session, err, data, len, session->argument);
    session_status_clear(session, SESSION_STATUS_IN_CALLBACK);

    return ret;
}

static void timer_callback(pico_time now, void *arg);
static void tftp_finish(struct pico_tftp_session *session);

static void tftp_schedule_timeout(struct pico_tftp_session *session, pico_time interval)
{
    pico_time new_timeout = PICO_TIME_MS() + interval;

    if (session->active_timers) {
        if (session->bigger_wallclock > new_timeout) {
            session->timer = pico_timer_add(interval + 1, timer_callback, session);
            if (!session->timer) {
                tftp_dbg("TFTP: Failed to start callback timer, deleting session\n");
                tftp_finish(session);
                return;
            }
            session->active_timers++;
        }
    } else {
        session->timer = pico_timer_add(interval + 1, timer_callback, session);
        if (!session->timer) {
            tftp_dbg("TFTP: Failed to start callback timer, deleting session\n");
            tftp_finish(session);
            return;
        }
        session->active_timers++;
        session->bigger_wallclock = new_timeout;
    }

    session->wallclock_timeout = new_timeout;
}

static void tftp_finish(struct pico_tftp_session *session)
{
    if (session->state != TFTP_STATE_CLOSING) {
        pico_socket_close(session->socket);
        session->state = TFTP_STATE_CLOSING;
        if (session->active_timers) {
            pico_timer_cancel(session->timer);
            --session->active_timers;
        }

        session->wallclock_timeout = 0;
        tftp_schedule_timeout(session, 5);
    }
}

static void tftp_send(struct pico_tftp_session *session, int len)
{
    if (len)
        session->len = len;
    else
        len = session->len;

    pico_socket_sendto(session->socket, session->tftp_block, session->len, &session->remote_address, session->remote_port);
}

static void tftp_send_ack(struct pico_tftp_session *session)
{
    struct pico_tftp_data_hdr *dh;

    dh = PICO_ZALLOC(sizeof(struct pico_tftp_data_hdr));
    if (!dh)
        return;

    dh->opcode = short_be(PICO_TFTP_ACK);
    dh->block = short_be(session->packet_counter);

    if (session->socket) {
        pico_socket_sendto(session->socket, dh, (int) sizeof(struct pico_tftp_err_hdr),
                           &session->remote_address, session->remote_port);
        tftp_schedule_timeout(session, PICO_TFTP_TIMEOUT);
    }

    PICO_FREE(dh);
}

static size_t prepare_options_string(struct pico_tftp_session *session, char *str_options, int32_t filesize)
{
    size_t len = 0;
    int res;

    if (session->options & PICO_TFTP_OPTION_TIME) {
        strcpy(str_options, "timeout");
        len += 8;
        res = num2string(session->option_timeout, &str_options[len], 4);
        if (res < 0)
            return 0;

        len += (size_t)res;
    }

    if (session->options & PICO_TFTP_OPTION_FILE) {
        strcpy(&str_options[len], "tsize");
        len += 6;
        res = num2string(filesize, &str_options[len], 11);
        if (res < 0)
            return 0;

        len += (size_t)res;
    }

    return len;
}

static void tftp_send_oack(struct pico_tftp_session *session)
{
    struct pico_tftp_hdr *hdr;
    size_t options_size;
    size_t options_pos = sizeof(struct pico_tftp_hdr);
    uint8_t *buf;
    char str_options[MAX_OPTIONS_SIZE] = {
        0
    };

    options_size = prepare_options_string(session, str_options, session->file_size);

    buf = PICO_ZALLOC(options_pos + options_size);
    if (!buf) {
        strcpy((char *)session->tftp_block, "Out of memory");
        do_callback(session, PICO_TFTP_EV_ERR_LOCAL, session->tftp_block, 0);
        tftp_finish(session);
        return;
    }

    hdr = (struct pico_tftp_hdr *)buf;
    hdr->opcode = short_be(PICO_TFTP_OACK);
    memcpy(buf + options_pos, str_options, options_size);
    (void)pico_socket_sendto(session->socket, buf, (int)(options_pos + options_size), &session->remote_address, session->remote_port);
    PICO_FREE(buf);
}

static void tftp_send_req(struct pico_tftp_session *session, union pico_address *a, uint16_t port, const char *filename, uint16_t opcode)
{
#define OCTET_STRSIZ 7U
    static const char octet[OCTET_STRSIZ] = {
        0, 'o', 'c', 't', 'e', 't', 0
    };
    struct pico_tftp_hdr *hdr;
    size_t len;
    size_t options_size;
    size_t options_pos;
    uint8_t *buf;
    char str_options[MAX_OPTIONS_SIZE] = {
        0
    };

    if (!filename) {
        return;
    }

    len = strlen(filename);

    options_size = prepare_options_string(session, str_options, (opcode == PICO_TFTP_WRQ) ? (session->file_size) : (0));

    options_pos = sizeof(struct pico_tftp_hdr) + OCTET_STRSIZ + len;
    buf = PICO_ZALLOC(options_pos + options_size);
    if (!buf) {
        strcpy((char *)session->tftp_block, "Out of memory");
        do_callback(session, PICO_TFTP_EV_ERR_LOCAL, session->tftp_block, 0);
        tftp_finish(session);
        return;
    }

    hdr = (struct pico_tftp_hdr *)buf;
    hdr->opcode = short_be(opcode);
    memcpy(buf + sizeof(struct pico_tftp_hdr), filename, len);
    memcpy(buf + sizeof(struct pico_tftp_hdr) + len, octet, OCTET_STRSIZ);
    memcpy(buf + options_pos, str_options, options_size);
    (void)pico_socket_sendto(session->socket, buf, (int)(options_pos + options_size), a, port);
    PICO_FREE(buf);
}

static void tftp_send_rx_req(struct pico_tftp_session *session, union pico_address *a, uint16_t port, const char *filename)
{
    tftp_send_req(session, a, port, filename, PICO_TFTP_RRQ);
    session->state = TFTP_STATE_READ_REQUESTED;
    tftp_schedule_timeout(session, PICO_TFTP_TIMEOUT);
}

static void tftp_send_tx_req(struct pico_tftp_session *session, union pico_address *a, uint16_t port, const char *filename)
{
    tftp_send_req(session, a, port, filename, PICO_TFTP_WRQ);
    session->state = TFTP_STATE_WRITE_REQUESTED;
    tftp_schedule_timeout(session, PICO_TFTP_TIMEOUT);
}

static int send_error(uint8_t *buf, struct pico_socket *sock, union pico_address *a, uint16_t port, uint16_t errcode, const char *errmsg)
{
    struct pico_tftp_err_hdr *eh;
    int32_t len;
    int32_t maxlen = PICO_TFTP_TOTAL_BLOCK_SIZE - sizeof(struct pico_tftp_err_hdr);

    if (!errmsg)
        len = 0;
    else
        len = (int32_t)strlen(errmsg);

    eh = (struct pico_tftp_err_hdr *) buf;
    eh->opcode = short_be(PICO_TFTP_ERROR);
    eh->error_code = short_be(errcode);
    if (len + 1 > maxlen)
        len = maxlen;

    if (len)
        memcpy(tftp_payload(eh), errmsg, (size_t)len);

    tftp_payload(eh)[len++] = (char)0;

    return pico_socket_sendto(sock, eh, (int)(len + (int32_t)sizeof(struct pico_tftp_err_hdr)), a, port);
}

static void tftp_send_error(struct pico_tftp_session *session, union pico_address *a, uint16_t port, uint16_t errcode, const char *errmsg)
{
    struct pico_tftp_err_hdr *eh;
    int32_t len;
    int32_t maxlen = PICO_TFTP_TOTAL_BLOCK_SIZE - sizeof(struct pico_tftp_err_hdr);

    if (!errmsg)
        len = 0;
    else
        len = (int32_t)strlen(errmsg);

    if (!a) {
        a = &session->remote_address;
        port = session->remote_port;
    }

    eh = (struct pico_tftp_err_hdr *) (session ? (session->tftp_block) : (server.tftp_block));
    eh->opcode = short_be(PICO_TFTP_ERROR);
    eh->error_code = short_be(errcode);
    if (len + 1 > maxlen)
        len = maxlen;

    if (len)
        memcpy(tftp_payload(eh), errmsg, (size_t)len);

    tftp_payload(eh)[len++] = (char)0;
    if (session) {
        (void)pico_socket_sendto(session->socket, eh, (int) (len + (int32_t)sizeof(struct pico_tftp_err_hdr)), a, port);
        tftp_finish(session);
    } else
        (void)pico_socket_sendto(server.listen_socket, eh, (int) (len + (int32_t)sizeof(struct pico_tftp_err_hdr)), a, port);
}

static void tftp_send_data(struct pico_tftp_session *session, const uint8_t *data, int32_t len)
{
    struct pico_tftp_data_hdr *dh;

    dh = (struct pico_tftp_data_hdr *) session->tftp_block;
    dh->opcode = short_be(PICO_TFTP_DATA);
    dh->block = short_be(session->packet_counter++);

    if (len < PICO_TFTP_PAYLOAD_SIZE)
        session->state = TFTP_STATE_WAIT_LAST_ACK;
    else
        session->state = TFTP_STATE_TX;

    memcpy(session->tftp_block + sizeof(struct pico_tftp_data_hdr), data, (size_t)len);
    pico_socket_sendto(session->socket, session->tftp_block, (int)(len + (int32_t)sizeof(struct pico_tftp_data_hdr)),
                       &session->remote_address, session->remote_port);
    tftp_schedule_timeout(session, PICO_TFTP_TIMEOUT);
}

static inline void tftp_eval_finish(struct pico_tftp_session *session, int32_t len)
{
    if (len < PICO_TFTP_PAYLOAD_SIZE) {
        pico_socket_close(session->socket);
        session->state = TFTP_STATE_CLOSING;
    }
}

static inline int tftp_data_prepare(struct pico_tftp_session *session, union pico_address *a, uint16_t port)
{
    if (!session->socket)
        return -1;

    if (pico_address_compare(a, &session->remote_address, session->socket->net->proto_number) != 0) {
        tftp_send_error(session, a, port, TFTP_ERR_EXCEEDED, "TFTP busy, try again later.");
        return -1;
    }

    return 0;
}

static void tftp_req(uint8_t *block, int32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_hdr *hdr = (struct pico_tftp_hdr *)block;
    char *filename;
    char *pos;
    char *mode;
    int ret;

    switch (short_be(hdr->opcode)) {
    case PICO_TFTP_RRQ:
    case PICO_TFTP_WRQ:
        filename = (char *)(block + sizeof(struct pico_tftp_hdr));
        len -= (int32_t)sizeof(struct pico_tftp_hdr);

        pos = extract_arg_pointer(filename, filename + len, &mode);
        if (!pos) {
            send_error(block, server.listen_socket, a, port, TFTP_ERR_EILL, "Invalid argument in request");
            return;
        }

        ret = strcmp("octet", mode);
        if (ret) {
            send_error(block, server.listen_socket, a, port, TFTP_ERR_EILL, "Unsupported mode");
            return;
        }

        /*ret = parse_optional_arguments((char *)(block + sizeof(struct pico_tftp_hdr)), len - sizeof(struct pico_tftp_hdr), &new_options, &new_timeout, &new_filesize);
           if (ret) {
            tftp_send_error(NULL, a, port, TFTP_ERR_EILL, "Bad request");
            return;
           } */

        if (server.listen_callback) {
            server.listen_callback(a, port, short_be(hdr->opcode), filename, len);
        }

        break;
    default:
        send_error(block, server.listen_socket, a, port, TFTP_ERR_EILL, "Illegal opcode");
    }
}

static int event_ack_base(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;
    uint16_t block_n;
    const char *wrong_address = "Wrong address";
    const char *wrong_block = "Wrong packet number";

    (void)len;
    if (pico_address_compare(a, &session->remote_address, session->socket->net->proto_number) != 0) {
        strcpy((char *)session->tftp_block, wrong_address);
        do_callback(session, PICO_TFTP_EV_ERR_PEER, session->tftp_block, len);
        tftp_send_error(session, a, port, TFTP_ERR_EXCEEDED, wrong_address);
        return -1;
    }

    dh = (struct pico_tftp_data_hdr *)session->tftp_block;
    block_n = short_be(dh->block);
    if (block_n != (session->packet_counter - 1U)) {
        strcpy((char *)session->tftp_block, wrong_block);
        do_callback(session, PICO_TFTP_EV_ERR_PEER, session->tftp_block, len);
        tftp_send_error(session, a, port, TFTP_ERR_EILL, wrong_block);
        return -1;
    }

    return 0;
}

static inline int event_ack0_check(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;
    uint16_t block_n;

    (void)len;
    if (pico_address_compare(a, &session->remote_address, session->socket->net->proto_number) != 0) {
        tftp_send_error(session, a, port, TFTP_ERR_EXCEEDED, "TFTP busy, try again later.");
        return -1;
    }

    dh = (struct pico_tftp_data_hdr *)session->tftp_block;
    block_n = short_be(dh->block);
    if (block_n != 0) {
        tftp_send_error(session, a, port, TFTP_ERR_EILL, "TFTP connection broken!");
        return -1;
    }

    return 0;
}

static void event_ack0_wr(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    if (!event_ack0_check(session, len, a, port)) {
        session->remote_port = port;
        do_callback(session, PICO_TFTP_EV_OK, session->tftp_block, 0);
    }
}

static void event_ack0_woc(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    if (!event_ack0_check(session, len, a, port))
        do_callback(session, PICO_TFTP_EV_OPT, session->tftp_block, 0);
}

static void event_ack(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    if (!event_ack_base(session, len, a, port))
        do_callback(session, PICO_TFTP_EV_OK, session->tftp_block, 0);
}

static void event_ack_last(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    if (!event_ack_base(session, len, a, port))
        tftp_finish(session);
}

static void event_data(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;
    int32_t payload_len = len - (int32_t)sizeof(struct pico_tftp_data_hdr);

    if (tftp_data_prepare(session, a, port))
        return;

    dh = (struct pico_tftp_data_hdr *)session->tftp_block;
    if (short_be(dh->block) > (session->packet_counter +  1U)) {
        strcpy((char *)session->tftp_block, "Wrong/unexpected sequence number");
        do_callback(session, PICO_TFTP_EV_ERR_LOCAL, session->tftp_block, 0);
        tftp_send_error(session, a, port, TFTP_ERR_EILL, "TFTP connection broken!");
        return;
    }

    if (short_be(dh->block) == (session->packet_counter + 1U)) {
        session->packet_counter++;
        if (do_callback(session, PICO_TFTP_EV_OK, tftp_payload(session->tftp_block), payload_len) >= 0) {
            if (!(session->status & SESSION_STATUS_APP_ACK))
                tftp_send_ack(session);
        }

        if (!(session->status & SESSION_STATUS_APP_ACK))
            tftp_eval_finish(session, len);
    }
}

static void event_data_rdr(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    if (tftp_data_prepare(session, a, port))
        return;

    session->remote_port = port;
    session->state = TFTP_STATE_RX;
    event_data(session, len, a, port);
}

static void event_data_rpl(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;

    (void)len;
    if (tftp_data_prepare(session, a, port))
        return;

    dh = (struct pico_tftp_data_hdr *)session->tftp_block;

    if (short_be(dh->block) == session->packet_counter)
        tftp_send_ack(session);
}

static void event_err(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    (void)a;
    (void)port;
    do_callback(session, PICO_TFTP_EV_ERR_PEER, session->tftp_block, len);
    tftp_finish(session);
}

static inline void event_oack(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    char *option_string = (char *)session->tftp_block + sizeof(struct pico_tftp_hdr);
    int ret;
    int proposed_options = session->options;

    (void)a;

    session->remote_port = port;

    ret = parse_optional_arguments(option_string, len - (int32_t)sizeof(struct pico_tftp_hdr), &session->options, &session->option_timeout, &session->file_size);
    if (ret || (session->options & ~proposed_options)) {
        do_callback(session, PICO_TFTP_EV_ERR_PEER, session->tftp_block, len);
        tftp_send_error(session, a, port, TFTP_ERR_EOPT, "Invalid option");
        return;
    }

    do_callback(session, PICO_TFTP_EV_OPT, session->tftp_block, len);
}

static void event_oack_rr(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    event_oack(session, len, a, port);
    tftp_send_ack(session);
    session->state = TFTP_STATE_RX;
}

static void event_oack_wr(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    event_oack(session, len, a, port);
    session->state = TFTP_STATE_TX;
}

static void event_timeout(struct pico_tftp_session *session, pico_time t)
{
    pico_time new_timeout;
    int factor;

    (void)t;
    if (++session->retry == TFTP_MAX_RETRY) {
        strcpy((char *)session->tftp_block, "Network timeout");
        do_callback(session, PICO_TFTP_EV_ERR_PEER, session->tftp_block, 0);
        tftp_finish(session);
        return;
    }

    tftp_send(session, 0);
    if (session->options & PICO_TFTP_OPTION_TIME)
        new_timeout = session->option_timeout * 1000U;
    else {
        new_timeout = PICO_TFTP_TIMEOUT;
        for (factor = session->retry; factor; --factor)
            new_timeout *= 2;
    }

    tftp_schedule_timeout(session, new_timeout);
}

static void event_timeout_closing(struct pico_tftp_session *session, pico_time t)
{
    (void)t;
    if (session->active_timers == 0)
        del_session(session);
}

static void event_timeout_final(struct pico_tftp_session *session, pico_time t)
{
    (void)t;

    tftp_finish(session);
}

static void unexpected(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    (void)len;
    tftp_send_error(session, a, port, TFTP_ERR_EILL, "Unexpected message");
}

static void null(struct pico_tftp_session *session, int32_t len, union pico_address *a, uint16_t port)
{
    (void)session;
    (void)len;
    (void)a;
    (void)port;
}

static struct automa_events fsm[AUTOMA_STATES] = {
    /*   STATE                       *     ACK          DATA            ERROR       OACK            TIMEOUT              */
    /* ***************************************************************************************************************** */
    { /* TFTP_STATE_READ_REQUESTED   */ unexpected,     event_data_rdr, event_err,  event_oack_rr,  event_timeout},
    { /* TFTP_STATE_RX               */ unexpected,     event_data,     event_err,  unexpected,     event_timeout},
    { /* TFTP_STATE_LAST_ACK_SENT    */ unexpected,     event_data_rpl, null,       unexpected,     event_timeout_final},
    { /* TFTP_STATE_WRITE_REQUESTED  */ event_ack0_wr,  unexpected,     event_err,  event_oack_wr,  event_timeout},
    { /* TFTP_STATE_TX               */ event_ack,      unexpected,     event_err,  unexpected,     event_timeout},
    { /* TFTP_STATE_WAIT_OPT_CONFIRM */ event_ack0_woc, unexpected,     event_err,  unexpected,     event_timeout},
    { /* TFTP_STATE_WAIT_LAST_ACK    */ event_ack_last, unexpected,     event_err,  unexpected,     event_timeout},
    { /* TFTP_STATE_CLOSING          */ null,           null,           null,       null,           event_timeout_closing}
};

static void tftp_message_received(struct pico_tftp_session *session, uint8_t *block, int32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_hdr *th = (struct pico_tftp_hdr *) block;

    if (!session->callback)
        return;

    session->wallclock_timeout = 0;

    switch (short_be(th->opcode)) {
    case PICO_TFTP_RRQ:
    case PICO_TFTP_WRQ:
        unexpected(session, len, a, port);
        break;
    case PICO_TFTP_DATA:
        fsm[session->state].data(session, len, a, port);
        break;
    case PICO_TFTP_ACK:
        fsm[session->state].ack(session, len, a, port);
        break;
    case PICO_TFTP_ERROR:
        fsm[session->state].error(session, len, a, port);
        break;
    case PICO_TFTP_OACK:
        fsm[session->state].oack(session, len, a, port);
        break;
    default:
        tftp_send_error(session, NULL, 0, TFTP_ERR_EILL, "Illegal opcode");
    }
}

static void tftp_cb(uint16_t ev, struct pico_socket *s)
{
    int r;
    struct pico_tftp_session *session;
    union pico_address ep;
    uint16_t port = 0;

    session = find_session_by_socket(s);
    if (session) {
        if (ev == PICO_SOCK_EV_ERR) {
            strcpy((char *)session->tftp_block, "Socket Error");
            do_callback(session, PICO_TFTP_EV_ERR_LOCAL, session->tftp_block, (int32_t)strlen((char *)session->tftp_block));
            tftp_finish(session);
            return;
        }

        r = pico_socket_recvfrom(s, session->tftp_block, PICO_TFTP_TOTAL_BLOCK_SIZE, &ep, &port);
        if (r < (int)sizeof(struct pico_tftp_hdr))
            return;

        tftp_message_received(session, session->tftp_block, r, &ep, port);
    } else {
        if (!server.listen_socket || s != server.listen_socket) {
            return;
        }

        r = pico_socket_recvfrom(s, server.tftp_block, PICO_TFTP_TOTAL_BLOCK_SIZE, &ep, &port);
        if (r < (int)sizeof(struct pico_tftp_hdr))
            return;

        tftp_req(server.tftp_block, r, &ep, port);
    }
}

static int application_rx_cb(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg)
{
    int *flag = (int *)arg;

    (void)block;

    switch (event) {
    case PICO_TFTP_EV_ERR_PEER:
    case PICO_TFTP_EV_ERR_LOCAL:
        *flag = 0 - event;
        break;
    case PICO_TFTP_EV_OK:
        session->len = len;
        *flag = 1;
        break;
    case PICO_TFTP_EV_OPT:
        break;
    }
    return 0;
}

static int application_tx_cb(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg)
{
    (void)session;
    (void)block;
    (void)len;

    *(int*)arg = ((event == PICO_TFTP_EV_OK) || (event == PICO_TFTP_EV_OPT)) ? (1) : (0 - event);
    return 0;
}

static void timer_callback(pico_time now, void *arg)
{
    struct pico_tftp_session *session = (struct pico_tftp_session *)arg;

    --session->active_timers;
    if (session->wallclock_timeout == 0) {
        /* Timer is cancelled. */
        return;
    }

    if (now >= session->wallclock_timeout) {
        session->wallclock_timeout = 0ULL;
        fsm[session->state].timeout(session, now);
    } else {
        tftp_schedule_timeout(session, session->wallclock_timeout - now);
    }
}

static struct pico_socket *tftp_socket_open(uint16_t family, uint16_t localport)
{
    struct pico_socket *sock;
    union pico_address local_address;

    sock = pico_socket_open(family, PICO_PROTO_UDP, tftp_cb);
    if (!sock)
        return NULL;

    localport = short_be(localport);

    memset(&local_address, 0, sizeof(union pico_address));
    if (pico_socket_bind(sock, &local_address, &localport) < 0) {
        pico_socket_close(sock);
        return NULL;
    }

    return sock;
}

static inline int tftp_start_check(struct pico_tftp_session *session, uint16_t port, const char *filename,
                                   int (*user_cb)(struct pico_tftp_session *session, uint16_t err, uint8_t *block, int32_t len, void *arg))
{
    if (!session) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if ((!server.listen_socket) && (port != short_be(PICO_TFTP_PORT))) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (!filename) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (!user_cb) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;
}

/*   ***   EXPORTED FUNCTIONS   ***   */

struct pico_tftp_session *pico_tftp_session_setup(union pico_address *a, uint16_t family)
{
    struct pico_socket *sock;

    sock = tftp_socket_open(family, 0);
    if (!sock)
        return NULL;

    return pico_tftp_session_create(sock, a);
}

int pico_tftp_get_option(struct pico_tftp_session *session, uint8_t type, int32_t *value)
{
    if (!session) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (type) {
    case PICO_TFTP_OPTION_FILE:
        if (session->options & PICO_TFTP_OPTION_FILE)
            *value = session->file_size;
        else {
            pico_err = PICO_ERR_ENOENT;
            return -1;
        }

        break;
    case PICO_TFTP_OPTION_TIME:
        if (session->options & PICO_TFTP_OPTION_TIME)
            *value = session->option_timeout;
        else {
            pico_err = PICO_ERR_ENOENT;
            return -1;
        }

        break;
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;
}

int pico_tftp_set_option(struct pico_tftp_session *session, uint8_t type, int32_t value)
{
    if (!session) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (type) {
    case PICO_TFTP_OPTION_FILE:
        if (value < 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        session->file_size = value;
        session->options |= PICO_TFTP_OPTION_FILE;
        break;
    case PICO_TFTP_OPTION_TIME:
        if (value > PICO_TFTP_MAX_TIMEOUT) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        session->option_timeout = (uint8_t)(value & 0xFF);
        if (value) {
            session->options |= PICO_TFTP_OPTION_TIME;
        } else {
            session->options &= ~PICO_TFTP_OPTION_TIME;
        }

        break;
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;
}

/* Active RX request from PicoTCP */
int pico_tftp_start_rx(struct pico_tftp_session *session, uint16_t port, const char *filename,
                       int (*user_cb)(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg), void *arg)
{
    if (tftp_start_check(session, port, filename, user_cb))
        return -1;

    session->callback = user_cb;
    session->packet_counter = 0u;
    session->argument = arg;

    add_session(session);

    if (port != short_be(PICO_TFTP_PORT)) {
        session->remote_port = port;
        session->state = TFTP_STATE_RX;
        if (session->options & (PICO_TFTP_OPTION_FILE | PICO_TFTP_OPTION_TIME))
            tftp_send_oack(session);
        else
            tftp_send_ack(session);
    } else {
        tftp_send_rx_req(session, &session->remote_address, port, filename);
    }

    return 0;
}

int pico_tftp_start_tx(struct pico_tftp_session *session, uint16_t port, const char *filename,
                       int (*user_cb)(struct pico_tftp_session *session, uint16_t event, uint8_t *block, int32_t len, void *arg), void *arg)
{
    if (tftp_start_check(session, port, filename, user_cb))
        return -1;

    session->callback = user_cb;
    session->packet_counter = 1u;
    session->argument = arg;

    add_session(session);

    if (port != short_be(PICO_TFTP_PORT)) {
        session->remote_port = port;
        if (session->options) {
            tftp_send_oack(session);
            session->state = TFTP_STATE_WAIT_OPT_CONFIRM;
        } else {
            do_callback(session, PICO_TFTP_EV_OK, NULL, 0);
        }
    } else
        tftp_send_tx_req(session, &session->remote_address, port, filename);

    return 0;
}

int pico_tftp_reject_request(union pico_address*addr, uint16_t port, uint16_t error_code, const char*error_message)
{
    return send_error(server.tftp_block, server.listen_socket, addr, port, error_code, error_message);
}

int32_t pico_tftp_send(struct pico_tftp_session *session, const uint8_t *data, int32_t len)
{
    int32_t size;


    if (len < 0) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    size = len;

    if (size > PICO_TFTP_PAYLOAD_SIZE) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    tftp_send_data(session, data, size);

    return len;
}

int pico_tftp_listen(uint16_t family, void (*cb)(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename, int32_t len))
{
    struct pico_socket *sock;

    if (server.listen_socket) {
        pico_err = PICO_ERR_EEXIST;
        return -1;
    }

    sock = tftp_socket_open(family, PICO_TFTP_PORT);
    if (!sock)
        return -1;

    server.listen_socket = sock;
    server.listen_callback = cb;

    return 0;
}

int pico_tftp_parse_request_args(char *args, int32_t len, int *options, uint8_t *timeout, int32_t *filesize)
{
    char *pos;
    char *end_args = args + len;

    args = extract_arg_pointer(args, end_args, &pos);

    return parse_optional_arguments(args, (int32_t)(end_args - args), options, timeout, filesize);
}

int pico_tftp_abort(struct pico_tftp_session *session, uint16_t error, const char *reason)
{
    if (!session) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (!find_session_by_socket(session->socket)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    tftp_send_error(session, NULL, 0, error, reason);

    return 0;
}

int pico_tftp_close_server(void)
{
    if (!server.listen_socket) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    pico_socket_close(server.listen_socket);
    server.listen_socket = NULL;
    return 0;
}

int pico_tftp_get_file_size(struct pico_tftp_session *session, int32_t *file_size)
{
    return pico_tftp_get_option(session, PICO_TFTP_OPTION_FILE, file_size);
}

struct pico_tftp_session *pico_tftp_app_setup(union pico_address *a, uint16_t port, uint16_t family, int *synchro)
{
    struct pico_tftp_session *session;

    if (!synchro) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    session = pico_tftp_session_setup(a, family);
    if (!session)
        return NULL;

    session->remote_port = port;
    session->status |= SESSION_STATUS_APP_ACK;
    session->argument = synchro;

    *synchro = 0;

    return session;
}

int pico_tftp_app_start_rx(struct pico_tftp_session *session, const char *filename)
{
    return pico_tftp_start_rx(session, session->remote_port, filename, application_rx_cb, session->argument);
}

int pico_tftp_app_start_tx(struct pico_tftp_session *session, const char *filename)
{
    return pico_tftp_start_tx(session, session->remote_port, filename, application_tx_cb, session->argument);
}

int32_t pico_tftp_get(struct pico_tftp_session *session, uint8_t *data, int32_t len)
{
    int synchro;

    if (!session || len < session->len ) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    synchro = *(int*)session->argument;
    *(int*)session->argument = 0;
    if ((session->state != TFTP_STATE_RX) && (session->state != TFTP_STATE_READ_REQUESTED))
        return -1;

    if (synchro < 0)
        return synchro;

    memcpy(data, tftp_payload(session->tftp_block), (size_t)session->len);
    len = session->len;

    tftp_send_ack(session);
    tftp_eval_finish(session, len);
    return len;
}

int32_t pico_tftp_put(struct pico_tftp_session *session, uint8_t *data, int32_t len)
{
    int synchro;

    if ((!session) || (!data) || (len < 0)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    synchro = *(int*)session->argument;
    *(int*)session->argument = 0;
    if (synchro < 0)
        return synchro;

    if (len > PICO_TFTP_PAYLOAD_SIZE)
        len = PICO_TFTP_PAYLOAD_SIZE;

    pico_tftp_send(session, data, len);
    return len;
}
