/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Author: Daniele Lacamera
 *********************************************************************/

#include <pico_defines.h>
#include <pico_stack.h>
#include <pico_socket.h>
#include <pico_tftp.h>

#define PICO_TFTP_TIMEOUT 5000

#define PICO_TFTP_STATE_RX          1
#define PICO_TFTP_STATE_RX_LAST     2
#define PICO_TFTP_STATE_TX          3
#define PICO_TFTP_STATE_TX_LAST     4


/* TFTP ERROR CODES (internal)
 * */
#define TFTP_ERR_UNDEF     0
#define TFTP_ERR_ENOENT    1
#define TFTP_ERR_EACC      2
#define TFTP_ERR_EXCEEDED  3
#define TFTP_ERR_EILL      4
#define TFTP_ERR_ETID      5
#define TFTP_ERR_EEXIST    6
#define TFTP_ERR_EUSR      7

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
#define PICO_TFTP_BLOCK_SIZE (PICO_TFTP_SIZE + sizeof(struct pico_tftp_data_hdr))
#define tftp_payload(p) (((uint8_t *)(p)) + sizeof(struct pico_tftp_data_hdr))

struct pico_tftp_session {
    int state;
    uint16_t packet_counter;
    /* Current connection */
    struct pico_socket *socket;
    union pico_address remote_address;
    uint16_t remote_port;
    uint16_t localport;
    pico_time wallclock_timeout;
    struct pico_tftp_session *next;
    struct pico_timer *timer;
    void *argument;
    int (*callback)(struct pico_tftp_session *session, uint16_t tftp_err, uint8_t *block, uint32_t len, void *arg);
};

static struct pico_tftp_session *tftp_sessions = NULL;
static struct pico_socket *listen_socket = NULL;

//static int (*pico_tftp_user_cb)(uint16_t tftp_err, uint8_t *block, uint32_t len) = NULL;
static int (*pico_tftp_listen_cb)(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename) = NULL;

static struct pico_tftp_session * pico_tftp_session_create(struct pico_socket *sock, int state, union pico_address *remote_addr)
{
    struct pico_tftp_session *session;

    session = (struct pico_tftp_session *) PICO_ZALLOC(sizeof (struct pico_tftp_session));
    session->state = state;
    session->packet_counter = 0u;
    session->socket = sock;
    session->wallclock_timeout = 0ULL;
    session->next = NULL;
    session->localport = 0;
    session->callback = NULL;
    session->argument = NULL;
    memcpy(&session->remote_address, remote_addr, sizeof(union pico_address));
    session->remote_port = 0;

    return session;
}

static struct pico_tftp_session * find_session_by_socket(struct pico_socket *tftp_socket)
{
    struct pico_tftp_session *pos = tftp_sessions;

    for (; pos ; pos = pos->next)
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
    struct pico_tftp_session *prev;
    struct pico_tftp_session *pos;

    for (pos = tftp_sessions; pos; pos = pos->next) {
        if (pos == idx) {
            if (pos == tftp_sessions)
                tftp_sessions = tftp_sessions->next;
            else
                prev->next = pos->next;

            pico_timer_cancel(idx->timer);
            PICO_FREE(idx);
            return 0;
        }
        prev = pos;
    }

    return -1;
}

/* Static buffer (to keep stack small) */
static uint8_t tftp_block[PICO_TFTP_BLOCK_SIZE];

static int check_opcode(struct pico_tftp_hdr *th)
{
    uint16_t be_opcode = short_be(th->opcode);
    if (be_opcode < PICO_TFTP_RRQ)
        return -1;

    if (be_opcode > TFTP_ERROR)
        return -1;

    return 0;
}

static void tftp_fsm_timeout(pico_time now, void *arg);

static void tftp_schedule_timeout(struct pico_tftp_session *session, pico_time interval)
{
    if (session->wallclock_timeout == 0)
        session->timer = pico_timer_add(interval + 1, tftp_fsm_timeout, session);

    session->wallclock_timeout = PICO_TIME_MS() + interval;
}

static void tftp_finish(struct pico_tftp_session *session)
{
    pico_socket_close(session->socket);
    del_session(session);
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
}

static void tftp_send_req(struct pico_tftp_session *session, union pico_address *a, uint16_t port, char *filename, uint16_t opcode)
{
#   define OCTET_STRSIZ 7U
    static const char octet[OCTET_STRSIZ] = {
        0, 'o', 'c', 't', 'e', 't', 0
    };
    struct pico_tftp_hdr *hdr;
    unsigned int len;
    uint8_t *buf;

    if (!filename) {
        return;
    }

    len = (unsigned int)strlen(filename);
    buf = PICO_ZALLOC(sizeof(struct pico_tftp_hdr) + OCTET_STRSIZ + len);
    if (!buf) {
        char errtxt[] = "Out of memory";
        session->callback(session, PICO_TFTP_ERR_LOCAL, (uint8_t *)errtxt, 0, session->argument);
        tftp_finish(session);
        return;
    }

    hdr = (struct pico_tftp_hdr *)buf;
    hdr->opcode = short_be(opcode);
    memcpy(buf + sizeof(struct pico_tftp_hdr), filename, len);
    memcpy(buf + sizeof(struct pico_tftp_hdr) + len, octet, OCTET_STRSIZ);
    (void)pico_socket_sendto(session->socket, buf, (int)(sizeof(struct pico_tftp_hdr) + OCTET_STRSIZ + len), a, port);
}

static void tftp_send_rx_req(struct pico_tftp_session *session, union pico_address *a, uint16_t port, char *filename)
{
    tftp_send_req(session, a, port, filename, PICO_TFTP_RRQ);
    tftp_schedule_timeout(session, PICO_TFTP_TIMEOUT);
}

static void tftp_send_tx_req(struct pico_tftp_session *session, union pico_address *a, uint16_t port, char *filename)
{
    tftp_send_req(session, a, port, filename, PICO_TFTP_WRQ);
    tftp_schedule_timeout(session, PICO_TFTP_TIMEOUT);
}

static void tftp_send_error(struct pico_tftp_session *session, union pico_address *a, uint16_t port, uint16_t errcode, const char *errmsg)
{
    struct pico_tftp_err_hdr *eh;
    uint32_t len;
    uint32_t maxlen = PICO_TFTP_BLOCK_SIZE - sizeof(struct pico_tftp_err_hdr);
    if (!errmsg)
        len = 0;
    else
        len = (uint32_t)strlen(errmsg);

    if (!a) {
        a = &session->remote_address;
        port = session->remote_port;
    }

    eh = (struct pico_tftp_err_hdr *) tftp_block;
    eh->opcode = short_be(TFTP_ERROR);
    eh->error_code = short_be(errcode);
    if (len + 1U > maxlen)
        len = maxlen;

    if (len)
        memcpy(tftp_payload(eh), errmsg, len);

    tftp_payload(eh)[len++] = (char)0;
    (void)pico_socket_sendto(session->socket, eh, (int) (len + sizeof(struct pico_tftp_err_hdr)), a, port);
    tftp_finish(session);
}

static void tftp_send_data(struct pico_tftp_session *session, const uint8_t *data, uint32_t len)
{
    struct pico_tftp_data_hdr *dh;

    dh = (struct pico_tftp_data_hdr *) tftp_block;
    dh->opcode = short_be(PICO_TFTP_DATA);
    dh->block = short_be(session->packet_counter++);

    if (len < PICO_TFTP_SIZE)
        session->state = PICO_TFTP_STATE_TX_LAST;

    memcpy(tftp_block + sizeof(struct pico_tftp_data_hdr), data, len);
    pico_socket_sendto(session->socket, tftp_block, (int) (len + sizeof(struct pico_tftp_data_hdr)),
                       &session->remote_address, session->remote_port);
    tftp_schedule_timeout(session, PICO_TFTP_TIMEOUT);
}

static inline void tftp_eval_finish(struct pico_tftp_session *session, uint32_t len)
{
    if (len < PICO_TFTP_BLOCK_SIZE) {
        session->state = PICO_TFTP_STATE_RX_LAST;
        tftp_finish(session);
    }
}

static void tftp_data(struct pico_tftp_session *session, uint8_t *block, uint32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;
    uint32_t payload_len = len - (uint32_t) sizeof(struct pico_tftp_data_hdr);

    if (!session->socket)
        return;

    if (pico_address_compare(a, &session->remote_address, session->socket->net->proto_number) != 0) {
        tftp_send_error(session, a, port, TFTP_ERR_EXCEEDED, "TFTP busy, try again later.");
        return;
    }

    if (!session->remote_port)
        session->remote_port = port;

    dh = (struct pico_tftp_data_hdr *)block;
    if (short_be(dh->block) > (session->packet_counter +  1U)) {
        char errtxt[] = "Wrong/unexpected sequence number";
        session->callback(session, PICO_TFTP_ERR_LOCAL, (uint8_t *)errtxt, 0, session->argument);
        tftp_send_error(session, a, port, TFTP_ERR_EILL, "TFTP connection broken! (Packet loss?)");
        return;
    }

    if (short_be(dh->block) == (session->packet_counter + 1U)) {
        session->packet_counter++;
        if (session->callback(session, PICO_TFTP_ERR_OK, tftp_payload(block), payload_len, session->argument) >= 0) {
            tftp_send_ack(session);
        }

        tftp_eval_finish(session, len);
    }
}

static void tftp_ack(struct pico_tftp_session *session, uint8_t *block, uint32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_data_hdr *dh;
    int state = session->state;
    uint16_t block_n;

    (void)len;
    if (pico_address_compare(a, &session->remote_address, session->socket->net->proto_number) != 0) {
        tftp_send_error(session, a, port, TFTP_ERR_EXCEEDED, "TFTP busy, try again later.");
        return;
    }

    dh = (struct pico_tftp_data_hdr *)block;
    block_n = short_be(dh->block);
    if (block_n != (session->packet_counter - 1U)) {
        tftp_send_error(session, a, port, TFTP_ERR_EILL, "TFTP connection broken! (Packet loss?)");
        return;
    }

    if (block_n == 0) {
        session->remote_port = port;
    }

    session->callback(session, PICO_TFTP_ERR_OK, NULL, 0, session->argument);

    if (state == PICO_TFTP_STATE_TX_LAST) {
        tftp_finish(session);
    }
}

static void tftp_timeout(struct pico_tftp_session *session, pico_time t)
{
    char errmsg[] = "Network timeout.";

    (void)t;
    session->callback(session, PICO_TFTP_ERR_PEER, (uint8_t *)errmsg, 0, session->argument);
    tftp_send_error(session, NULL, 0, TFTP_ERR_EXCEEDED, "TFTP timeout. Please reply faster.");
}

static void tftp_req(uint8_t *block, uint32_t len, union pico_address *a, uint16_t port)
{
    struct pico_tftp_hdr *hdr = (struct pico_tftp_hdr *)block;

    if ((len > 0) && pico_tftp_listen_cb) {
        pico_tftp_listen_cb(a, port, short_be(hdr->opcode), (char *)(block + sizeof(struct pico_tftp_hdr)));
    }
}

static void tftp_data_err(struct pico_tftp_session *session, uint8_t *block, uint32_t len, union pico_address *a, uint16_t port)
{
    (void)len;
    (void)block;
    (void)port;
    if (pico_address_compare(a, &session->remote_address, session->socket->net->proto_number) != 0) {
        return;
    }

    session->callback(session, PICO_TFTP_ERR_PEER, block + 1, 0, session->argument);
}

static void tftp_fsm_timeout(pico_time now, void *arg)
{
    struct pico_tftp_session *session = (struct pico_tftp_session *)arg;
    if (session->wallclock_timeout == 0) {
        /* Timer is canceled. */
        return;
    }

    if (now >= session->wallclock_timeout) {
        tftp_timeout(session, now);

        session->wallclock_timeout = 0ULL;
    } else {
        tftp_schedule_timeout(session, session->wallclock_timeout - now);
    }
}

static void tftp_receive(struct pico_tftp_session *session, uint8_t *block, uint32_t r, union pico_address *a, uint16_t port)
{
    struct pico_tftp_hdr *th = (struct pico_tftp_hdr *) block;
    uint16_t idx;

    if (check_opcode(th) < 0) {
        tftp_send_error(session, NULL, 0, TFTP_ERR_EILL, "Illegal opcode");
        return;
    }

    idx = short_be(th->opcode);
    if (idx < PICO_TFTP_DATA) {
        /* listen related stuff... NB: here session == NULL*/
        tftp_req(block, r, a, port);
    } else if (idx == TFTP_ERROR) {
        tftp_data_err(session, block, r, a, port);
    } else {
        if (session->state == PICO_TFTP_STATE_RX || session->state == PICO_TFTP_STATE_RX_LAST)
            tftp_data(session, block, r, a, port);
        else
            tftp_ack(session, block, r, a, port);
    }
}

static void tftp_cb(uint16_t ev, struct pico_socket *s)
{
    int r;
    struct pico_tftp_session *session;
    union pico_address ep;
    uint16_t port;

    session = find_session_by_socket(s);
    if (session) {
        if (ev == PICO_SOCK_EV_ERR) {
            char errtxt[] = "Socket Error";
            session->callback(session, PICO_TFTP_ERR_LOCAL, (uint8_t *)errtxt, 0, session->argument);
            tftp_finish(session);
        }
    } else
        if (!listen_socket || s != listen_socket)
            return;

    r = pico_socket_recvfrom(s, tftp_block, PICO_TFTP_BLOCK_SIZE, &ep, &port);
    if (r < (int)sizeof(struct pico_tftp_hdr))
        return;

    tftp_receive(session, tftp_block, (uint32_t)r, &ep, port);
}

static struct pico_socket * tftp_socket_open(uint16_t family, uint16_t localport)
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

/* Active RX request from PicoTCP */
struct pico_tftp_session * pico_tftp_start_rx(union pico_address *a, uint16_t port, uint16_t family, char *filename,
        int (*user_cb)(struct pico_tftp_session *session, uint16_t err, uint8_t *block, uint32_t len, void *arg), void *arg)
{
    struct pico_socket *sock;
    struct pico_tftp_session *session;

    if (!user_cb) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if ((!listen_socket) && (port != short_be(PICO_TFTP_PORT))) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    sock = tftp_socket_open(family, 0); // a, port);
    if (!sock)
        return NULL;

    session = pico_tftp_session_create(sock, PICO_TFTP_STATE_RX, a);

    session->callback = user_cb;
    session->packet_counter = 0u;
    session->argument = arg;

    add_session(session);

    if (port != short_be(PICO_TFTP_PORT)) {
        session->remote_port = port;
        tftp_send_ack(session);
    } else {
        tftp_send_rx_req(session, a, port, filename);
    }

    return session;
}

struct pico_tftp_session * pico_tftp_start_tx(union pico_address *a, uint16_t port, uint16_t family, char *filename,
        int (*user_cb)(struct pico_tftp_session *session, uint16_t err, uint8_t *block, uint32_t len, void *arg), void *arg)
{
    struct pico_socket *sock;
    struct pico_tftp_session *session;

    if (!user_cb) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if ((!listen_socket) && (port != short_be(PICO_TFTP_PORT))) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    sock = tftp_socket_open(family, 0);
    if (!sock)
        return NULL;

    session = pico_tftp_session_create(sock, PICO_TFTP_STATE_TX, a);

    session->callback = user_cb;
    session->packet_counter = 1u;
    session->argument = arg;

    add_session(session);

    if (port != short_be(PICO_TFTP_PORT)) {
        session->remote_port = port;
        user_cb(session, PICO_TFTP_ERR_OK, NULL, 0, arg);
    } else
        tftp_send_tx_req(session, a, port, filename);

    return session;
}

int pico_tftp_send(struct pico_tftp_session *session, const uint8_t *data, int len)
{
    uint32_t size;

    if (session->state == PICO_TFTP_STATE_RX) {
        pico_err = PICO_ERR_ENOTCONN;
        return -1;
    }

    if (len < 0) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    size = (uint32_t)len;

    if (size > PICO_TFTP_SIZE) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    tftp_send_data(session, data, size);

    return len;
}

int pico_tftp_listen(uint16_t family, int (*cb)(union pico_address *addr, uint16_t port, uint16_t opcode, char *filename))
{
    struct pico_socket *sock;

    if (listen_socket)
        pico_tftp_abort(NULL);

    sock = tftp_socket_open(family, PICO_TFTP_PORT);
    if (!sock)
        return -1;

    listen_socket = sock;
    pico_tftp_listen_cb = cb;

    return 0;
}

/* session must be a valid session handler; if equals NULL listen socket is closed */
int pico_tftp_abort(struct pico_tftp_session *session)
{
    int ret;

    if (!session) {
        // listen socket...
        if (!listen_socket) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        pico_socket_close(listen_socket);
        listen_socket = NULL;
        return 0;
    }

    if (!find_session_by_socket(session->socket)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    tftp_send_error(session, NULL, 0, TFTP_ERR_UNDEF, "Cancelled by user");

    ret = pico_socket_close(session->socket);
    return del_session(session)? -1: ret;
}
